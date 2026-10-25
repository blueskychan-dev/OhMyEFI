#include "unlock.h"
#include "hwinfo.h"
#include "nvram.h"
#include "debug.h"
#include "ui.h"
#include "util.h"

UNLOCK_FIVR_INFO   gUnlockFivr;
UNLOCK_ME_PSP_INFO gUnlockMePsp;
UNLOCK_SPI_INFO    gUnlockSpi;

static BOOLEAN s_deep_probed_once = FALSE;
static BOOLEAN s_fv_scanned_once  = FALSE;
static UINT8  *s_fv_cache_buf     = NULL;
static UINTN   s_fv_cache_size    = 0;
static UINTN   s_unlock_q_idx[256];

static const CHAR8 * const kFivrPlaneNames[UNLOCK_FIVR_PLANE_COUNT] = {
    "CPU Core",
    "Intel iGPU (Slice)",
    "CPU Cache / Ring",
    "System Agent (SA)",
    "Analog I/O"
};

/* =========================================================================
 * Helper: Check 32-bit vs 64-bit Physical MMIO Address Reachability
 * ========================================================================= */
static BOOLEAN mmio_addr_reachable(UINT64 phys, BOOLEAN require_writable) {
    if (phys < 0x100000ULL) return FALSE;
#if !defined(__x86_64__) && !defined(_M_X64)
    if (phys > 0xFFFFF000ULL) return FALSE;
#endif
    BOOLEAN mapped = FALSE, writable = FALSE;
    if (!cpu_probe_address(phys, &mapped, &writable) || !mapped) return FALSE;
    if (require_writable && !writable) return FALSE;
    return TRUE;
}

static BOOLEAN parse_signed_mv(const CHAR8 *s, INT32 *out_mv) {
    if (!s || !out_mv) return FALSE;
    while (*s == ' ' || *s == '\t') s++;
    BOOLEAN neg = FALSE;
    if (*s == '-') { neg = TRUE; s++; }
    else if (*s == '+') { s++; }
    while (*s == ' ') s++;
    UINT64 mag = 0;
    if (!parse_dec_u64(s, &mag) || mag > 500ULL) return FALSE;
    *out_mv = neg ? -(INT32)mag : (INT32)mag;
    return TRUE;
}

/* =========================================================================
 * 1. Firmware Volume (FV2) Hidden PE32 / RAW HII PackageList Extractor
 *    Extracts unregistered Setup / CpuSetup / SaSetup / PchSetup / MeSetup
 *    IFR FormSets directly from BIOS flash on Dell, Lenovo, HP, AMI, Insyde!
 * ========================================================================= */
static BOOLEAN guid_is_trivial(const EFI_GUID *g) {
    const UINT8 *b = (const UINT8 *)g;
    BOOLEAN all0 = TRUE, allF = TRUE;
    for (UINTN i = 0; i < sizeof(EFI_GUID); i++) {
        if (b[i] != 0x00U) all0 = FALSE;
        if (b[i] != 0xFFU) allF = FALSE;
    }
    return (all0 || allF);
}

static BOOLEAN hii_buf_has_pkg_guid(const UINT8 *buf, UINTN buf_sz, const EFI_GUID *target) {
    if (!buf || buf_sz < sizeof(EFI_HII_PACKAGE_LIST_HEADER) || !target) return FALSE;
    UINTN off = 0;
    while (off + sizeof(EFI_HII_PACKAGE_LIST_HEADER) <= buf_sz) {
        EFI_HII_PACKAGE_LIST_HEADER hdr;
        memcpy(&hdr, buf + off, sizeof(hdr));
        if (hdr.PackageLength < sizeof(EFI_HII_PACKAGE_LIST_HEADER) ||
            off + hdr.PackageLength > buf_sz) {
            break;
        }
        EFI_GUID pkg_guid = hdr.PackageListGuid;
        if (guid_equal(&pkg_guid, target)) return TRUE;
        off += hdr.PackageLength;
    }
    return FALSE;
}

static BOOLEAN validate_hii_pkg_list_at(const UINT8 *data, UINTN avail, UINT32 *out_len) {
    if (!data || avail < sizeof(EFI_HII_PACKAGE_LIST_HEADER) + 8U) return FALSE;

    EFI_HII_PACKAGE_LIST_HEADER plh;
    memcpy(&plh, data, sizeof(plh));
    if (plh.PackageLength < 28U || plh.PackageLength > 0x400000U || plh.PackageLength > avail) {
        return FALSE;
    }
    EFI_GUID pkg_guid = plh.PackageListGuid;
    if (guid_is_trivial(&pkg_guid)) return FALSE;

    UINTN pos = sizeof(EFI_HII_PACKAGE_LIST_HEADER);
    UINTN end = (UINTN)plh.PackageLength;
    BOOLEAN saw_forms   = FALSE;
    BOOLEAN saw_strings = FALSE;
    BOOLEAN valid_end   = FALSE;

    for (UINTN guard = 0; guard < 256U && pos + 4U <= end; guard++) {
        UINT32 phdr = 0;
        memcpy(&phdr, data + pos, 4);
        UINT32 plen  = phdr & 0x00FFFFFFU;
        UINT8  ptype = (UINT8)((phdr >> 24) & 0xFFU);

        if (ptype == EFI_HII_PACKAGE_END) {
            if (plen == 4U && pos + 4U == end) {
                valid_end = TRUE;
            }
            break;
        }
        if (plen < 4U || pos + plen > end) break;
        if (ptype == 0x00U || (ptype > 0x0DU && ptype < 0xE0U)) break;

        if (ptype == EFI_HII_PACKAGE_FORMS && plen >= 16U)   saw_forms   = TRUE;
        if (ptype == EFI_HII_PACKAGE_STRINGS && plen >= 48U) saw_strings = TRUE;
        pos += plen;
    }

    if (valid_end && saw_forms && saw_strings) {
        if (out_len) *out_len = plh.PackageLength;
        return TRUE;
    }
    return FALSE;
}

static VOID append_pkg_list_to_blob(
    UINT8 **io_blob,
    UINTN *io_sz,
    UINTN *io_cap,
    const UINT8 *pkg_data,
    UINT32 pkg_len
) {
    if (!io_blob || !io_sz || !io_cap || !pkg_data || pkg_len < 28U) return;
    if (*io_sz + pkg_len > 0x1800000U) return; /* 24 MB safety ceiling */

    EFI_GUID g;
    memcpy(&g, pkg_data, sizeof(EFI_GUID));
    if (hii_buf_has_pkg_guid(*io_blob, *io_sz, &g)) return;

    if (*io_sz + pkg_len > *io_cap) {
        UINTN ncap = (*io_cap == 0) ? 131072U : (*io_cap * 2U);
        while (ncap < *io_sz + pkg_len) ncap *= 2U;
        UINT8 *nb = (UINT8 *)alloc_pool(ncap);
        if (!nb) return;
        if (*io_blob && *io_sz > 0) memcpy(nb, *io_blob, *io_sz);
        if (*io_blob) free_pool(*io_blob);
        *io_blob = nb;
        *io_cap  = ncap;
    }
    memcpy(*io_blob + *io_sz, pkg_data, pkg_len);
    *io_sz += pkg_len;
}

static VOID scan_pe32_for_hii_lists(
    const UINT8 *pe,
    UINTN pe_sz,
    UINT8 **io_blob,
    UINTN *io_sz,
    UINTN *io_cap
) {
    if (!pe || pe_sz < 0x100U || pe[0] != 'M' || pe[1] != 'Z') return;
    UINT32 lfanew = 0;
    memcpy(&lfanew, pe + 0x3CU, 4);
    if (lfanew < 0x40U || (UINTN)lfanew + 24U > pe_sz) return;
    if (pe[lfanew] != 'P' || pe[lfanew + 1] != 'E' || pe[lfanew + 2] != 0 || pe[lfanew + 3] != 0) return;

    UINT16 num_secs = 0, opt_sz = 0;
    memcpy(&num_secs, pe + lfanew + 6U, 2);
    memcpy(&opt_sz,   pe + lfanew + 20U, 2);
    if (num_secs == 0 || num_secs > 32U) return;

    UINTN sec_tab = (UINTN)lfanew + 24U + (UINTN)opt_sz;
    if (sec_tab + (UINTN)num_secs * 40U > pe_sz) return;

    for (UINT16 s = 0; s < num_secs; s++) {
        const UINT8 *sh = pe + sec_tab + (UINTN)s * 40U;
        BOOLEAN is_rsrc = (memcmp(sh, ".rsrc", 5) == 0);
        BOOLEAN is_hii  = (memcmp(sh, ".hii", 4) == 0);
        if (!is_rsrc && !is_hii) continue;

        UINT32 raw_sz = 0, raw_ptr = 0, virt_sz = 0;
        memcpy(&virt_sz, sh + 8U,  4);
        memcpy(&raw_sz,  sh + 16U, 4);
        memcpy(&raw_ptr, sh + 20U, 4);
        UINT32 span = (raw_sz > 0) ? raw_sz : virt_sz;
        if (raw_ptr == 0 || span < 28U || (UINTN)raw_ptr + (UINTN)span > pe_sz) continue;

        UINTN s_off = (UINTN)raw_ptr;
        UINTN s_end = s_off + (UINTN)span;
        while (s_off + 28U <= s_end) {
            UINT32 plen = 0;
            if (validate_hii_pkg_list_at(pe + s_off, s_end - s_off, &plen)) {
                append_pkg_list_to_blob(io_blob, io_sz, io_cap, pe + s_off, plen);
                s_off += (plen + 3U) & ~3U;
            } else {
                s_off += 4U;
            }
        }
    }
}

static VOID ensure_fv2_hii_cache_scanned(VOID) {
    if (s_fv_scanned_once) return;
    s_fv_scanned_once = TRUE;

    UINTN fv_cnt = 0;
    EFI_HANDLE *fv_handles = NULL;
    if (EFI_ERROR(efi_locate_handles(&gEfiFirmwareVolume2ProtocolGuid, &fv_cnt, &fv_handles)) ||
        !fv_handles || fv_cnt == 0) {
        return;
    }

    UINTN cap = 0;
    for (UINTN fi = 0; fi < fv_cnt && fi < 32U; fi++) {
        EFI_FIRMWARE_VOLUME2_PROTOCOL *fv = NULL;
        if (EFI_ERROR(gBS->HandleProtocol(fv_handles[fi], &gEfiFirmwareVolume2ProtocolGuid, (VOID **)&fv)) ||
            !fv || !fv->GetNextFile || !fv->ReadSection) {
            continue;
        }
        UINTN key_sz = (fv->KeySize >= 16U) ? (UINTN)fv->KeySize : 16U;
        if (key_sz > 4096U) continue;
        VOID *key = alloc_zero_pool(key_sz);
        if (!key) continue;

        for (UINTN guard = 0; guard < 1536U; guard++) {
            EFI_FV_FILETYPE ftype = EFI_FV_FILETYPE_ALL;
            EFI_GUID name_guid;
            EFI_FV_FILE_ATTRIBUTES fattr = 0;
            UINTN fsize = 0;
            EFI_STATUS st = fv->GetNextFile(fv, key, &ftype, &name_guid, &fattr, &fsize);
            if (EFI_ERROR(st)) break;

            if (ftype == EFI_FV_FILETYPE_DRIVER ||
                ftype == EFI_FV_FILETYPE_APPLICATION ||
                ftype == EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER) {
                VOID *sec_buf = NULL;
                UINTN sec_sz  = 0;
                UINT32 auth   = 0;
                if (!EFI_ERROR(fv->ReadSection(fv, &name_guid, EFI_SECTION_PE32, 0, &sec_buf, &sec_sz, &auth)) &&
                    sec_buf) {
                    if (sec_sz >= 0x100U && sec_sz <= 0x1000000U) {
                        scan_pe32_for_hii_lists((const UINT8 *)sec_buf, sec_sz,
                                                &s_fv_cache_buf, &s_fv_cache_size, &cap);
                    }
                    free_pool(sec_buf);
                }
            } else if (ftype == EFI_FV_FILETYPE_FREEFORM) {
                VOID *raw_buf = NULL;
                UINTN raw_sz  = 0;
                UINT32 auth   = 0;
                if (!EFI_ERROR(fv->ReadSection(fv, &name_guid, EFI_SECTION_RAW, 0, &raw_buf, &raw_sz, &auth)) &&
                    raw_buf) {
                    UINT32 plen = 0;
                    if (raw_sz >= 28U && raw_sz <= 0x800000U &&
                        validate_hii_pkg_list_at((const UINT8 *)raw_buf, raw_sz, &plen)) {
                        append_pkg_list_to_blob(&s_fv_cache_buf, &s_fv_cache_size, &cap,
                                                (const UINT8 *)raw_buf, plen);
                    }
                    free_pool(raw_buf);
                }
            }
        }
        free_pool(key);
    }

    free_pool(fv_handles);
}

VOID unlock_append_fv_hii_packages(UINT8 **io_buf, UINTN *io_size, UINTN *out_added_lists) {
    if (out_added_lists) *out_added_lists = 0;
    if (!io_buf || !io_size) return;

    ensure_fv2_hii_cache_scanned();
    if (!s_fv_cache_buf || s_fv_cache_size < sizeof(EFI_HII_PACKAGE_LIST_HEADER)) return;

    UINTN added = 0;
    UINTN extra_bytes = 0;
    UINTN off = 0;
    while (off + sizeof(EFI_HII_PACKAGE_LIST_HEADER) <= s_fv_cache_size) {
        EFI_HII_PACKAGE_LIST_HEADER hdr;
        memcpy(&hdr, s_fv_cache_buf + off, sizeof(hdr));
        if (hdr.PackageLength < sizeof(EFI_HII_PACKAGE_LIST_HEADER) ||
            off + hdr.PackageLength > s_fv_cache_size) {
            break;
        }
        EFI_GUID pkg_guid = hdr.PackageListGuid;
        if (!hii_buf_has_pkg_guid(*io_buf, *io_size, &pkg_guid)) {
            extra_bytes += hdr.PackageLength;
        }
        off += hdr.PackageLength;
    }

    if (extra_bytes == 0 || *io_size + extra_bytes > 0x2000000U) return;

    UINT8 *merged = (UINT8 *)alloc_pool(*io_size + extra_bytes);
    if (!merged) return;
    UINTN mpos = 0;
    if (*io_buf && *io_size > 0) {
        memcpy(merged, *io_buf, *io_size);
        mpos = *io_size;
    }

    off = 0;
    while (off + sizeof(EFI_HII_PACKAGE_LIST_HEADER) <= s_fv_cache_size) {
        EFI_HII_PACKAGE_LIST_HEADER hdr;
        memcpy(&hdr, s_fv_cache_buf + off, sizeof(hdr));
        if (hdr.PackageLength < sizeof(EFI_HII_PACKAGE_LIST_HEADER) ||
            off + hdr.PackageLength > s_fv_cache_size) {
            break;
        }
        EFI_GUID pkg_guid = hdr.PackageListGuid;
        if (!hii_buf_has_pkg_guid(merged, mpos, &pkg_guid)) {
            memcpy(merged + mpos, s_fv_cache_buf + off, hdr.PackageLength);
            mpos += hdr.PackageLength;
            added++;
        }
        off += hdr.PackageLength;
    }

    if (*io_buf) free_pool(*io_buf);
    *io_buf  = merged;
    *io_size = mpos;
    if (out_added_lists) *out_added_lists = added;
}

/* =========================================================================
 * 2. Intel FIVR Live Voltage Offset Engine (MSR 0x150 OC_MAILBOX)
 * ========================================================================= */
static BOOLEAN fivr_hw_eligible(VOID) {
    if (!gHw.cpu_msr.is_intel || gHw.feat_hypervisor) return FALSE;
    if (gHw.cpu_family != 6U || gHw.cpu_model < 0x3CU) return FALSE; /* Haswell (0x3C) and newer */
    return TRUE;
}

static BOOLEAN fivr_read_plane_mv_raw(UINT8 plane, INT32 *out_mv) {
    if (out_mv) *out_mv = 0;
    if (!fivr_hw_eligible() || plane >= UNLOCK_FIVR_PLANE_COUNT) return FALSE;

    UINT64 cmd = 0x8000001000000000ULL | ((UINT64)plane << 40);
    if (!cpu_safe_wrmsr(0x150U, cmd)) return FALSE;

    UINT64 rsp = 0;
    BOOLEAN ready = FALSE;
    for (UINTN tries = 0; tries < 40U; tries++) {
        if (!cpu_safe_rdmsr(0x150U, &rsp)) return FALSE;
        if ((rsp & (1ULL << 63)) == 0) {
            ready = TRUE;
            break;
        }
        if (gBS && gBS->Stall) gBS->Stall(10);
    }
    if (!ready) return FALSE;
    UINT8 cc = (UINT8)((rsp >> 32) & 0xFFU);
    if (cc != 0) return FALSE;

    UINT32 raw11 = (UINT32)((rsp >> 21) & 0x7FFU);
    INT32  s11   = (raw11 & 0x400U) ? ((INT32)raw11 - 2048) : (INT32)raw11;
    INT32  mv    = (s11 >= 0) ? ((s11 * 1000 + 512) / 1024) : ((s11 * 1000 - 512) / 1024);
    if (out_mv) *out_mv = mv;
    return TRUE;
}

static VOID refresh_fivr_offsets(VOID) {
    memset(&gUnlockFivr, 0, sizeof(gUnlockFivr));
    if (!fivr_hw_eligible()) return;

    for (UINT8 p = 0; p < UNLOCK_FIVR_PLANE_COUNT; p++) {
        INT32 mv = 0;
        if (fivr_read_plane_mv_raw(p, &mv)) {
            gUnlockFivr.plane_valid[p] = TRUE;
            gUnlockFivr.plane_mv[p]    = mv;
            if (p == 0) gUnlockFivr.supported = TRUE;
        }
    }
    if (gHw.cpu_msr.flex_oc_valid && gHw.cpu_msr.oc_locked) {
        gUnlockFivr.plundervolt_locked = TRUE;
    }
}

BOOLEAN unlock_fivr_set_plane_mv(UINT8 plane, INT32 target_mv, CHAR8 *err_out, UINTN max_err) {
    if (err_out && max_err > 0) err_out[0] = '\0';
    if (!fivr_hw_eligible() || plane >= UNLOCK_FIVR_PLANE_COUNT) {
        if (err_out) str_cpy(err_out, "Intel FIVR MSR 0x150 is only available on bare-metal Haswell+ Intel CPUs.", max_err);
        return FALSE;
    }
    if (target_mv < -250) target_mv = -250;
    if (target_mv > 150)  target_mv = 150;

    INT32 s11 = (target_mv >= 0) ? ((target_mv * 1024 + 500) / 1000)
                                 : ((target_mv * 1024 - 500) / 1000);
    UINT32 raw11 = ((UINT32)s11) & 0x7FFU;
    UINT64 cmd = 0x8000001100000000ULL | ((UINT64)plane << 40) | ((UINT64)raw11 << 21);

    if (!cpu_safe_wrmsr(0x150U, cmd)) {
        if (err_out) str_cpy(err_out, "WRMSR 0x150 faulted (#GP) — OC Mailbox blocked by microcode.", max_err);
        return FALSE;
    }
    for (UINTN tries = 0; tries < 40U; tries++) {
        UINT64 rsp = 0;
        if (!cpu_safe_rdmsr(0x150U, &rsp)) break;
        if ((rsp & (1ULL << 63)) == 0) break;
        if (gBS && gBS->Stall) gBS->Stall(10);
    }

    INT32 verify_mv = 0;
    if (!fivr_read_plane_mv_raw(plane, &verify_mv)) {
        if (err_out) str_cpy(err_out, "Failed to verify MSR 0x150 read-back.", max_err);
        return FALSE;
    }
    gUnlockFivr.plane_valid[plane] = TRUE;
    gUnlockFivr.plane_mv[plane]    = verify_mv;

    INT32 diff = verify_mv - target_mv;
    if (diff < 0) diff = -diff;
    if (diff > 3) {
        gUnlockFivr.plundervolt_locked = TRUE;
        if (err_out) {
            snprintf_ascii(err_out, max_err,
                "CPU ignored offset (stayed at %d mV)! Plundervolt / Overclocking Lock (0x194[20]) or Undervolt Protection is active. Unlock in NVRAM first & reboot!",
                verify_mv);
        }
        return FALSE;
    }
    gUnlockFivr.plundervolt_locked = FALSE;
    gVolatileHwTweakActive = TRUE;
    return TRUE;
}

static BOOLEAN pick_fivr_mv_modal(const CHAR8 *title, INT32 cur_mv, INT32 *out_mv) {
    static const INT32 kPresets[12] = {
        0, -25, -40, -50, -65, -75, -90, -100, -115, -125, -150, +25
    };
    CHAR8 obufs[13][52];
    const CHAR8 *optrs[13];
    UINTN cur_idx = 0;
    INT32 best_diff = 9999;

    for (UINTN i = 0; i < 12U; i++) {
        if (kPresets[i] == 0) {
            str_cpy(obufs[i], "  0 mV  (Stock / Default Voltage)", sizeof(obufs[i]));
        } else if (kPresets[i] > 0) {
            snprintf_ascii(obufs[i], sizeof(obufs[i]), "+%d mV  (Light Stability Overvolt)", kPresets[i]);
        } else {
            const CHAR8 *tag = (kPresets[i] >= -50)  ? "Conservative Safe Undervolt" :
                               (kPresets[i] >= -100) ? "Sweet-Spot Laptop/Desktop UV" :
                                                       "Aggressive Undervolt (Test Stability!)";
            snprintf_ascii(obufs[i], sizeof(obufs[i]), "%d mV  (%s)", kPresets[i], tag);
        }
        optrs[i] = obufs[i];
        INT32 d = cur_mv - kPresets[i];
        if (d < 0) d = -d;
        if (d < best_diff) { best_diff = d; cur_idx = i; }
    }
    str_cpy(obufs[12], "Enter Custom Millivolt Offset (-250 .. +150 mV)...", sizeof(obufs[12]));
    optrs[12] = obufs[12];

    INTN p = ui_pick_option_modal(title, optrs, 13, cur_idx, cur_idx);
    if (p < 0) return FALSE;
    if (p < 12) {
        *out_mv = kPresets[p];
        return TRUE;
    }

    CHAR8 init_s[16], out_s[16];
    snprintf_ascii(init_s, sizeof(init_s), "%d", cur_mv);
    if (!ui_input_modal("Custom FIVR Voltage Offset (mV)",
                        "Signed millivolts (-250 to +150, e.g. -85 or -110):",
                        init_s, out_s, sizeof(out_s), FALSE)) {
        return FALSE;
    }
    INT32 custom_mv = 0;
    if (!parse_signed_mv(out_s, &custom_mv) || custom_mv < -250 || custom_mv > 150) {
        ui_message_modal("Invalid Offset", "Please enter an integer between -250 and +150 mV.", TRUE);
        return FALSE;
    }
    *out_mv = custom_mv;
    return TRUE;
}

VOID unlock_edit_fivr_plane_interactive(UINT8 plane) {
    if (plane >= UNLOCK_FIVR_PLANE_COUNT) return;
    if (!gUnlockFivr.supported || !gUnlockFivr.plane_valid[plane]) {
        INTN hq = hw_hii_find_question_icase("Core Voltage Offset", NULL);
        if (hq < 0) hq = hw_hii_find_question_icase("Undervolt", NULL);
        if (hq < 0) hq = hw_hii_find_question_icase("Overclocking Lock", NULL);
        CHAR8 msg[256];
        snprintf_ascii(msg, sizeof(msg),
            "Live Intel FIVR OC_MAILBOX (MSR 0x150) is not accessible (%s).\n"
            "%s",
            gHw.feat_hypervisor ? "Running inside Hypervisor/VM" : "Restricted or unsupported CPU generation",
            (hq >= 0) ? "Tip: Motherboard HII voltage/unlock options are listed below!" :
                        "Use 'One-Click Unlock' or 'setup_var_3 Offset Editor' to unlock NVRAM locks.");
        ui_message_modal("FIVR Mailbox Unavailable", msg, TRUE);
        return;
    }

    CHAR8 title[64];
    snprintf_ascii(title, sizeof(title), "FIVR Plane %u: %s (MSR 0x150)",
                   (UINT32)plane, kFivrPlaneNames[plane]);
    INT32 target_mv = 0;
    if (!pick_fivr_mv_modal(title, gUnlockFivr.plane_mv[plane], &target_mv)) return;

    CHAR8 err[220];
    if (unlock_fivr_set_plane_mv(plane, target_mv, err, sizeof(err))) {
        CHAR8 ok[160];
        snprintf_ascii(ok, sizeof(ok),
            "Applied %s = %d mV via MSR 0x150!\n"
            "Verified live hardware read-back: %d mV.\n"
            "Chainload Windows/Linux/macOS from Boot tab (without cold reset) to keep active!",
            kFivrPlaneNames[plane], target_mv, gUnlockFivr.plane_mv[plane]);
        ui_message_modal("FIVR Voltage Offset Applied", ok, FALSE);
    } else {
        ui_message_modal("FIVR Write Blocked (Plundervolt / OC Lock)", err, TRUE);
    }
}

VOID unlock_edit_fivr_core_cache_sync_interactive(VOID) {
    if (!gUnlockFivr.supported) {
        unlock_edit_fivr_plane_interactive(0);
        return;
    }
    INT32 target_mv = 0;
    if (!pick_fivr_mv_modal("Sync CPU Core + CPU Cache Offset (Planes 0 & 2)",
                            gUnlockFivr.plane_mv[0], &target_mv)) {
        return;
    }
    CHAR8 err[220];
    BOOLEAN ok0 = unlock_fivr_set_plane_mv(0, target_mv, err, sizeof(err));
    BOOLEAN ok2 = unlock_fivr_set_plane_mv(2, target_mv, ok0 ? err : NULL, ok0 ? sizeof(err) : 0);
    if (ok0 && ok2) {
        CHAR8 ok[160];
        snprintf_ascii(ok, sizeof(ok),
            "Synchronized CPU Core (%d mV) + CPU Cache/Ring (%d mV) in MSR 0x150!\n"
            "Chainload your OS from the Boot tab to run with this undervolt active.",
            gUnlockFivr.plane_mv[0], gUnlockFivr.plane_mv[2]);
        ui_message_modal("Core + Cache Undervolt Active", ok, FALSE);
    } else {
        ui_message_modal("FIVR Sync Blocked", err, TRUE);
    }
}

/* =========================================================================
 * 3. Intel ME / CSME (PCI 00:16.0 + HECI1 MMIO) & AMD PSP Engine
 * ========================================================================= */
static const CHAR8 *me_working_state_name(UINT8 ws) {
    switch (ws & 0x0FU) {
        case 0x0: return "Reset";
        case 0x1: return "Initializing";
        case 0x2: return "Recovery Mode";
        case 0x3: return "Test / Disabled";
        case 0x4: return "ME Soft-Disabled";
        case 0x5: return "Normal";
        case 0x6: return "Sleep / Wait";
        case 0x7: return "Transition";
        case 0x8: return "Invalid CPU";
        default:  return "Unknown";
    }
}

static const CHAR8 *me_op_mode_name(UINT8 om) {
    switch (om & 0x0FU) {
        case 0x0: return "Normal";
        case 0x2: return "Debug Mode";
        case 0x3: return "Soft Temp Disable (HAP!)";
        case 0x4: return "SECOVR_JMPR (Pin Override!)";
        case 0x5: return "SECOVR_HECI (HMRFPO Active!)";
        case 0x7: return "Enhanced Debug";
        default:  return "OEM / Reserved";
    }
}

/* Safe, timeout-bounded HECI1 MMIO Circular Buffer MKHI exchange */
static BOOLEAN heci1_mkhi_transact(
    const UINT32 *tx_dwords,
    UINTN tx_dword_cnt,
    UINTN tx_byte_len,
    UINT32 *rx_dwords,
    UINTN max_rx_dwords,
    UINTN *out_rx_bytes
) {
    if (out_rx_bytes) *out_rx_bytes = 0;
    if (!gUnlockMePsp.me_present || !gUnlockMePsp.heci_mmio_ok ||
        !tx_dwords || tx_dword_cnt == 0 || tx_dword_cnt > 16U) {
        return FALSE;
    }

    volatile UINT32 *cb_ww  = (volatile UINT32 *)(UINTN)(gUnlockMePsp.heci_bar0 + 0x00U);
    volatile UINT32 *h_csr  = (volatile UINT32 *)(UINTN)(gUnlockMePsp.heci_bar0 + 0x04U);
    volatile UINT32 *cb_rw  = (volatile UINT32 *)(UINTN)(gUnlockMePsp.heci_bar0 + 0x08U);
    volatile UINT32 *me_csr = (volatile UINT32 *)(UINTN)(gUnlockMePsp.heci_bar0 + 0x0CU);

    UINT32 mcsr = *me_csr;
    if (mcsr == 0xFFFFFFFFU || (mcsr & (1U << 3)) == 0) {
        return FALSE; /* ME_RDY_HRA == 0 */
    }

    UINT32 hcsr = *h_csr;
    UINT8  h_cbd = (UINT8)((hcsr >> 24) & 0xFFU);
    if (h_cbd < (UINT8)(tx_dword_cnt + 2U) || h_cbd > 128U) return FALSE;

    /* Ensure Host Ready (H_RDY bit 3) is asserted without accidentally clearing/setting RST */
    if ((hcsr & (1U << 3)) == 0) {
        *h_csr = (hcsr & ~0x12U) | (1U << 3) | (1U << 2);
        if (gBS && gBS->Stall) gBS->Stall(1000);
        hcsr = *h_csr;
        if ((hcsr & (1U << 3)) == 0) return FALSE;
    }

    /* Drain any leftover unread DWORDs in ME->Host circular buffer */
    UINT8 me_rp = (UINT8)((mcsr >> 8) & 0xFFU);
    UINT8 me_wp = (UINT8)((mcsr >> 16) & 0xFFU);
    UINT8 pending = (UINT8)(me_wp - me_rp);
    if (pending > 0 && pending <= 64U) {
        for (UINT8 d = 0; d < pending; d++) { (VOID)*cb_rw; }
        *h_csr = ((*h_csr) & ~0x10U) | (1U << 2) | (1U << 1);
    }

    /* Check Host->ME circular buffer room */
    hcsr = *h_csr;
    UINT8 h_rp = (UINT8)((hcsr >> 8) & 0xFFU);
    UINT8 h_wp = (UINT8)((hcsr >> 16) & 0xFFU);
    UINT8 used = (UINT8)(h_wp - h_rp);
    if ((UINTN)used + tx_dword_cnt + 1U > (UINTN)h_cbd) return FALSE;

    /* HECI Header: ME Client=0x07 (MKHI), Host=0x01, Length=tx_byte_len, Complete=1 */
    UINT32 heci_hdr = 0x80000000U |
                      (((UINT32)tx_byte_len & 0x1FFU) << 16) |
                      (0x01U << 8) |
                      0x07U;
    *cb_ww = heci_hdr;
    for (UINTN i = 0; i < tx_dword_cnt; i++) {
        *cb_ww = tx_dwords[i];
    }
    /* Set H_IG (bit 2) and clear H_IS (bit 1 W1C) while keeping H_RDY (bit 3) */
    *h_csr = ((*h_csr) & ~0x10U) | (1U << 3) | (1U << 2) | (1U << 1);

    /* Poll up to 40 ms for ME response */
    for (UINTN wait = 0; wait < 400U; wait++) {
        mcsr = *me_csr;
        if (mcsr == 0xFFFFFFFFU) return FALSE;
        me_rp = (UINT8)((mcsr >> 8) & 0xFFU);
        me_wp = (UINT8)((mcsr >> 16) & 0xFFU);
        UINT8 avail = (UINT8)(me_wp - me_rp);
        if (avail >= 2U) {
            UINT32 rhdr = *cb_rw;
            UINTN rbytes = (UINTN)((rhdr >> 16) & 0x1FFU);
            UINTN rdwords = (rbytes + 3U) >> 2;
            if (rdwords + 1U > (UINTN)avail) rdwords = (UINTN)avail - 1U;
            for (UINTN i = 0; i < rdwords; i++) {
                UINT32 w = *cb_rw;
                if (rx_dwords && i < max_rx_dwords) rx_dwords[i] = w;
            }
            /* Pulse H_IG so ME updates its read pointer */
            *h_csr = ((*h_csr) & ~0x10U) | (1U << 3) | (1U << 2) | (1U << 1);
            if (out_rx_bytes) *out_rx_bytes = rbytes;
            return (rbytes >= 4U);
        }
        if (gBS && gBS->Stall) gBS->Stall(100);
    }
    return FALSE;
}

/* Safe AMD Ryzen SMN (System Management Network) Indirect Access via PCI 00:00.0 0xB8/0xBC */
static BOOLEAN amd_smn_read32(UINT32 smn_addr, UINT32 *out_val) {
    if (out_val) *out_val = 0xFFFFFFFFU;
    UINT32 root_id = 0xFFFFFFFFU;
    if (!hw_pci_cfg_read32_raw(0, 0, 0, 0x00U, &root_id) ||
        (root_id & 0xFFFFU) != 0x1022U) {
        return FALSE;
    }
    UINT32 prev_idx = 0;
    BOOLEAN had_prev = hw_pci_cfg_read32_raw(0, 0, 0, 0xB8U, &prev_idx);
    hw_pci_cfg_write32_raw(0, 0, 0, 0xB8U, smn_addr & ~3U);
    UINT32 data = 0xFFFFFFFFU;
    BOOLEAN ok = hw_pci_cfg_read32_raw(0, 0, 0, 0xBCU, &data);
    if (had_prev) {
        hw_pci_cfg_write32_raw(0, 0, 0, 0xB8U, prev_idx);
    }
    if (ok && out_val) *out_val = data;
    return ok;
}

static BOOLEAN amd_smn_write32(UINT32 smn_addr, UINT32 val) {
    UINT32 root_id = 0xFFFFFFFFU;
    if (!hw_pci_cfg_read32_raw(0, 0, 0, 0x00U, &root_id) ||
        (root_id & 0xFFFFU) != 0x1022U) {
        return FALSE;
    }
    UINT32 prev_idx = 0;
    BOOLEAN had_prev = hw_pci_cfg_read32_raw(0, 0, 0, 0xB8U, &prev_idx);
    hw_pci_cfg_write32_raw(0, 0, 0, 0xB8U, smn_addr & ~3U);
    hw_pci_cfg_write32_raw(0, 0, 0, 0xBCU, val);
    if (had_prev) {
        hw_pci_cfg_write32_raw(0, 0, 0, 0xB8U, prev_idx);
    }
    return TRUE;
}

static VOID probe_intel_me_and_amd_psp(BOOLEAN query_heci_mkhi) {
    /* Preserve previously queried MKHI / SMU firmware version across fast refreshes */
    BOOLEAN prev_ver_ok  = gUnlockMePsp.fw_ver_valid;
    UINT16  prev_maj     = gUnlockMePsp.fw_major;
    UINT16  prev_min     = gUnlockMePsp.fw_minor;
    UINT16  prev_hf      = gUnlockMePsp.fw_hotfix;
    UINT16  prev_bld     = gUnlockMePsp.fw_build;
    BOOLEAN prev_hmr_ok  = gUnlockMePsp.hmrfpo_queried;
    UINT8   prev_hmr_st  = gUnlockMePsp.hmrfpo_status;
    BOOLEAN prev_smu_ok  = gUnlockMePsp.smu_ver_valid;
    UINT8   prev_smu_maj = gUnlockMePsp.smu_major;
    UINT8   prev_smu_min = gUnlockMePsp.smu_minor;
    UINT8   prev_smu_pat = gUnlockMePsp.smu_patch;

    memset(&gUnlockMePsp, 0, sizeof(gUnlockMePsp));
    gUnlockMePsp.me_pci_idx      = -1;
    gUnlockMePsp.amd_psp_pci_idx = -1;

    if (gHw.cpu_msr.is_amd) {
        for (UINTN i = 0; i < gHw.pci_count; i++) {
            const HW_PCI_DEV_INFO *pd = &gHw.pci_devs[i];
            if (!gUnlockMePsp.amd_psp_present &&
                pd->vendor_id == 0x1022U && pd->class_code == 0x10U && pd->subclass == 0x80U) {
                gUnlockMePsp.amd_psp_present = TRUE;
                gUnlockMePsp.amd_psp_pci_idx = (INTN)i;
                gUnlockMePsp.psp_bus         = pd->bus;
                gUnlockMePsp.psp_dev         = pd->dev;
                gUnlockMePsp.psp_func        = pd->func;
                gUnlockMePsp.psp_vid         = pd->vendor_id;
                gUnlockMePsp.psp_did         = pd->device_id;
                gUnlockMePsp.psp_cmd         = pd->command;
                gUnlockMePsp.psp_bar         = (UINT64)(pd->bar0 & ~0xFULL);
            }
            if (!gUnlockMePsp.amd_iommu_present &&
                pd->vendor_id == 0x1022U && pd->class_code == 0x08U && pd->subclass == 0x06U) {
                gUnlockMePsp.amd_iommu_present = TRUE;
                gUnlockMePsp.amd_iommu_did     = pd->device_id;
            }
        }

        /* Probe AMD Root Complex (00:00.0) & SMN Aperture (e.g. X570 + Ryzen 9 5950X [1022:1480]) */
        UINT32 root_dw = 0xFFFFFFFFU;
        if (hw_pci_cfg_read32_raw(0, 0, 0, 0x00U, &root_dw) && (root_dw & 0xFFFFU) == 0x1022U) {
            gUnlockMePsp.amd_smn_ok   = TRUE;
            gUnlockMePsp.amd_root_did = (UINT16)(root_dw >> 16);

            if (!gHw.feat_hypervisor && (gHw.cpu_family >= 0x17U)) {
                /* Read passive Zen SMUIO::THM_TCON_CUR_TMP (SMN 0x00059800) */
                UINT32 thm = 0;
                if (amd_smn_read32(0x00059800U, &thm) && thm != 0U && thm != 0xFFFFFFFFU) {
                    INT32 t_c = (INT32)(((thm >> 21) & 0x7FFU) / 8U);
                    if ((thm & (1U << 19)) != 0) t_c -= 49;
                    if (t_c >= 5 && t_c <= 125) {
                        gUnlockMePsp.amd_tctl_valid = TRUE;
                        gUnlockMePsp.amd_tctl_c     = t_c;
                    }
                }

                /* Query MP1 SMU Firmware Version once on idle Matisse/Vermeer AM4 Root (0x1480) */
                if (prev_smu_ok && !query_heci_mkhi) {
                    gUnlockMePsp.smu_ver_valid = TRUE;
                    gUnlockMePsp.smu_major     = prev_smu_maj;
                    gUnlockMePsp.smu_minor     = prev_smu_min;
                    gUnlockMePsp.smu_patch     = prev_smu_pat;
                } else if (query_heci_mkhi && gUnlockMePsp.amd_root_did == 0x1480U) {
                    UINT32 rsp = 0;
                    if (amd_smn_read32(0x03B10570U, &rsp) && rsp == 0x00000001U) {
                        amd_smn_write32(0x03B10A40U, 0U);
                        amd_smn_write32(0x03B10570U, 0U);
                        amd_smn_write32(0x03B10524U, 0x02U); /* TEST_MSG_GetSmuVersion */
                        for (UINTN w = 0; w < 200U; w++) {
                            if (amd_smn_read32(0x03B10570U, &rsp) && rsp != 0U) break;
                            if (gBS && gBS->Stall) gBS->Stall(100);
                        }
                        UINT32 arg0 = 0;
                        if (rsp == 0x00000001U && amd_smn_read32(0x03B10A40U, &arg0) &&
                            arg0 != 0U && arg0 != 0xFFFFFFFFU) {
                            gUnlockMePsp.smu_ver_valid = TRUE;
                            gUnlockMePsp.smu_major     = (UINT8)((arg0 >> 16) & 0xFFU);
                            gUnlockMePsp.smu_minor     = (UINT8)((arg0 >> 8) & 0xFFU);
                            gUnlockMePsp.smu_patch     = (UINT8)(arg0 & 0xFFU);
                        }
                    }
                }
            }
        }
        return;
    }

    /* 1. Check enumerated PCI list for Intel ME HECI1 (00:16.0 or Intel Class 07:80 on Bus 0) */
    UINT8 cand_bus = 0, cand_dev = 0x16U, cand_fn = 0;
    BOOLEAN found_bdf = FALSE;
    for (UINTN i = 0; i < gHw.pci_count; i++) {
        const HW_PCI_DEV_INFO *pd = &gHw.pci_devs[i];
        if (pd->seg == 0 && pd->bus == 0 && pd->vendor_id == 0x8086U &&
            ((pd->dev == 0x16U && pd->func == 0U) ||
             (pd->dev == 0x03U && pd->func == 0U && pd->class_code == 0x07U && pd->subclass == 0x80U))) {
            cand_bus = pd->bus;
            cand_dev = pd->dev;
            cand_fn  = pd->func;
            gUnlockMePsp.me_enumerated_pci = TRUE;
            gUnlockMePsp.me_pci_idx        = (INTN)i;
            found_bdf = TRUE;
            if (pd->dev == 0x16U) break;
        }
    }

    /* 2. Even if hidden from UEFI PCI enumeration, probe raw 00:16.0 via ECAM / 0xCF8! */
    UINT32 id_dw = 0xFFFFFFFFU;
    if (!hw_pci_cfg_read32_raw(cand_bus, cand_dev, cand_fn, 0x00U, &id_dw) ||
        (id_dw & 0xFFFFU) != 0x8086U || (id_dw >> 16) == 0xFFFFU) {
        if (!found_bdf) return;
    }
    UINT32 cls_dw = 0;
    if (!found_bdf && hw_pci_cfg_read32_raw(cand_bus, cand_dev, cand_fn, 0x08U, &cls_dw)) {
        UINT8 cc = (UINT8)((cls_dw >> 24) & 0xFFU);
        if (cc != 0x07U && cc != 0x0CU && cc != 0xFFU) return;
    }

    gUnlockMePsp.me_present = TRUE;
    gUnlockMePsp.me_bus     = cand_bus;
    gUnlockMePsp.me_dev     = cand_dev;
    gUnlockMePsp.me_func    = cand_fn;
    gUnlockMePsp.me_vid     = (UINT16)(id_dw & 0xFFFFU);
    gUnlockMePsp.me_did     = (UINT16)((id_dw >> 16) & 0xFFFFU);

    UINT16 cmd16 = 0;
    if (hw_pci_cfg_read16_raw(cand_bus, cand_dev, cand_fn, 0x04U, &cmd16)) {
        gUnlockMePsp.me_cmd = cmd16;
    }

    UINT32 bar_lo = 0, bar_hi = 0;
    if (hw_pci_cfg_read32_raw(cand_bus, cand_dev, cand_fn, 0x10U, &bar_lo) &&
        bar_lo != 0 && bar_lo != 0xFFFFFFFFU && (bar_lo & 1U) == 0) {
        UINT64 b64 = (UINT64)(bar_lo & ~0xFULL);
        if (((bar_lo >> 1) & 3U) == 2U &&
            hw_pci_cfg_read32_raw(cand_bus, cand_dev, cand_fn, 0x14U, &bar_hi)) {
            b64 |= ((UINT64)bar_hi << 32);
        }
        gUnlockMePsp.heci_bar0 = b64;
        if ((gUnlockMePsp.me_cmd & 0x0002U) != 0 && mmio_addr_reachable(b64, TRUE)) {
            gUnlockMePsp.heci_mmio_ok = TRUE;
        }
    }

    static const UINT16 kHfOffs[6] = { 0x40U, 0x48U, 0x60U, 0x64U, 0x68U, 0x6CU };
    for (UINTN i = 0; i < 6U; i++) {
        UINT32 v = 0;
        if (hw_pci_cfg_read32_raw(cand_bus, cand_dev, cand_fn, kHfOffs[i], &v)) {
            gUnlockMePsp.hfsts[i] = v;
        }
    }

    UINT32 h1 = gUnlockMePsp.hfsts[0];
    gUnlockMePsp.working_state = (UINT8)(h1 & 0x0FU);
    gUnlockMePsp.mfg_mode      = ((h1 & (1U << 4)) != 0);
    gUnlockMePsp.fpt_bad       = ((h1 & (1U << 5)) != 0);
    gUnlockMePsp.op_state      = (UINT8)((h1 >> 6) & 0x07U);
    gUnlockMePsp.fw_init_done  = ((h1 & (1U << 9)) != 0);
    gUnlockMePsp.error_code    = (UINT8)((h1 >> 12) & 0x0FU);
    gUnlockMePsp.op_mode       = (UINT8)((h1 >> 16) & 0x0FU);
    str_cpy(gUnlockMePsp.working_state_str, me_working_state_name(gUnlockMePsp.working_state),
            sizeof(gUnlockMePsp.working_state_str));
    str_cpy(gUnlockMePsp.op_mode_str, me_op_mode_name(gUnlockMePsp.op_mode),
            sizeof(gUnlockMePsp.op_mode_str));

    /* Intel Boot Guard (HFSTS6 @ 0x6C on Haswell/Broadwell/Skylake+) */
    if (gHw.cpu_family == 6U && gHw.cpu_model >= 0x3CU &&
        gUnlockMePsp.hfsts[5] != 0xFFFFFFFFU && gUnlockMePsp.hfsts[5] != 0U) {
        UINT32 h6 = gUnlockMePsp.hfsts[5];
        gUnlockMePsp.boot_guard_valid      = TRUE;
        gUnlockMePsp.boot_guard_verified   = ((h6 & ((1U << 0) | (1U << 28))) != 0);
        gUnlockMePsp.boot_guard_measured   = ((h6 & (1U << 29)) != 0);
        gUnlockMePsp.boot_guard_fpf_locked = ((h6 & (1U << 30)) != 0);
    }

    if (prev_ver_ok && !query_heci_mkhi) {
        gUnlockMePsp.fw_ver_valid   = TRUE;
        gUnlockMePsp.fw_major       = prev_maj;
        gUnlockMePsp.fw_minor       = prev_min;
        gUnlockMePsp.fw_hotfix      = prev_hf;
        gUnlockMePsp.fw_build       = prev_bld;
        gUnlockMePsp.hmrfpo_queried = prev_hmr_ok;
        gUnlockMePsp.hmrfpo_status  = prev_hmr_st;
    } else if (query_heci_mkhi && gUnlockMePsp.heci_mmio_ok && gUnlockMePsp.working_state == 5U) {
        /* MKHI_GEN_GET_FW_VERSION: Group=0xFF, Cmd=0x02 */
        UINT32 tx_ver = 0x000002FFU;
        UINT32 rx[8];
        UINTN  rbytes = 0;
        memset(rx, 0, sizeof(rx));
        if (heci1_mkhi_transact(&tx_ver, 1U, 4U, rx, 8U, &rbytes) && rbytes >= 12U &&
            ((rx[0] >> 24) & 0xFFU) == 0U) {
            gUnlockMePsp.fw_ver_valid = TRUE;
            gUnlockMePsp.fw_minor     = (UINT16)(rx[1] & 0xFFFFU);
            gUnlockMePsp.fw_major     = (UINT16)((rx[1] >> 16) & 0xFFFFU);
            gUnlockMePsp.fw_build     = (UINT16)(rx[2] & 0xFFFFU);
            gUnlockMePsp.fw_hotfix    = (UINT16)((rx[2] >> 16) & 0xFFFFU);
        }

        /* MKHI_HMRFPO_GET_STATUS: Group=0x05, Cmd=0x03 */
        UINT32 tx_hmr = 0x00000305U;
        memset(rx, 0, sizeof(rx));
        if (heci1_mkhi_transact(&tx_hmr, 1U, 4U, rx, 8U, &rbytes) && rbytes >= 5U &&
            ((rx[0] >> 24) & 0xFFU) == 0U) {
            gUnlockMePsp.hmrfpo_queried = TRUE;
            gUnlockMePsp.hmrfpo_status  = (UINT8)(rx[1] & 0xFFU);
        }
    }
}

static BOOLEAN send_me_hmrfpo_enable(CHAR8 *msg_out, UINTN max_msg) {
    if (!gUnlockMePsp.me_present || !gUnlockMePsp.heci_mmio_ok) {
        str_cpy(msg_out, "Intel ME HECI1 MMIO BAR0 is not active/mapped on this platform.", max_msg);
        return FALSE;
    }
    /* MKHI_HMRFPO_ENABLE: Group=0x05, Cmd=0x01 + 64-bit Nonce (0) */
    UINT32 tx[3] = { 0x00000105U, 0x00000000U, 0x00000000U };
    UINT32 rx[8];
    UINTN  rbytes = 0;
    memset(rx, 0, sizeof(rx));
    if (!heci1_mkhi_transact(tx, 3U, 12U, rx, 8U, &rbytes) || rbytes < 4U) {
        str_cpy(msg_out, "HECI1 MKHI_HMRFPO_ENABLE timed out or ME rejected host message (End-of-Post may already be asserted).", max_msg);
        return FALSE;
    }
    UINT8 mkhi_res = (UINT8)((rx[0] >> 24) & 0xFFU);
    UINT8 hmr_sts  = (rbytes >= 13U) ? (UINT8)(rx[3] & 0xFFU) : (UINT8)(rx[1] & 0xFFU);
    probe_intel_me_and_amd_psp(TRUE);

    if (mkhi_res == 0U && (hmr_sts == 0U || gUnlockMePsp.op_mode == 5U)) {
        snprintf_ascii(msg_out, max_msg,
            "MKHI_HMRFPO_ENABLE ACCEPTED! (Result=0x00, Status=0x%02X, HFSTS1=0x%08X).\n"
            "ME Flash Protection Override is now active until next global reset!",
            (UINT32)hmr_sts, gUnlockMePsp.hfsts[0]);
        return TRUE;
    }
    snprintf_ascii(msg_out, max_msg,
        "ME responded to MKHI_HMRFPO_ENABLE with Result=0x%02X, Status=0x%02X (HFSTS1=0x%08X).\n"
        "Tip: Enable 'ME FW Image Re-Flash' or disable 'End of Post' in HII options below & reboot!",
        (UINT32)mkhi_res, (UINT32)hmr_sts, gUnlockMePsp.hfsts[0]);
    return FALSE;
}

/* =========================================================================
 * 4. PCH / ICH9 / AMD FCH SPI & BIOS Flash Write-Protection Inspector
 * ========================================================================= */
static VOID populate_intel_spibar_regs(UINT64 spibar, BOOLEAN is_100_series_layout) {
    if (!mmio_addr_reachable(spibar, FALSE)) return;
    UINT16 hsfs = 0xFFFFU;
    if (!safe_read_mem(spibar + 0x04U, &hsfs, 2) || hsfs == 0xFFFFU) return;

    gUnlockSpi.spibar_valid = TRUE;
    gUnlockSpi.spibar_phys  = spibar;
    gUnlockSpi.hsfsts       = hsfs;
    gUnlockSpi.flockdn      = ((hsfs & (1U << 15)) != 0);
    gUnlockSpi.fdv          = ((hsfs & (1U << 14)) != 0);
    gUnlockSpi.fdopss       = ((hsfs & (1U << 13)) != 0);

    UINT32 frap = 0;
    if (safe_read_mem(spibar + 0x50U, &frap, 4)) {
        gUnlockSpi.frap = frap;
        gUnlockSpi.brra = (UINT8)(frap & 0xFFU);
        gUnlockSpi.brwa = (UINT8)((frap >> 8) & 0xFFU);
    }

    UINT16 fpr_base = is_100_series_layout ? 0x84U : 0x54U;
    UINT8  wpe_cnt  = 0;
    for (UINTN i = 0; i < 5U; i++) {
        UINT32 pr = 0;
        if (safe_read_mem(spibar + fpr_base + i * 4U, &pr, 4)) {
            gUnlockSpi.fpr[i] = pr;
            if ((pr & (1U << 31)) != 0) wpe_cnt++;
        }
    }
    gUnlockSpi.fpr_wpe_count = wpe_cnt;
}

static VOID probe_spi_flash_locks(VOID) {
    memset(&gUnlockSpi, 0, sizeof(gUnlockSpi));

    /* 1. Try Modern Intel 100..700-Series PCH SPI Controller (PCI 00:1F.5) */
    UINT32 id_1f5 = 0xFFFFFFFFU;
    if (!gHw.cpu_msr.is_amd &&
        hw_pci_cfg_read32_raw(0, 0x1FU, 5U, 0x00U, &id_1f5) &&
        (id_1f5 & 0xFFFFU) == 0x8086U && (id_1f5 >> 16) != 0xFFFFU) {
        gUnlockSpi.present    = TRUE;
        gUnlockSpi.is_pch_1f5 = TRUE;
        gUnlockSpi.bus        = 0;
        gUnlockSpi.dev        = 0x1FU;
        gUnlockSpi.func       = 5U;
        gUnlockSpi.vid        = 0x8086U;
        gUnlockSpi.did        = (UINT16)(id_1f5 >> 16);
        str_cpy(gUnlockSpi.controller_name, "Intel PCH SPI (00:1F.5)", sizeof(gUnlockSpi.controller_name));

        UINT8 bc = 0;
        if (hw_pci_cfg_read8_raw(0, 0x1FU, 5U, 0xDCU, &bc)) {
            gUnlockSpi.bios_cntl_valid = TRUE;
            gUnlockSpi.bios_cntl       = bc;
            gUnlockSpi.bioswe          = ((bc & 0x01U) != 0);
            gUnlockSpi.ble             = ((bc & 0x02U) != 0);
            gUnlockSpi.eiss            = ((bc & 0x20U) != 0);
        }
        UINT32 bar0 = 0;
        if (hw_pci_cfg_read32_raw(0, 0x1FU, 5U, 0x10U, &bar0) &&
            bar0 != 0 && bar0 != 0xFFFFFFFFU && (bar0 & 1U) == 0) {
            populate_intel_spibar_regs((UINT64)(bar0 & ~0xFFFU), TRUE);
        }
        if (!gUnlockSpi.spibar_valid) {
            populate_intel_spibar_regs(0xFE010000ULL, TRUE);
        }
        return;
    }

    /* 2. Try Intel ICH9 / 5..9-Series LPC Bridge (PCI 00:1F.0 + RCBA+0x3800 — also QEMU q35!) */
    UINT32 id_1f0 = 0xFFFFFFFFU;
    if (hw_pci_cfg_read32_raw(0, 0x1FU, 0U, 0x00U, &id_1f0) &&
        (id_1f0 & 0xFFFFU) == 0x8086U && (id_1f0 >> 16) != 0xFFFFU) {
        gUnlockSpi.present    = TRUE;
        gUnlockSpi.is_pch_1f5 = FALSE;
        gUnlockSpi.bus        = 0;
        gUnlockSpi.dev        = 0x1FU;
        gUnlockSpi.func       = 0U;
        gUnlockSpi.vid        = 0x8086U;
        gUnlockSpi.did        = (UINT16)(id_1f0 >> 16);
        str_cpy(gUnlockSpi.controller_name, "Intel LPC/SPI (00:1F.0)", sizeof(gUnlockSpi.controller_name));

        /* Check if P2SB-hidden 100+ series SPI MMIO @ 0xFE010000 is mapped on Skylake+ */
        if (!gHw.feat_hypervisor && gHw.cpu_family == 6U && gHw.cpu_model >= 0x4EU) {
            populate_intel_spibar_regs(0xFE010000ULL, TRUE);
        }

        UINT8 bc = 0;
        if (hw_pci_cfg_read8_raw(0, 0x1FU, 0U, 0xDCU, &bc) && bc != 0xFFU) {
            gUnlockSpi.bios_cntl_valid = TRUE;
            gUnlockSpi.bios_cntl       = bc;
            gUnlockSpi.bioswe          = ((bc & 0x01U) != 0);
            gUnlockSpi.ble             = ((bc & 0x02U) != 0);
            gUnlockSpi.eiss            = ((bc & 0x20U) != 0);
        }
        if (!gUnlockSpi.spibar_valid) {
            UINT32 rcba = 0;
            if (hw_pci_cfg_read32_raw(0, 0x1FU, 0U, 0xF0U, &rcba) &&
                (rcba & 1U) != 0 && rcba != 0xFFFFFFFFU) {
                UINT64 spibar = (UINT64)(rcba & ~0x3FFFU) + 0x3800ULL;
                populate_intel_spibar_regs(spibar, FALSE);
            }
        }
        return;
    }

    /* 3. Try AMD FCH LPC/SPI Bridge (PCI 00:14.3 Vendor 0x1022 / 0x1002) */
    UINT32 id_143 = 0xFFFFFFFFU;
    if (hw_pci_cfg_read32_raw(0, 0x14U, 3U, 0x00U, &id_143) &&
        ((id_143 & 0xFFFFU) == 0x1022U || (id_143 & 0xFFFFU) == 0x1002U)) {
        gUnlockSpi.present    = TRUE;
        gUnlockSpi.is_amd_fch = TRUE;
        gUnlockSpi.bus        = 0;
        gUnlockSpi.dev        = 0x14U;
        gUnlockSpi.func       = 3U;
        gUnlockSpi.vid        = (UINT16)(id_143 & 0xFFFFU);
        gUnlockSpi.did        = (UINT16)(id_143 >> 16);
        str_cpy(gUnlockSpi.controller_name, "AMD FCH LPC/SPI (00:14.3)", sizeof(gUnlockSpi.controller_name));

        UINT32 spi_base = 0;
        if (hw_pci_cfg_read32_raw(0, 0x14U, 3U, 0xA0U, &spi_base) &&
            spi_base != 0 && spi_base != 0xFFFFFFFFU) {
            UINT64 base = (UINT64)(spi_base & 0xFFFFFF00U);
            if (mmio_addr_reachable(base, FALSE)) {
                gUnlockSpi.spibar_valid = TRUE;
                gUnlockSpi.spibar_phys  = base;
            }
        }
    }
}

VOID unlock_refresh_all(BOOLEAN deep_probe) {
    BOOLEAN do_deep = deep_probe || !s_deep_probed_once;
    if (do_deep) {
        s_deep_probed_once = TRUE;
        refresh_fivr_offsets();
    }
    probe_intel_me_and_amd_psp(do_deep);
    probe_spi_flash_locks();
}

/* =========================================================================
 * 5. HII Unlock Matchers, One-Click Unlock & Interactive HII Question Editor
 * ========================================================================= */
static VOID edit_hii_q_modal(UINTN q_idx) {
    if (!gHw.hii_questions || q_idx >= gHw.hii_question_count) return;
    const HW_HII_QUESTION *q = &gHw.hii_questions[q_idx];

    UINT64 cur_val = 0;
    BOOLEAN in_nv = FALSE;
    hw_hii_read_question_val(q_idx, &cur_val, &in_nv);

    if (!in_nv) {
        const CHAR8 *vs_nm = (q->varstore_idx >= 0 && (UINTN)q->varstore_idx < gHw.hii_varstore_count)
                             ? gHw.hii_varstores[q->varstore_idx].name : "Unknown";
        CHAR8 msg[280];
        snprintf_ascii(msg, sizeof(msg),
            "Setting: %s\nVarStore: \"%s\"  VarOffset: 0x%04X (%u byte)%s\n\n"
            "This IFR VarStore is not currently exposed as a standalone UEFI NVRAM variable.",
            q->prompt, vs_nm, (UINT32)q->var_offset, (UINT32)q->width,
            q->is_suppressed ? " [HIDDEN]" : "");
        ui_message_modal("HII IFR Offset Info", msg, FALSE);
        return;
    }

    CHAR8 err[160];
    err[0] = '\0';

    if (q->opt_count > 0) {
        CHAR8 obufs[HW_MAX_HII_Q_OPTS][56];
        const CHAR8 *optrs[HW_MAX_HII_Q_OPTS];
        UINTN cur_i = 0;
        for (UINT8 i = 0; i < q->opt_count; i++) {
            snprintf_ascii(obufs[i], sizeof(obufs[i]), "%s (0x%02lX)", q->opts[i].label, q->opts[i].value);
            optrs[i] = obufs[i];
            if (q->opts[i].value == cur_val) cur_i = i;
        }
        INTN picked = ui_pick_option_modal(q->prompt, optrs, q->opt_count, cur_i, cur_i);
        if (picked >= 0 && (UINTN)picked < q->opt_count) {
            if (!hw_hii_write_question_val(q_idx, q->opts[picked].value, err, sizeof(err))) {
                ui_message_modal("HII Write Failed", err, TRUE);
            }
        }
    } else {
        CHAR8 init_s[32], out_s[32], pr[96];
        snprintf_ascii(init_s, sizeof(init_s), "0x%lX", cur_val);
        snprintf_ascii(pr, sizeof(pr), "VarOffset 0x%04X (%uB) | Range: 0x%lX .. 0x%lX (hex):",
                       (UINT32)q->var_offset, (UINT32)q->width, q->min_val, q->max_val);
        if (ui_input_modal(q->prompt, pr, init_s, out_s, sizeof(out_s), TRUE)) {
            UINT64 nv = 0;
            if (parse_hex_u64(out_s, &nv)) {
                if (!hw_hii_write_question_val(q_idx, nv, err, sizeof(err))) {
                    ui_message_modal("HII Write Failed", err, TRUE);
                }
            }
        }
    }
}

static BOOLEAN is_unlock_hub_hii_q(const HW_HII_QUESTION *q) {
    const CHAR8 *p = q->prompt;
    if (gHw.cpu_msr.is_amd) {
        return str_contains_icase(p, "PSP") ||
               str_contains_icase(p, "fTPM") ||
               str_contains_icase(p, "Security Device") ||
               str_contains_icase(p, "Pluton") ||
               str_contains_icase(p, "TSME") ||
               str_contains_icase(p, "SMEE") ||
               str_contains_icase(p, "IOMMU") ||
               str_contains_icase(p, "Curve Optimizer") ||
               str_contains_icase(p, "Precision Boost") ||
               str_contains_icase(p, "BIOS Lock") ||
               str_contains_icase(p, "Flash") ||
               str_contains_icase(p, "SPI") ||
               str_contains_icase(p, "Lock");
    }
    return str_contains_icase(p, "Overclocking Lock") ||
           str_contains_icase(p, "OC Lock") ||
           str_contains_icase(p, "CFG Lock") ||
           str_contains_icase(p, "Undervolt") ||
           str_contains_icase(p, "Voltage Offset") ||
           str_contains_icase(p, "BIOS Lock") ||
           str_contains_icase(p, "BIOS Guard") ||
           str_contains_icase(p, "Flash Protection") ||
           str_contains_icase(p, "FPRR") ||
           str_contains_icase(p, "SPI Lock") ||
           str_contains_icase(p, "ME State") ||
           str_contains_icase(p, "ME FW") ||
           str_contains_icase(p, "MeFwDowngrade") ||
           str_contains_icase(p, "End of Post") ||
           str_contains_icase(p, "High Assurance") ||
           str_contains_icase(p, "HAP") ||
           str_contains_icase(p, "AltMeDisable") ||
           str_contains_icase(p, "CSME") ||
           str_contains_icase(p, "AMT") ||
           str_contains_icase(p, "SGX") ||
           str_contains_icase(p, "Software Guard") ||
           str_contains_icase(p, "VT-d");
}

static UINTN collect_unlock_hii_questions(UINTN *out_idx, UINTN max_out) {
    UINTN cnt = 0;
    if (!gHw.hii_questions) return 0;
    for (UINTN i = 0; i < gHw.hii_question_count && cnt < max_out; i++) {
        if (is_unlock_hub_hii_q(&gHw.hii_questions[i])) {
            out_idx[cnt++] = i;
        }
    }
    return cnt;
}

static VOID run_one_click_undervolt_cfg_unlock(VOID) {
    UINTN targets[16];
    UINTN tcnt = 0;
    if (gHw.hii_questions) {
        for (UINTN i = 0; i < gHw.hii_question_count && tcnt < 16U; i++) {
            const CHAR8 *p = gHw.hii_questions[i].prompt;
            if (str_contains_icase(p, "Overclocking Lock") ||
                str_icmp(p, "OC Lock") == 0 ||
                str_contains_icase(p, "CFG Lock") ||
                str_contains_icase(p, "Undervolt Protection")) {
                targets[tcnt++] = i;
            }
        }
    }

    BOOLEAN msr_cfg_unlocked = FALSE;
    if (gHw.cpu_msr.cst_cfg_valid && gHw.cpu_msr.cfg_locked) {
        if (hw_intel_unlock_cfg_lock_msr()) msr_cfg_unlocked = TRUE;
    }

    if (tcnt == 0) {
        CHAR8 msg[320];
        snprintf_ascii(msg, sizeof(msg),
            "No IFR questions named 'Overclocking Lock', 'CFG Lock', or 'Undervolt Protection' were found in HII/FV2 (%u total decoded questions).\n\n"
            "%s"
            "If you know your model's hex offset (e.g. Dell XPS 7590 Setup 0x789 -> 0x00), select 'setup_var / setup_var_3 Offset Editor' right below!",
            (UINT32)gHw.hii_question_count,
            msr_cfg_unlocked ? "Live MSR 0xE2 CFG Lock WAS unlocked for this boot!\n\n" : "");
        ui_message_modal("Auto-Unlock Scan Result", msg, FALSE);
        return;
    }

    CHAR8 preview[420];
    UINTN pos = 0;
    pos += (UINTN)snprintf_ascii(preview, sizeof(preview),
        "Found %u hardware lock option(s) in BIOS IFR:\n", (UINT32)tcnt);
    for (UINTN i = 0; i < tcnt && pos + 80U < sizeof(preview); i++) {
        const HW_HII_QUESTION *q = &gHw.hii_questions[targets[i]];
        const CHAR8 *vsn = (q->varstore_idx >= 0 && (UINTN)q->varstore_idx < gHw.hii_varstore_count)
                           ? gHw.hii_varstores[q->varstore_idx].name : "?";
        UINT64 cv = 0;
        BOOLEAN in_nv = FALSE;
        hw_hii_read_question_val(targets[i], &cv, &in_nv);
        pos += (UINTN)snprintf_ascii(preview + pos, sizeof(preview) - pos,
            " - %s (%s:0x%X) [%s -> 0x00]\n",
            q->prompt, vsn, (UINT32)q->var_offset,
            in_nv ? (cv ? "0x01 Locked" : "0x00 Unlocked") : "NoNVRAM");
    }
    snprintf_ascii(preview + pos, sizeof(preview) - pos,
        "\nSet all matched locks to 0x00 (Disabled/Unlocked) via setup_var_3 NVRAM write?");

    if (!ui_confirm_modal("Confirm One-Click Undervolt & CFG Unlock", preview, TRUE)) return;

    UINTN ok_cnt = 0, fail_cnt = 0;
    CHAR8 last_err[140];
    last_err[0] = '\0';
    for (UINTN i = 0; i < tcnt; i++) {
        UINT64 disable_val = 0;
        const HW_HII_QUESTION *q = &gHw.hii_questions[targets[i]];
        for (UINT8 oi = 0; oi < q->opt_count; oi++) {
            if (str_contains_icase(q->opts[oi].label, "Disable") ||
                str_contains_icase(q->opts[oi].label, "Unlock")) {
                disable_val = q->opts[oi].value;
                break;
            }
        }
        if (hw_hii_write_question_val(targets[i], disable_val, last_err, sizeof(last_err))) ok_cnt++;
        else fail_cnt++;
    }

    CHAR8 res[300];
    if (ok_cnt > 0 && fail_cnt == 0) {
        snprintf_ascii(res, sizeof(res),
            "Unlocked %u/%u BIOS lock setting(s) in NVRAM!\n"
            "Perform a Cold/Warm Reboot for CPU microcode to load unlockedMSR 0xE2 / 0x194 / FIVR 0x150.",
            (UINT32)ok_cnt, (UINT32)tcnt);
        ui_message_modal("Unlock Written to NVRAM", res, FALSE);
    } else {
        snprintf_ascii(res, sizeof(res),
            "Updated %u/%u setting(s) (%u failed).\nLast error: %s",
            (UINT32)ok_cnt, (UINT32)tcnt, (UINT32)fail_cnt,
            last_err[0] ? last_err : "VarStore not in NVRAM");
        ui_message_modal("Unlock Partial / Write-Protected", res, TRUE);
    }
}

/* =========================================================================
 * 6. Built-In datasone/grub-mod-setup_var Engine
 *    Supports ALL 5 grub-mod-setup_var modes + Direct CLI Command Input:
 *      - setup_var      <off> [val]          (First Setup VarStore)
 *      - setup_var2     <off> [val]          (Sync Setup + Custom on InsydeH2O)
 *      - setup_var_3    <off> [val]          (Skip <0x10B dummy Setup decoys)
 *      - setup_var_vs   <off> <sz> [val]     (1/2/4/8B width in Setup)
 *      - setup_var_cv   <var> <off> [sz] [v] (Any named VarStore)
 *    Includes HiiConfigRouting->RouteConfig sync, multi-GUID shadow sync,
 *    and immediate post-write GetVariable() read-back verification!
 * ========================================================================= */
#define SV_MAX_CANDS 32

static VOID sv_try_route_config(const CHAR16 *vname_w, const EFI_GUID *vguid, const UINT8 *buf, UINTN bsz) {
    if (!vname_w || !vguid || !buf || bsz == 0) return;
    EFI_HII_CONFIG_ROUTING_PROTOCOL *rt = NULL;
    if (EFI_ERROR(efi_locate_protocol(&gEfiHiiConfigRoutingProtocolGuid, (VOID **)&rt)) ||
        !rt || !rt->BlockToConfig || !rt->RouteConfig) {
        return;
    }

    CHAR16 hdr[192];
    CHAR16 *req = NULL;
    UINTN req_chars = (UINTN)wsnprintf(hdr, 192,
        "GUID=%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x&NAME=",
        vguid->Data1, (UINT32)vguid->Data2, (UINT32)vguid->Data3,
        (UINT32)vguid->Data4[0], (UINT32)vguid->Data4[1],
        (UINT32)vguid->Data4[2], (UINT32)vguid->Data4[3],
        (UINT32)vguid->Data4[4], (UINT32)vguid->Data4[5],
        (UINT32)vguid->Data4[6], (UINT32)vguid->Data4[7]);
    UINTN nlen = wstr_len(vname_w);
    req = (CHAR16 *)alloc_zero_pool((req_chars + nlen * 4U + 64U) * sizeof(CHAR16));
    if (!req) return;
    memcpy(req, hdr, req_chars * sizeof(CHAR16));
    UINTN p = req_chars;
    static const CHAR16 kHexL[16] = {
        L'0',L'1',L'2',L'3',L'4',L'5',L'6',L'7',L'8',L'9',L'a',L'b',L'c',L'd',L'e',L'f'
    };
    for (UINTN i = 0; i < nlen; i++) {
        UINT16 ch = (UINT16)vname_w[i];
        req[p++] = kHexL[(ch >> 12) & 0xFU];
        req[p++] = kHexL[(ch >> 8)  & 0xFU];
        req[p++] = kHexL[(ch >> 4)  & 0xFU];
        req[p++] = kHexL[ch & 0xFU];
    }
    p += (UINTN)wsnprintf(req + p, 48U, "&OFFSET=0&WIDTH=%x", (UINT32)bsz);

    CHAR16 *cfg = NULL, *prog = NULL;
    if (!EFI_ERROR(rt->BlockToConfig(rt, req, buf, bsz, &cfg, &prog)) && cfg) {
        CHAR16 *rprog = NULL;
        rt->RouteConfig(rt, cfg, &rprog);
        free_pool(cfg);
    }
    free_pool(req);
}

static INTN sv_find_var_index(const CHAR8 *name, BOOLEAN skip_small_0x10, BOOLEAN pick_first) {
    INTN best_idx = -1;
    UINTN best_sz = 0;
    for (UINTN i = 0; i < gVarCount; i++) {
        if (str_icmp(gVarList[i].name, name) != 0) continue;
        if (skip_small_0x10 && gVarList[i].data_size < 0x10U) continue;
        if (gVarList[i].data_size == 0) continue;
        if (pick_first) return (INTN)i;
        if (gVarList[i].data_size >= best_sz) {
            best_sz  = gVarList[i].data_size;
            best_idx = (INTN)i;
        }
    }
    if (best_idx < 0 && skip_small_0x10) {
        return sv_find_var_index(name, FALSE, pick_first);
    }
    return best_idx;
}

static INTN sv_cross_check_ifr(const CHAR8 *store_name, UINTN byte_off) {
    if (!gHw.hii_questions || !store_name) return -1;
    for (UINTN qi = 0; qi < gHw.hii_question_count; qi++) {
        const HW_HII_QUESTION *q = &gHw.hii_questions[qi];
        UINTN q_byte_off = q->is_bitfield ? ((UINTN)q->var_offset / 8U) : (UINTN)q->var_offset;
        if (q_byte_off == byte_off &&
            q->varstore_idx >= 0 && (UINTN)q->varstore_idx < gHw.hii_varstore_count &&
            str_icmp(gHw.hii_varstores[q->varstore_idx].name, store_name) == 0) {
            return (INTN)qi;
        }
    }
    return -1;
}

static VOID sv_commit_offset_interactive(
    INTN var_idx,
    UINTN off,
    UINTN width,
    BOOLEAN has_preset_val,
    UINT64 preset_val,
    BOOLEAN sync_custom_store,
    const CHAR8 *mode_tag
) {
    if (var_idx < 0 || (UINTN)var_idx >= gVarCount) return;
    if (width != 1U && width != 2U && width != 4U && width != 8U) width = 1U;

    const NVRAM_VAR_ENTRY *ve = &gVarList[var_idx];
    UINT32 attrs = 0;
    UINTN  vsz   = 0;
    UINT8 *vdata = NULL;
    if (EFI_ERROR(nvram_read_var(ve->name_w, (EFI_GUID *)&ve->guid, &attrs, &vsz, &vdata)) || !vdata || vsz == 0) {
        if (vdata) free_pool(vdata);
        ui_message_modal("Read Failed", "Could not read selected NVRAM variable data.", TRUE);
        return;
    }

    if (off + width > vsz) {
        free_pool(vdata);
        CHAR8 oob[160];
        snprintf_ascii(oob, sizeof(oob),
            "Offset 0x%X (%u byte%s) exceeds '%s' size (%u bytes / max 0x%X)!",
            (UINT32)off, (UINT32)width, (width > 1U) ? "s" : "",
            ve->name, (UINT32)vsz, (UINT32)(vsz - 1U));
        ui_message_modal("Offset Out of Range", oob, TRUE);
        return;
    }

    UINT64 cur_val = 0;
    for (UINTN b = 0; b < width; b++) {
        cur_val |= ((UINT64)vdata[off + b] << (b * 8U));
    }

    INTN matched_q = sv_cross_check_ifr(ve->name, off);

    CHAR8 ctx_hex[64];
    UINTN cs = (off >= 4U) ? (off - 4U) : 0U;
    UINTN ce = (cs + 8U <= vsz) ? (cs + 8U) : vsz;
    UINTN hp = 0;
    for (UINTN k = cs; k < ce && hp + 5U < sizeof(ctx_hex); k++) {
        hp += (UINTN)snprintf_ascii(ctx_hex + hp, sizeof(ctx_hex) - hp,
                                    (k == off) ? "[%02X] " : "%02X ", (UINT32)vdata[k]);
    }

    UINT64 new_val   = preset_val;
    BOOLEAN have_new = has_preset_val;

    if (!have_new && matched_q >= 0 && !gHw.hii_questions[matched_q].is_bitfield &&
        gHw.hii_questions[matched_q].opt_count > 0) {
        const HW_HII_QUESTION *mq = &gHw.hii_questions[matched_q];
        CHAR8 obufs[HW_MAX_HII_Q_OPTS + 1][64];
        const CHAR8 *optrs[HW_MAX_HII_Q_OPTS + 1];
        UINTN cur_i = 0;
        for (UINT8 oi = 0; oi < mq->opt_count; oi++) {
            snprintf_ascii(obufs[oi], sizeof(obufs[oi]), "0x%02lX = %s",
                           mq->opts[oi].value, mq->opts[oi].label);
            optrs[oi] = obufs[oi];
            if (mq->opts[oi].value == cur_val) cur_i = oi;
        }
        str_cpy(obufs[mq->opt_count], "Enter Custom Hex Value...", sizeof(obufs[mq->opt_count]));
        optrs[mq->opt_count] = obufs[mq->opt_count];

        CHAR8 ptitle[72];
        snprintf_ascii(ptitle, sizeof(ptitle), "%s[0x%X] = \"%s\"",
                       ve->name, (UINT32)off, mq->prompt);
        INTN op = ui_pick_option_modal(ptitle, optrs, (UINTN)mq->opt_count + 1U, cur_i, cur_i);
        if (op < 0) { free_pool(vdata); return; }
        if ((UINTN)op < mq->opt_count) {
            new_val  = mq->opts[op].value;
            have_new = TRUE;
        }
    }

    if (!have_new) {
        CHAR8 val_prompt[120], init_hex[24], out_hex[24], mtitle[72];
        if (matched_q >= 0) {
            snprintf_ascii(mtitle, sizeof(mtitle), "%s[0x%X]: %s",
                           ve->name, (UINT32)off, gHw.hii_questions[matched_q].prompt);
        } else {
            snprintf_ascii(mtitle, sizeof(mtitle), "%s[0x%X] (Cur=0x%lX)",
                           ve->name, (UINT32)off, cur_val);
        }
        snprintf_ascii(val_prompt, sizeof(val_prompt),
            "Bytes @0x%X: %s| New %uB hex:", (UINT32)cs, ctx_hex, (UINT32)width);
        snprintf_ascii(init_hex, sizeof(init_hex), "0x%02lX", cur_val);
        if (!ui_input_modal(mtitle, val_prompt, init_hex, out_hex, sizeof(out_hex), TRUE)) {
            free_pool(vdata);
            return;
        }
        if (!parse_hex_u64(out_hex, &new_val)) {
            free_pool(vdata);
            return;
        }
    }

    CHAR8 confirm_txt[420];
    if (matched_q >= 0) {
        snprintf_ascii(confirm_txt, sizeof(confirm_txt),
            "Mode     : %s  |  Store: %s (%uB, Attr 0x%02X)%s\n"
            "IFR Match: \"%s\"%s%s\n"
            "Offset   : 0x%04X (%uB)  |  0x%02lX  -->  0x%02lX\n\n"
            "Write to NVRAM (+ RouteConfig & Read-Back Verify) now?",
            mode_tag ? mode_tag : "setup_var_3", ve->name, (UINT32)vsz, attrs,
            sync_custom_store ? " [+Custom Sync]" : "",
            gHw.hii_questions[matched_q].prompt,
            gHw.hii_questions[matched_q].is_suppressed ? " [HIDDEN]" : "",
            gHw.hii_questions[matched_q].is_bitfield ? " [Bitfield Store]" : "",
            (UINT32)off, (UINT32)width, cur_val, new_val);
    } else {
        snprintf_ascii(confirm_txt, sizeof(confirm_txt),
            "Mode     : %s  |  Store: %s (%uB, Attr 0x%02X)%s\n"
            "IFR Match: <No exported HII match — verify offset matches your exact BIOS!>\n"
            "Bytes    : @0x%X: %s\n"
            "Offset   : 0x%04X (%uB)  |  0x%02lX  -->  0x%02lX\n\n"
            "Write to NVRAM (+ RouteConfig & Read-Back Verify) now?",
            mode_tag ? mode_tag : "setup_var_3", ve->name, (UINT32)vsz, attrs,
            sync_custom_store ? " [+Custom Sync]" : "",
            (UINT32)cs, ctx_hex,
            (UINT32)off, (UINT32)width, cur_val, new_val);
    }

    if (!ui_confirm_modal("Confirm grub-mod-setup_var NVRAM Write", confirm_txt, TRUE)) {
        free_pool(vdata);
        return;
    }

    for (UINTN b = 0; b < width; b++) {
        vdata[off + b] = (UINT8)((new_val >> (b * 8U)) & 0xFFULL);
    }
    if (attrs == 0) {
        attrs = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
    }

    CHAR16 saved_name_w[64];
    CHAR8  saved_name_a[64];
    EFI_GUID saved_guid = ve->guid;
    wstr_cpy(saved_name_w, ve->name_w, 64);
    str_cpy(saved_name_a, ve->name, sizeof(saved_name_a));

    EFI_STATUS st = nvram_write_var(saved_name_w, &saved_guid, attrs, vsz, vdata);
    if (EFI_ERROR(st)) {
        free_pool(vdata);
        CHAR8 err[260];
        snprintf_ascii(err, sizeof(err),
            "SetVariable(\"%s\") failed: %s!\n%s",
            saved_name_a, efi_status_str(st),
            (st == EFI_WRITE_PROTECTED || st == EFI_SECURITY_VIOLATION)
                ? "SMM NVRAM write-protection (SPI BIOS Lock / Protected Setup) blocked the write."
                : "Firmware rejected variable update.");
        ui_message_modal("setup_var Write Rejected", err, TRUE);
        return;
    }

    /* RouteConfig driver sync (ThinkPad Setup Checksum / AMD AGESA APCB sync) */
    sv_try_route_config(saved_name_w, &saved_guid, vdata, vsz);

    /* Sync secondary GUID shadow copies + InsydeH2O "Custom" mirror (setup_var2) */
    UINTN synced_mirrors = 0;
    for (UINTN i = 0; i < gVarCount; i++) {
        const NVRAM_VAR_ENTRY *other = &gVarList[i];
        BOOLEAN is_same_name = (str_icmp(other->name, saved_name_a) == 0 &&
                                !guid_equal(&other->guid, &saved_guid) &&
                                other->data_size >= 0x10U);
        BOOLEAN is_custom_mirror = ((sync_custom_store || str_icmp(saved_name_a, "Setup") == 0) &&
                                    str_icmp(other->name, "Custom") == 0);
        if (!is_same_name && !is_custom_mirror) continue;
        if (other->data_size < off + width) continue;

        UINT32 oa = 0;
        UINTN  osz = 0;
        UINT8 *obuf = NULL;
        if (!EFI_ERROR(nvram_read_var(other->name_w, (EFI_GUID *)&other->guid, &oa, &osz, &obuf)) &&
            obuf && osz >= off + width) {
            for (UINTN b = 0; b < width; b++) {
                obuf[off + b] = (UINT8)((new_val >> (b * 8U)) & 0xFFULL);
            }
            if (!EFI_ERROR(nvram_write_var(other->name_w, (EFI_GUID *)&other->guid, oa, osz, obuf))) {
                sv_try_route_config(other->name_w, &other->guid, obuf, osz);
                synced_mirrors++;
            }
        }
        if (obuf) free_pool(obuf);
    }

    free_pool(vdata);

    /* Immediate post-write GetVariable() read-back verification! */
    UINT32 va = 0;
    UINTN  vrsz = 0;
    UINT8 *vrbuf = NULL;
    UINT64 rb_val = 0;
    BOOLEAN rb_ok = FALSE;
    if (!EFI_ERROR(nvram_read_var(saved_name_w, &saved_guid, &va, &vrsz, &vrbuf)) &&
        vrbuf && off + width <= vrsz) {
        for (UINTN b = 0; b < width; b++) {
            rb_val |= ((UINT64)vrbuf[off + b] << (b * 8U));
        }
        rb_ok = (rb_val == new_val);
    }
    if (vrbuf) free_pool(vrbuf);

    nvram_enumerate_all();

    if (!rb_ok) {
        CHAR8 drop_msg[300];
        snprintf_ascii(drop_msg, sizeof(drop_msg),
            "WARNING: SetVariable(\"%s\") returned EFI_SUCCESS, but read-back at 0x%04X is still 0x%02lX (expected 0x%02lX)!\n\n"
            "Your BIOS SMM handler silently ignored the write (BIOS Lock / Protected NVRAM).\n"
            "Try enabling 'SPI BIOS Write-Enable' or unlocking 'BIOS Lock' first.",
            saved_name_a, (UINT32)off, rb_val, new_val);
        ui_message_modal("SMM Silent Write Drop Detected!", drop_msg, TRUE);
        return;
    }

    CHAR8 ok[260];
    snprintf_ascii(ok, sizeof(ok),
        "Verified %s[0x%04X] = 0x%02lX (was 0x%02lX)!%s\n"
        "Reboot from the Exit tab so motherboard firmware loads the updated NVRAM setting.",
        saved_name_a, (UINT32)off, rb_val, cur_val,
        (synced_mirrors > 0) ? " [Mirrors + RouteConfig Synced]" : " [Read-Back Verified]");
    ui_message_modal("setup_var Write Verified", ok, FALSE);
}

static UINTN tokenize_cli_args(CHAR8 *buf, CHAR8 *argv[], UINTN max_args) {
    UINTN argc = 0;
    CHAR8 *p = buf;
    while (*p && argc < max_args) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = '\0';
    }
    return argc;
}

static VOID run_setup_var_cli_modal(VOID) {
    CHAR8 cmd_in[128];
    if (!ui_input_modal(
            "datasone/grub-mod-setup_var Command Line",
            "Ex: setup_var_3 0x789 0x00 | setup_var_cv CpuSetup 0x43 0x01 0x00:",
            "setup_var_3 0x", cmd_in, sizeof(cmd_in), FALSE) || !cmd_in[0]) {
        return;
    }

    CHAR8 work[128];
    str_cpy(work, cmd_in, sizeof(work));
    CHAR8 *argv[6];
    UINTN argc = tokenize_cli_args(work, argv, 6U);
    if (argc < 2U) {
        ui_message_modal("Invalid Command Syntax",
            "Supported commands:\n"
            "  setup_var    <offset> [val]\n"
            "  setup_var2   <offset> [val]\n"
            "  setup_var_3  <offset> [val]\n"
            "  setup_var_vs <offset> <size> [val]\n"
            "  setup_var_cv <varname> <offset> [size] [val]",
            TRUE);
        return;
    }

    const CHAR8 *cmd  = argv[0];
    const CHAR8 *vnam = "Setup";
    BOOLEAN skip_0x10 = TRUE;
    BOOLEAN pick_1st  = FALSE;
    BOOLEAN sync_cust = FALSE;
    UINT64  off64     = 0;
    UINT64  sz64      = 1ULL;
    UINT64  val64     = 0;
    BOOLEAN has_val   = FALSE;
    BOOLEAN syntax_ok = FALSE;

    if (str_icmp(cmd, "setup_var") == 0) {
        skip_0x10 = FALSE;
        pick_1st  = TRUE;
        syntax_ok = parse_hex_u64(argv[1], &off64);
        if (syntax_ok && argc >= 3U) { syntax_ok = parse_hex_u64(argv[2], &val64); has_val = TRUE; }
    } else if (str_icmp(cmd, "setup_var2") == 0) {
        skip_0x10 = FALSE;
        sync_cust = TRUE;
        syntax_ok = parse_hex_u64(argv[1], &off64);
        if (syntax_ok && argc >= 3U) { syntax_ok = parse_hex_u64(argv[2], &val64); has_val = TRUE; }
    } else if (str_icmp(cmd, "setup_var_3") == 0) {
        skip_0x10 = TRUE;
        syntax_ok = parse_hex_u64(argv[1], &off64);
        if (syntax_ok && argc >= 3U) { syntax_ok = parse_hex_u64(argv[2], &val64); has_val = TRUE; }
    } else if (str_icmp(cmd, "setup_var_vs") == 0 && argc >= 3U) {
        skip_0x10 = TRUE;
        syntax_ok = parse_hex_u64(argv[1], &off64) && parse_hex_u64(argv[2], &sz64);
        if (syntax_ok && argc >= 4U) { syntax_ok = parse_hex_u64(argv[3], &val64); has_val = TRUE; }
    } else if (str_icmp(cmd, "setup_var_cv") == 0 && argc >= 3U) {
        vnam      = argv[1];
        skip_0x10 = FALSE;
        syntax_ok = parse_hex_u64(argv[2], &off64);
        if (syntax_ok && argc == 4U) {
            UINT64 a3 = 0;
            syntax_ok = parse_hex_u64(argv[3], &a3);
            if (syntax_ok) {
                /* If 3rd arg is 0x00 (or not 1/2/4/8), user wrote <var> <off> <val>; else read <size>B and prompt */
                if (a3 != 1ULL && a3 != 2ULL && a3 != 4ULL && a3 != 8ULL) {
                    sz64    = 1ULL;
                    val64   = a3;
                    has_val = TRUE;
                } else {
                    sz64    = a3;
                    has_val = FALSE;
                }
            }
        } else if (syntax_ok && argc >= 5U) {
            syntax_ok = parse_hex_u64(argv[3], &sz64) && parse_hex_u64(argv[4], &val64);
            has_val   = TRUE;
        }
    }

    if (!syntax_ok || (sz64 != 1ULL && sz64 != 2ULL && sz64 != 4ULL && sz64 != 8ULL)) {
        ui_message_modal("Command Parse Error",
            "Could not parse command arguments. Check hex offsets/sizes (1, 2, 4, or 8 bytes).\n"
            "Example: setup_var_cv CpuSetup 0x43 0x01 0x00",
            TRUE);
        return;
    }

    INTN vi = sv_find_var_index(vnam, skip_0x10, pick_1st);
    if (vi < 0) {
        CHAR8 nf[160];
        snprintf_ascii(nf, sizeof(nf),
            "NVRAM VarStore \"%s\" was not found on this machine.", vnam);
        ui_message_modal("VarStore Not Found", nf, TRUE);
        return;
    }

    sv_commit_offset_interactive(vi, (UINTN)off64, (UINTN)sz64, has_val, val64, sync_cust, cmd);
}

VOID unlock_open_setup_var_modal(VOID) {
    nvram_enumerate_all();

    INTN  cand_var_idx[SV_MAX_CANDS];
    UINT8 cand_mode[SV_MAX_CANDS]; /* 0=CLI, 1=setup_var_3, 2=setup_var2, 3=normal, 4=manual name */
    CHAR8 cand_labels[SV_MAX_CANDS][70];
    const CHAR8 *cand_ptrs[SV_MAX_CANDS];
    UINTN ccnt = 0;

    /* Option 0: Direct CLI input supporting all 5 datasone/grub-mod-setup_var commands */
    cand_var_idx[ccnt] = -2;
    cand_mode[ccnt]    = 0;
    str_cpy(cand_labels[ccnt], "[CLI] Type setup_var / setup_var2 / setup_var_3 / setup_var_cv...",
            sizeof(cand_labels[ccnt]));
    cand_ptrs[ccnt] = cand_labels[ccnt];
    ccnt++;

    INTN setup3_idx = sv_find_var_index("Setup", TRUE, FALSE);
    INTN custom_idx = sv_find_var_index("Custom", FALSE, FALSE);

    if (setup3_idx >= 0) {
        cand_var_idx[ccnt] = setup3_idx;
        cand_mode[ccnt]    = 1;
        snprintf_ascii(cand_labels[ccnt], sizeof(cand_labels[ccnt]),
            "Setup  [%uB, GUID %08X.. - setup_var_3 Skip <0x10B]",
            (UINT32)gVarList[setup3_idx].data_size,
            gVarList[setup3_idx].guid.Data1);
        cand_ptrs[ccnt] = cand_labels[ccnt];
        ccnt++;

        if (custom_idx >= 0 && ccnt + 1U < SV_MAX_CANDS) {
            cand_var_idx[ccnt] = setup3_idx;
            cand_mode[ccnt]    = 2;
            snprintf_ascii(cand_labels[ccnt], sizeof(cand_labels[ccnt]),
                "Setup + Custom [%uB+%uB - setup_var2 InsydeH2O Sync!]",
                (UINT32)gVarList[setup3_idx].data_size,
                (UINT32)gVarList[custom_idx].data_size);
            cand_ptrs[ccnt] = cand_labels[ccnt];
            ccnt++;
        }
    }

    static const CHAR8 * const kPriNames[] = {
        "Setup", "CpuSetup", "SaSetup", "PchSetup", "MeSetup", "SiSetup",
        "SystemConfig", "SetupData", "Custom", "AmdSetup", "CbsSetup", "PbsSetup"
    };
    for (UINTN p = 0; p < sizeof(kPriNames) / sizeof(kPriNames[0]) && ccnt + 1U < SV_MAX_CANDS; p++) {
        for (UINTN i = 0; i < gVarCount && ccnt + 1U < SV_MAX_CANDS; i++) {
            if ((INTN)i == setup3_idx || gVarList[i].data_size == 0) continue;
            if (str_icmp(gVarList[i].name, kPriNames[p]) == 0 ||
                str_contains_icase(gVarList[i].name, "Setup")) {
                BOOLEAN dup = FALSE;
                for (UINTN k = 0; k < ccnt; k++) {
                    if (cand_mode[k] == 3 && cand_var_idx[k] == (INTN)i) dup = TRUE;
                }
                if (dup) continue;
                cand_var_idx[ccnt] = (INTN)i;
                cand_mode[ccnt]    = 3;
                snprintf_ascii(cand_labels[ccnt], sizeof(cand_labels[ccnt]),
                    "%-16s [%u bytes, GUID %08X..]",
                    gVarList[i].name, (UINT32)gVarList[i].data_size, gVarList[i].guid.Data1);
                cand_ptrs[ccnt] = cand_labels[ccnt];
                ccnt++;
            }
        }
    }

    for (UINTN i = 0; i < gVarCount && ccnt + 1U < SV_MAX_CANDS; i++) {
        if ((INTN)i == setup3_idx || gVarList[i].data_size < 1U) continue;
        BOOLEAN dup = FALSE;
        for (UINTN k = 0; k < ccnt; k++) {
            if ((cand_mode[k] == 1 || cand_mode[k] == 3) && cand_var_idx[k] == (INTN)i) dup = TRUE;
        }
        if (dup) continue;
        cand_var_idx[ccnt] = (INTN)i;
        cand_mode[ccnt]    = 3;
        snprintf_ascii(cand_labels[ccnt], sizeof(cand_labels[ccnt]),
            "%-16s [%u bytes, GUID %08X..]",
            gVarList[i].name, (UINT32)gVarList[i].data_size, gVarList[i].guid.Data1);
        cand_ptrs[ccnt] = cand_labels[ccnt];
        ccnt++;
    }

    cand_var_idx[ccnt] = -1;
    cand_mode[ccnt]    = 4;
    str_cpy(cand_labels[ccnt], "Search / Enter Variable Name Manually (setup_var_cv)...",
            sizeof(cand_labels[ccnt]));
    cand_ptrs[ccnt] = cand_labels[ccnt];
    ccnt++;

    INTN default_sel = (setup3_idx >= 0) ? 1 : 0;
    INTN sel = ui_select_modal("grub-mod-setup_var: CLI / Target VarStore", cand_ptrs, ccnt, (UINTN)default_sel);
    if (sel < 0) return;

    if (cand_mode[sel] == 0) {
        run_setup_var_cli_modal();
        return;
    }

    BOOLEAN sync_cust = (cand_mode[sel] == 2);
    const CHAR8 *mtag = (cand_mode[sel] == 2) ? "setup_var2" :
                        (cand_mode[sel] == 1) ? "setup_var_3" : "setup_var_cv";

    INTN chosen_vi = cand_var_idx[sel];
    if (chosen_vi < 0) {
        CHAR8 vname_in[48];
        if (!ui_input_modal("setup_var_cv Variable Name",
                            "Enter NVRAM Variable Name (e.g. Setup, CpuSetup, AmdSetup, CbsSetup):",
                            "Setup", vname_in, sizeof(vname_in), FALSE) || !vname_in[0]) {
            return;
        }
        chosen_vi = sv_find_var_index(vname_in, FALSE, FALSE);
        if (chosen_vi < 0) {
            CHAR8 emsg[160];
            snprintf_ascii(emsg, sizeof(emsg),
                "NVRAM variable \"%s\" was not found in GetNextVariableName() enumeration.", vname_in);
            ui_message_modal("Variable Not Found", emsg, TRUE);
            return;
        }
    }

    const NVRAM_VAR_ENTRY *ve = &gVarList[chosen_vi];
    UINTN vsz = ve->data_size;
    if (vsz == 0) return;

    CHAR8 off_prompt[96], off_str[24];
    snprintf_ascii(off_prompt, sizeof(off_prompt),
        "Store: %s (%u bytes, 0x0 .. 0x%X) - Enter Hex Offset (e.g. 0x43):",
        ve->name, (UINT32)vsz, (UINT32)(vsz - 1U));
    if (!ui_input_modal("setup_var: Enter Hex VarOffset", off_prompt, "0x0", off_str, sizeof(off_str), TRUE)) {
        return;
    }

    UINT64 off64 = 0;
    if (!parse_hex_u64(off_str, &off64) || off64 >= (UINT64)vsz) {
        CHAR8 oob[128];
        snprintf_ascii(oob, sizeof(oob),
            "Hex offset '%s' exceeds variable '%s' size (%u bytes / max 0x%X)!",
            off_str, ve->name, (UINT32)vsz, (UINT32)(vsz - 1U));
        ui_message_modal("Offset Out of Range", oob, TRUE);
        return;
    }
    UINTN off = (UINTN)off64;

    const CHAR8 *w_opts[4] = {
        "1 Byte  (UINT8  - Standard setup_var / setup_var_3)",
        "2 Bytes (UINT16 - setup_var_vs 0x02)",
        "4 Bytes (UINT32 - setup_var_vs 0x04)",
        "8 Bytes (UINT64 - setup_var_vs 0x08)"
    };
    UINTN max_w_choices = (off + 8U <= vsz) ? 4U :
                          ((off + 4U <= vsz) ? 3U : ((off + 2U <= vsz) ? 2U : 1U));
    INTN w_pick = (max_w_choices > 1U)
                  ? ui_pick_option_modal("Select Byte Width (setup_var_vs)", w_opts, max_w_choices, 0, 0) : 0;
    if (w_pick < 0) return;
    UINTN width = (w_pick == 0) ? 1U : ((w_pick == 1) ? 2U : ((w_pick == 2) ? 4U : 8U));

    sv_commit_offset_interactive(chosen_vi, off, width, FALSE, 0, sync_cust, mtag);
}

/* =========================================================================
 * 6B. Dortania OpenCore MSR 0xE2 (CFG Lock) All-Core Verifier & Unlocker
 *     Implements OpenCore VerifyMsrE2 + ControlMsrE2 + IFR setup_var_cv!
 * ========================================================================= */
typedef struct {
    UINT32 total_probed;
    UINT32 readable_cnt;
    UINT32 locked_cnt;
    UINT32 unlocked_cnt;
    UINT64 first_val;
    BOOLEAN mismatch_vals;
} MSR_E2_AUDIT_CTX;

static VOID EFIAPI ap_audit_msr_e2_proc(VOID *buffer) {
    MSR_E2_AUDIT_CTX *ctx = (MSR_E2_AUDIT_CTX *)buffer;
    if (!ctx) return;
    ctx->total_probed++;
    UINT64 v = 0;
    if (cpu_safe_rdmsr(0xE2U, &v)) {
        ctx->readable_cnt++;
        if ((v & (1ULL << 15)) != 0) ctx->locked_cnt++;
        else                         ctx->unlocked_cnt++;
        if (v != ctx->first_val) ctx->mismatch_vals = TRUE;
    }
}

VOID unlock_verify_msr_e2_all_cores_modal(VOID) {
    if (gHw.cpu_msr.is_amd) {
        ui_message_modal("MSR 0xE2 Not Applicable on AMD",
            "MSR 0xE2 (PKG_CST_CONFIG_CONTROL / CFG Lock) is an Intel-only register.\n"
            "AMD Ryzen systems do not have CFG Lock!", FALSE);
        return;
    }

    MSR_E2_AUDIT_CTX audit;
    memset(&audit, 0, sizeof(audit));
    audit.total_probed = 1U;

    UINT64 bsp_e2 = 0;
    if (cpu_safe_rdmsr(0xE2U, &bsp_e2)) {
        audit.readable_cnt = 1U;
        audit.first_val    = bsp_e2;
        if ((bsp_e2 & (1ULL << 15)) != 0) audit.locked_cnt = 1U;
        else                              audit.unlocked_cnt = 1U;
    }

    UINTN mp_total = 1U, mp_en = 1U;
    EFI_MP_SERVICES_PROTOCOL *mp = NULL;
    if (!EFI_ERROR(efi_locate_protocol(&gEfiMpServicesProtocolGuid, (VOID **)&mp)) && mp) {
        if (mp->GetNumberOfProcessors) {
            mp->GetNumberOfProcessors(mp, &mp_total, &mp_en);
        }
        if (audit.readable_cnt > 0 && mp->StartupAllAPs && mp_en > 1U) {
            mp->StartupAllAPs(mp, ap_audit_msr_e2_proc, TRUE, NULL, 400000, &audit, NULL);
        }
    }

    /* Search decoded HII / FV2 IFR for CFG Lock questions */
    INTN cfg_qs[8];
    UINTN cfg_q_cnt = 0;
    if (gHw.hii_questions) {
        for (UINTN i = 0; i < gHw.hii_question_count && cfg_q_cnt < 8U; i++) {
            const CHAR8 *p = gHw.hii_questions[i].prompt;
            if (str_contains_icase(p, "CFG Lock") || str_contains_icase(p, "MSR 0xE2")) {
                cfg_qs[cfg_q_cnt++] = (INTN)i;
            }
        }
    }

    CHAR8 report[560];
    UINTN pos = 0;
    if (audit.readable_cnt == 0) {
        pos += (UINTN)snprintf_ascii(report + pos, sizeof(report) - pos,
            "VerifyMsrE2 : MSR 0xE2 unreadable (%s)\n"
            "CPU Threads : %u enabled / %u total\n",
            gHw.feat_hypervisor ? "Hypervisor/VM masks MSR 0xE2" : "#GP on RDMSR 0xE2",
            (UINT32)mp_en, (UINT32)mp_total);
    } else {
        const CHAR8 *verdict =
            (audit.locked_cnt == 0) ? "CFG-Lock = UNLOCKED (0x00) across ALL cores!" :
            (audit.unlocked_cnt == 0) ? "CFG-Lock = LOCKED (Bit 15=1) across ALL cores" :
            "INCONSISTENT CORES! (Some locked, some unlocked!)";
        pos += (UINTN)snprintf_ascii(report + pos, sizeof(report) - pos,
            "VerifyMsrE2 : %s\n"
            "BSP 0xE2    : 0x%016lX  [Bit 15 = %u]\n"
            "All Threads : %u/%u readable | Locked=%u | Unlocked=%u\n",
            verdict, bsp_e2, (UINT32)((bsp_e2 >> 15) & 1ULL),
            audit.readable_cnt, (UINT32)mp_en, audit.locked_cnt, audit.unlocked_cnt);
    }

    if (cfg_q_cnt > 0) {
        pos += (UINTN)snprintf_ascii(report + pos, sizeof(report) - pos,
            "\nDortania IFR Match (%u found):\n", (UINT32)cfg_q_cnt);
        for (UINTN i = 0; i < cfg_q_cnt && pos + 96U < sizeof(report); i++) {
            const HW_HII_QUESTION *q = &gHw.hii_questions[cfg_qs[i]];
            const CHAR8 *vsn = (q->varstore_idx >= 0 && (UINTN)q->varstore_idx < gHw.hii_varstore_count)
                               ? gHw.hii_varstores[q->varstore_idx].name : "Setup";
            UINT64 cv = 0;
            BOOLEAN in_nv = FALSE;
            hw_hii_read_question_val((UINTN)cfg_qs[i], &cv, &in_nv);
            if (q->is_bitfield) {
                pos += (UINTN)snprintf_ascii(report + pos, sizeof(report) - pos,
                    "  %s [BitOff 0x%X, %ub] Cur=%s\n",
                    vsn, (UINT32)q->var_offset, (UINT32)q->width,
                    in_nv ? (cv ? "1 (Locked)" : "0 (Unlocked)") : "NoNVRAM");
            } else {
                pos += (UINTN)snprintf_ascii(report + pos, sizeof(report) - pos,
                    "  setup_var_cv %s 0x%04X 0x%02X 0x00  [Cur=%s]\n",
                    vsn, (UINT32)q->var_offset, (UINT32)q->width,
                    in_nv ? (cv ? "0x01 Locked" : "0x00 Unlocked") : "NoNVRAM");
            }
        }
    } else {
        pos += (UINTN)snprintf_ascii(report + pos, sizeof(report) - pos,
            "\nIFR Scan    : No question named 'CFG Lock' in exported HII (%u questions).\n"
            "Tip: Use 'grub-mod-setup_var CLI' if you extracted your BIOS offset via UEFITool/ifrextract!",
            (UINT32)gHw.hii_question_count);
    }

    const CHAR8 *acts[4];
    UINTN acnt = 0;
    INTN act_unlock_all = -1, act_sv = -1, act_boot = -1;

    if (cfg_q_cnt > 0 || audit.locked_cnt > 0) {
        act_unlock_all = (INTN)acnt;
        acts[acnt++] = "Unlock CFG Lock Now (NVRAM 0x00 + Live All-Core MSR 0xE2)";
    }
    act_sv = (INTN)acnt;
    acts[acnt++] = "Open grub-mod-setup_var CLI / Hex Offset Patcher...";
    act_boot = (INTN)acnt;
    acts[acnt++] = ">> Boot OS Directly (Keep Live MSR State Active) <<";
    acts[acnt++] = "Close Report";

    ui_message_modal("Dortania MSR 0xE2 (VerifyMsrE2 & ControlMsrE2)", report, audit.locked_cnt > 0);
    INTN pick = ui_select_modal("MSR 0xE2 (CFG Lock) Actions", acts, acnt, 0);
    if (pick < 0) return;

    if (pick == act_unlock_all) {
        BOOLEAN live_ok = hw_intel_unlock_cfg_lock_msr();
        UINTN nv_ok = 0;
        CHAR8 err[160];
        err[0] = '\0';
        for (UINTN i = 0; i < cfg_q_cnt; i++) {
            if (hw_hii_write_question_val((UINTN)cfg_qs[i], 0ULL, err, sizeof(err))) nv_ok++;
        }
        hw_refresh_cpu_msrs();
        CHAR8 done[280];
        snprintf_ascii(done, sizeof(done),
            "NVRAM CFG Lock Updated : %u/%u IFR store(s)\n"
            "Live All-Core MSR 0xE2 : %s\n"
            "%s",
            (UINT32)nv_ok, (UINT32)cfg_q_cnt,
            live_ok ? "UNLOCKED across all cores for this boot!" :
                      (audit.readable_cnt == 0 ? "MSR Masked in VM" : "Write-locked until Cold Reboot!"),
            (nv_ok > 0) ? "Reboot from Exit tab to make microcode boot with MSR 0xE2 unlocked permanently!"
                        : (err[0] ? err : ""));
        ui_message_modal("ControlMsrE2 Result", done, (nv_ok == 0 && !live_ok));
    } else if (pick == act_sv) {
        unlock_open_setup_var_modal();
    } else if (pick == act_boot) {
        nvram_boot_os_preserve_live_modal("Boot / Chainload OS (Preserve Unlocked MSR 0xE2)");
    }
}

/* =========================================================================
 * 6C. Persistent Startup Hardware Auto-Apply Profile (OhMyEfiAutoPatch)
 *     Automatically re-applies live MSR / FIVR / AMD P0 tweaks every boot!
 * ========================================================================= */
#define OHMYEFI_AUTOPATCH_MAGIC 0x3150414FU /* 'OAP1' */

typedef struct {
    UINT32 magic;
    UINT8  apply_cfg_unlock;
    UINT8  apply_intel_turbo; /* 0=ignore, 1=enable, 2=disable */
    UINT8  apply_fivr;
    UINT8  fivr_plane_mask;
    INT16  fivr_mv[UNLOCK_FIVR_PLANE_COUNT];
    UINT8  apply_amd_p0_vid;
    UINT8  amd_p0_vid;
    UINT8  apply_amd_cpb;     /* 0=ignore, 1=enable, 2=disable */
    UINT8  reserved[5];
} PACKED OHMYEFI_AUTOPATCH_CFG;

BOOLEAN unlock_has_startup_autopatch(VOID) {
    UINT32 a = 0;
    UINTN sz = 0;
    UINT8 *buf = NULL;
    BOOLEAN ok = FALSE;
    if (!EFI_ERROR(nvram_read_var(L"OhMyEfiAutoPatch", &gOhMyEfiAutoPatchGuid, &a, &sz, &buf)) &&
        buf && sz == sizeof(OHMYEFI_AUTOPATCH_CFG)) {
        const OHMYEFI_AUTOPATCH_CFG *cfg = (const OHMYEFI_AUTOPATCH_CFG *)buf;
        if (cfg->magic == OHMYEFI_AUTOPATCH_MAGIC) ok = TRUE;
    }
    if (buf) free_pool(buf);
    return ok;
}

BOOLEAN unlock_apply_startup_autopatch(CHAR8 *status_out, UINTN max_status) {
    if (status_out && max_status > 0) status_out[0] = '\0';
    UINT32 a = 0;
    UINTN sz = 0;
    UINT8 *buf = NULL;
    if (EFI_ERROR(nvram_read_var(L"OhMyEfiAutoPatch", &gOhMyEfiAutoPatchGuid, &a, &sz, &buf)) ||
        !buf || sz != sizeof(OHMYEFI_AUTOPATCH_CFG)) {
        if (buf) free_pool(buf);
        return FALSE;
    }

    OHMYEFI_AUTOPATCH_CFG cfg;
    memcpy(&cfg, buf, sizeof(cfg));
    free_pool(buf);
    if (cfg.magic != OHMYEFI_AUTOPATCH_MAGIC) return FALSE;

    UINTN applied = 0;
    if (cfg.apply_cfg_unlock && gHw.cpu_msr.cst_cfg_valid && gHw.cpu_msr.cfg_locked) {
        if (hw_intel_unlock_cfg_lock_msr()) applied++;
    }
    if ((cfg.apply_intel_turbo == 1U || cfg.apply_intel_turbo == 2U) && gHw.cpu_msr.misc_valid) {
        if (hw_write_cpu_msr_bit(0x1A0U, 38, cfg.apply_intel_turbo == 2U)) applied++;
    }
    if (cfg.apply_fivr) {
        refresh_fivr_offsets();
        for (UINT8 p = 0; p < UNLOCK_FIVR_PLANE_COUNT; p++) {
            if ((cfg.fivr_plane_mask & (1U << p)) != 0) {
                if (unlock_fivr_set_plane_mv(p, (INT32)cfg.fivr_mv[p], NULL, 0)) applied++;
            }
        }
    }
    if (cfg.apply_amd_p0_vid && gHw.cpu_msr.is_amd && gHw.cpu_msr.amd_pstate_valid) {
        if (hw_amd_set_p0_vid(cfg.amd_p0_vid)) applied++;
    }
    if ((cfg.apply_amd_cpb == 1U || cfg.apply_amd_cpb == 2U) && gHw.cpu_msr.is_amd && gHw.cpu_msr.amd_hwcr_valid) {
        if (hw_write_cpu_msr_bit(0xC0010015U, 25, cfg.apply_amd_cpb == 2U)) applied++;
    }

    if (applied > 0) {
        gVolatileHwTweakActive = TRUE;
        hw_refresh_cpu_msrs();
        if (status_out && max_status > 0) {
            snprintf_ascii(status_out, max_status,
                "Startup Auto-Patch Applied (%u live tweak%s)! Chainload OS directly to keep active.",
                (UINT32)applied, (applied > 1U) ? "s" : "");
        }
        return TRUE;
    }
    return FALSE;
}

VOID unlock_manage_autopatch_modal(VOID) {
    unlock_refresh_all(FALSE);
    hw_refresh_cpu_msrs();

    BOOLEAN has_cur = unlock_has_startup_autopatch();
    const CHAR8 *opts[3] = {
        "Save Current Live CPU / FIVR / MSR Tweaks to Startup Auto-Patch (NVRAM)",
        "Delete / Clear Saved Startup Auto-Patch Profile",
        "Cancel"
    };
    INTN pick = ui_select_modal(
        has_cur ? "Startup Auto-Patch Profile [ACTIVE in NVRAM]"
                : "Startup Auto-Patch Profile [Not Set]",
        opts, 3, 0);
    if (pick < 0 || pick == 2) return;

    if (pick == 1) {
        EFI_STATUS st = nvram_delete_var(L"OhMyEfiAutoPatch", &gOhMyEfiAutoPatchGuid);
        ui_message_modal("Auto-Patch Cleared",
            EFI_ERROR(st) ? "No Startup Auto-Patch profile was stored in NVRAM."
                          : "Removed OhMyEfiAutoPatch from NVRAM.",
            FALSE);
        return;
    }

    OHMYEFI_AUTOPATCH_CFG cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.magic = OHMYEFI_AUTOPATCH_MAGIC;

    if (!gHw.cpu_msr.is_amd) {
        cfg.apply_cfg_unlock = 1U;
        if (gHw.cpu_msr.misc_valid && gHw.cpu_msr.turbo_hw_avail) {
            cfg.apply_intel_turbo = gHw.cpu_msr.turbo_disabled ? 2U : 1U;
        }
        if (gUnlockFivr.supported) {
            cfg.apply_fivr = 1U;
            for (UINT8 p = 0; p < UNLOCK_FIVR_PLANE_COUNT; p++) {
                if (gUnlockFivr.plane_valid[p]) {
                    cfg.fivr_plane_mask |= (UINT8)(1U << p);
                    cfg.fivr_mv[p]       = (INT16)gUnlockFivr.plane_mv[p];
                }
            }
        }
    } else {
        if (gHw.cpu_msr.amd_pstate_valid && gHw.cpu_msr.amd_p0_vid > 0) {
            cfg.apply_amd_p0_vid = 1U;
            cfg.amd_p0_vid       = gHw.cpu_msr.amd_p0_vid;
        }
        if (gHw.cpu_msr.amd_hwcr_valid) {
            cfg.apply_amd_cpb = gHw.cpu_msr.amd_cpb_disabled ? 2U : 1U;
        }
    }

    UINT32 attr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
    EFI_STATUS st = nvram_write_var(L"OhMyEfiAutoPatch", &gOhMyEfiAutoPatchGuid, attr, sizeof(cfg), &cfg);
    if (EFI_ERROR(st)) {
        ui_message_modal("Save Failed", "Firmware NVRAM rejected saving OhMyEfiAutoPatch.", TRUE);
        return;
    }

    ui_message_modal("Startup Auto-Patch Saved!",
        "Saved current live CPU / MSR / FIVR / AMD P0 profile to NVRAM (OhMyEfiAutoPatch)!\n"
        "Every time Oh my EFI! boots, these live register tweaks will auto-apply.\n"
        "Remember: use 'Boot OS Directly (No Reset)' to chainload your OS without wiping MSRs!",
        FALSE);
}

static VOID handle_amd_smn_inspector_modal(VOID) {
    if (!gUnlockMePsp.amd_smn_ok) {
        ui_message_modal("AMD SMN Unavailable",
            "PCI 00:00.0 is not an AMD Root Complex (0x1022) with indirect SMN 0xB8/0xBC access.", TRUE);
        return;
    }
    CHAR8 addr_s[24];
    if (!ui_input_modal("AMD Ryzen SMN (00:00.0 0xB8/0xBC) Inspector",
                        "Enter 32-bit SMN Address (e.g. 0x00059800 THM_TCON, 0x03B10570 SMU):",
                        "0x00059800", addr_s, sizeof(addr_s), TRUE)) {
        return;
    }
    UINT64 a64 = 0;
    if (!parse_hex_u64(addr_s, &a64) || a64 > 0xFFFFFFFFULL) return;
    UINT32 base = (UINT32)(a64 & ~3ULL);

    UINT32 d[4] = { 0, 0, 0, 0 };
    for (UINTN i = 0; i < 4U; i++) {
        amd_smn_read32(base + (UINT32)(i * 4U), &d[i]);
    }
    CHAR8 msg[280];
    snprintf_ascii(msg, sizeof(msg),
        "AMD Root Complex [1022:%04X] SMN Aperture Read:\n"
        "  SMN[0x%08X] = 0x%08X\n"
        "  SMN[0x%08X] = 0x%08X\n"
        "  SMN[0x%08X] = 0x%08X\n"
        "  SMN[0x%08X] = 0x%08X",
        (UINT32)gUnlockMePsp.amd_root_did,
        base + 0x00U, d[0], base + 0x04U, d[1],
        base + 0x08U, d[2], base + 0x0CU, d[3]);
    ui_message_modal("AMD SMN 16-Byte Window", msg, FALSE);
}

/* =========================================================================
 * 7. Interactive Submenu: Unlock Hub (Undervolt, ME/PSP, SPI & setup_var_3)
 * ========================================================================= */
static UINTN unlock_left_width(VOID) {
    UINTN split_x = (gUiCols * 2U) / 3U;
    if (split_x < 50U && gUiCols >= 80U) split_x = 52U;
    if (gUiCols - split_x < 27U && gUiCols >= 80U) split_x = gUiCols - 28U;
    return split_x - 3U;
}

static VOID u_draw_kv(UINTN lx, UINTN y, UINTN lw, const CHAR8 *label, const CHAR8 *val) {
    if (y >= gUiRows - 2U) return;
    ui_puts_n(lx, y, label, 22U, gTheme.label_attr);
    if (lw > 23U) ui_puts_n(lx + 23U, y, val, lw - 23U, gTheme.value_attr);
}

static VOID u_draw_opt(
    UINTN lx, UINTN y, UINTN lw,
    BOOLEAN sel, BOOLEAN dim,
    const CHAR8 *label, const CHAR8 *val
) {
    if (y >= gUiRows - 2U) return;
    UINT8 a = dim ? (sel ? gTheme.dim_sel_attr : gTheme.dim_attr)
                  : (sel ? gTheme.item_sel_attr : gTheme.item_attr);
    if (sel) ui_hline(lx, y, lw, L' ', a);
    ui_puts_n(lx, y, label, 22U, a);
    if (lw > 23U) {
        CHAR8 tmp[64];
        snprintf_ascii(tmp, sizeof(tmp), "[%s]", val);
        ui_puts_n(lx + 23U, y, tmp, lw - 23U, a);
    }
}

static VOID format_hii_val_short(UINTN q_idx, CHAR8 *out, UINTN max_len) {
    const HW_HII_QUESTION *q = &gHw.hii_questions[q_idx];
    UINT64 val = 0;
    BOOLEAN in_nv = FALSE;
    if (!hw_hii_read_question_val(q_idx, &val, &in_nv) || !in_nv) {
        snprintf_ascii(out, max_len, "Off:0x%04X", (UINT32)q->var_offset);
        return;
    }
    for (UINT8 i = 0; i < q->opt_count; i++) {
        if (q->opts[i].value == val) {
            str_cpy(out, q->opts[i].label, max_len);
            return;
        }
    }
    snprintf_ascii(out, max_len, "0x%lX", val);
}

static VOID handle_spi_bioswe_interactive(VOID) {
    probe_spi_flash_locks();
    if (!gUnlockSpi.present || !gUnlockSpi.bios_cntl_valid) {
        ui_message_modal("BIOS_CNTL Not Exposed",
            "Platform does not expose a standard x86 LPC/SPI BIOS_CNTL (0xDC) register.", TRUE);
        return;
    }

    CHAR8 info[320];
    snprintf_ascii(info, sizeof(info),
        "%s [%04X:%04X] Offset 0xDC = 0x%02X\n"
        "  BIOSWE (Bit 0 Write Enable) : %u\n"
        "  BLE    (Bit 1 SMM Lock En)  : %u\n"
        "  EISS   (Bit 5 InSMM.STS)    : %u\n"
        "  FLOCKDN: %s  |  FPRR Protected Ranges: %u\n\n"
        "%s",
        gUnlockSpi.controller_name, (UINT32)gUnlockSpi.vid, (UINT32)gUnlockSpi.did,
        (UINT32)gUnlockSpi.bios_cntl,
        (UINT32)gUnlockSpi.bioswe, (UINT32)gUnlockSpi.ble, (UINT32)gUnlockSpi.eiss,
        gUnlockSpi.spibar_valid ? (gUnlockSpi.flockdn ? "1 (Locked)" : "0 (Unlocked!)") : "N/A",
        (UINT32)gUnlockSpi.fpr_wpe_count,
        gUnlockSpi.ble
            ? "WARNING: BLE=1 triggers an SMI trap when setting BIOSWE=1. Attempt live write anyway?"
            : "BLE=0! Toggle live BIOSWE (Bit 0) & clear EISS (Bit 5) now?");

    if (!ui_confirm_modal("SPI BIOS_CNTL Flash Write Control", info, !gUnlockSpi.ble)) return;

    UINT8 target_bc = gUnlockSpi.bioswe
                      ? (UINT8)(gUnlockSpi.bios_cntl & ~0x01U)
                      : (UINT8)((gUnlockSpi.bios_cntl & ~0x20U) | 0x01U);
    hw_pci_cfg_write8_raw(gUnlockSpi.bus, gUnlockSpi.dev, gUnlockSpi.func, 0xDCU, target_bc);
    probe_spi_flash_locks();
    if (gUnlockSpi.bioswe) gVolatileHwTweakActive = TRUE;

    CHAR8 res[220];
    snprintf_ascii(res, sizeof(res),
        "Read-back BIOS_CNTL (0xDC) = 0x%02X  (BIOSWE=%u, BLE=%u, EISS=%u).\n%s",
        (UINT32)gUnlockSpi.bios_cntl,
        (UINT32)gUnlockSpi.bioswe, (UINT32)gUnlockSpi.ble, (UINT32)gUnlockSpi.eiss,
        gUnlockSpi.bioswe
            ? "Host BIOS Flash Region Write Enable (BIOSWE=1) is now ACTIVE!"
            : "BIOSWE is 0 (cleared or SMM handler suppressed write because BLE/EISS is set).");
    ui_message_modal("BIOS_CNTL Update Result", res, !gUnlockSpi.bioswe && (target_bc & 1U));
}

static VOID handle_bios_flash_nvram_unlock(VOID) {
    INTN q_bl   = hw_hii_find_question_icase("BIOS Lock", NULL);
    INTN q_fprr = hw_hii_find_question_icase("Flash Protection", NULL);
    if (q_fprr < 0) q_fprr = hw_hii_find_question_icase("FPRR", NULL);
    INTN q_bg   = hw_hii_find_question_icase("BIOS Guard", NULL);
    INTN q_spil = hw_hii_find_question_icase("SPI Lock", NULL);

    INTN found[4];
    CHAR8 lbufs[4][64];
    const CHAR8 *lptrs[4];
    UINTN cnt = 0;
    INTN cands[4] = { q_bl, q_fprr, q_bg, q_spil };
    for (UINTN i = 0; i < 4U; i++) {
        if (cands[i] < 0) continue;
        BOOLEAN dup = FALSE;
        for (UINTN k = 0; k < cnt; k++) if (found[k] == cands[i]) dup = TRUE;
        if (dup) continue;
        found[cnt] = cands[i];
        CHAR8 vs[28];
        format_hii_val_short((UINTN)cands[i], vs, sizeof(vs));
        snprintf_ascii(lbufs[cnt], sizeof(lbufs[cnt]), "%s [%s]",
                       gHw.hii_questions[cands[i]].prompt, vs);
        lptrs[cnt] = lbufs[cnt];
        cnt++;
    }

    if (cnt == 0) {
        CHAR8 msg[256];
        if (gUnlockSpi.spibar_valid) {
            snprintf_ascii(msg, sizeof(msg),
                "No HII 'BIOS Lock' / 'FPRR' question found in exported IFR.\n"
                "SPIBAR @ 0x%lX: HSFSTS=0x%04X (FLOCKDN=%u, FDV=%u, FDOPSS=%u), FRAP=0x%08X (BRRA=0x%02X, BRWA=0x%02X).\n"
                "Open SPIBAR MMIO in Hex Inspector?",
                gUnlockSpi.spibar_phys, (UINT32)gUnlockSpi.hsfsts,
                (UINT32)gUnlockSpi.flockdn, (UINT32)gUnlockSpi.fdv, (UINT32)gUnlockSpi.fdopss,
                gUnlockSpi.frap, (UINT32)gUnlockSpi.brra, (UINT32)gUnlockSpi.brwa);
            if (ui_confirm_modal("SPI Flash Registers", msg, FALSE)) {
                debug_open_hex_editor(gUnlockSpi.spibar_phys, "SPIBAR MMIO");
            }
        } else {
            ui_message_modal("No HII BIOS Lock Found",
                "Firmware does not expose 'BIOS Lock' or 'FPRR' in HII. Use 'setup_var_3 Offset Editor' if you have a known offset.",
                FALSE);
        }
        return;
    }

    if (cnt == 1U) {
        edit_hii_q_modal((UINTN)found[0]);
        return;
    }
    INTN pick = ui_select_modal("Select BIOS / SPI Flash Lock Setting", lptrs, cnt, 0);
    if (pick >= 0 && (UINTN)pick < cnt) {
        edit_hii_q_modal((UINTN)found[pick]);
    }
}

static VOID handle_intel_me_control_menu(BOOLEAN fw_reflash_focus) {
    /* Gather ME-related HII questions */
    INTN me_qs[12];
    CHAR8 mbufs[15][68];
    const CHAR8 *mptrs[15];
    UINTN mcnt = 0;

    if (gHw.hii_questions) {
        for (UINTN i = 0; i < gHw.hii_question_count && mcnt < 10U; i++) {
            const CHAR8 *p = gHw.hii_questions[i].prompt;
            BOOLEAN match = fw_reflash_focus
                ? (str_contains_icase(p, "ME FW") || str_contains_icase(p, "MeFw") ||
                   str_contains_icase(p, "End of Post") || str_contains_icase(p, "AMT") ||
                   str_contains_icase(p, "Manageability"))
                : (str_contains_icase(p, "ME State") || str_contains_icase(p, "HAP") ||
                   str_contains_icase(p, "High Assurance") || str_contains_icase(p, "AltMeDisable") ||
                   str_contains_icase(p, "CSME") || str_contains_icase(p, "Intel(R) ME"));
            if (match) {
                me_qs[mcnt] = (INTN)i;
                CHAR8 vs[24];
                format_hii_val_short(i, vs, sizeof(vs));
                snprintf_ascii(mbufs[mcnt], sizeof(mbufs[mcnt]), "HII: %s [%s]", p, vs);
                mptrs[mcnt] = mbufs[mcnt];
                mcnt++;
            }
        }
    }

    INTN act_toggle_heci = -1, act_pci_hex = -1, act_mmio_hex = -1;
    if (gUnlockMePsp.me_present) {
        act_toggle_heci = (INTN)mcnt;
        snprintf_ascii(mbufs[mcnt], sizeof(mbufs[mcnt]),
            "Live HECI1 PCI 00:%02X.%X Host Decode [%s]",
            (UINT32)gUnlockMePsp.me_dev, (UINT32)gUnlockMePsp.me_func,
            (gUnlockMePsp.me_cmd & 0x06U) ? "Enabled (Mem+BusMaster)" : "Disabled (Host Isolated)");
        mptrs[mcnt] = mbufs[mcnt];
        mcnt++;

        if (gUnlockMePsp.me_pci_idx >= 0) {
            act_pci_hex = (INTN)mcnt;
            str_cpy(mbufs[mcnt], "Open Intel ME HECI1 (00:16.0) 256B PCI Config Hex Editor...", sizeof(mbufs[mcnt]));
            mptrs[mcnt] = mbufs[mcnt];
            mcnt++;
        }
        if (gUnlockMePsp.heci_mmio_ok) {
            act_mmio_hex = (INTN)mcnt;
            snprintf_ascii(mbufs[mcnt], sizeof(mbufs[mcnt]),
                "Inspect HECI1 BAR0 MMIO Registers @ 0x%lX...", gUnlockMePsp.heci_bar0);
            mptrs[mcnt] = mbufs[mcnt];
            mcnt++;
        }
    }

    if (mcnt == 0) {
        ui_message_modal("Intel ME / CSME Not Detected",
            "PCI 00:16.0 (Intel ME HECI1) is not present on this platform and no ME HII options were exported.",
            FALSE);
        return;
    }

    INTN c = ui_select_modal(fw_reflash_focus ? "Intel ME Re-Flash, EOP & AMT Control"
                                              : "Intel ME State / HAP & HECI1 Control",
                             mptrs, mcnt, 0);
    if (c < 0) return;

    if (c == act_toggle_heci) {
        const CHAR8 *hopts[2] = {
            "Isolate Host HECI1 Interface (Clear MSE + BusMaster on 00:16.0)",
            "Enable Host HECI1 Interface (Set MSE + BusMaster on 00:16.0)"
        };
        UINT8 cur_en = (gUnlockMePsp.me_cmd & 0x02U) ? 1U : 0U;
        INTN p = ui_pick_option_modal("Intel ME HECI1 PCI Command (00:16.0)", hopts, 2, cur_en, cur_en);
        if (p >= 0) {
            UINT16 ncmd = (p == 1) ? (UINT16)(gUnlockMePsp.me_cmd | 0x0006U)
                                   : (UINT16)(gUnlockMePsp.me_cmd & ~0x0006U);
            hw_pci_cfg_write16_raw(gUnlockMePsp.me_bus, gUnlockMePsp.me_dev, gUnlockMePsp.me_func, 0x04U, ncmd);
            probe_intel_me_and_amd_psp(FALSE);
        }
    } else if (c == act_pci_hex && gUnlockMePsp.me_pci_idx >= 0) {
        debug_open_pci_config_editor((UINTN)gUnlockMePsp.me_pci_idx);
        probe_intel_me_and_amd_psp(FALSE);
    } else if (c == act_mmio_hex && gUnlockMePsp.heci_mmio_ok) {
        debug_open_hex_editor(gUnlockMePsp.heci_bar0, "HECI1 MMIO");
    } else if ((UINTN)c < mcnt && me_qs[c] >= 0) {
        edit_hii_q_modal((UINTN)me_qs[c]);
    }
}

VOID unlock_draw_submenu(UINTN tab_idx, const CHAR8 *footer_status, UINTN *io_cur, UINTN *io_scroll) {
    unlock_refresh_all(FALSE);
    UINTN hq_cnt = collect_unlock_hii_questions(s_unlock_q_idx, 256U);
    BOOLEAN has_autopatch = unlock_has_startup_autopatch();

    UINTN lx = 2U;
    UINTN lw = unlock_left_width();
    UINTN y  = 3U;
    CHAR8 b[96];

    if (gHw.cpu_msr.is_amd) {
        const CHAR8 *help_amd =
            "AMD Ryzen / X570 / AM4 / AM5 Platform Unlock Hub:\n"
            "- Patch CBS/PBS/AmdSetup/Setup offsets (including EDK2 Bit-VarStores!) with RouteConfig & read-back verify.\n"
            "- Live AMD SMN (00:00.0 0xB8/0xBC), MP1 SMU FW, Tctl Temp, IOMMU (00:00.2), PSP/fTPM, SVI2 VID & Startup Auto-Patch!";
        ui_draw_setup_frame(tab_idx, "Unlock Hub: AMD SMN, SMU, PSP & setup_var", TRUE,
                            "AMD Unlock & SMN Hub", help_amd, footer_status);

        if (gUnlockMePsp.amd_smn_ok) {
            CHAR8 smu_s[32], t_s[24], iommu_s[24];
            if (gUnlockMePsp.smu_ver_valid) {
                snprintf_ascii(smu_s, sizeof(smu_s), "SMU:%u.%u.%u ",
                               (UINT32)gUnlockMePsp.smu_major, (UINT32)gUnlockMePsp.smu_minor,
                               (UINT32)gUnlockMePsp.smu_patch);
            } else {
                str_cpy(smu_s, "SMN:Ready ", sizeof(smu_s));
            }
            if (gUnlockMePsp.amd_tctl_valid) {
                snprintf_ascii(t_s, sizeof(t_s), "Tctl:%dC ", gUnlockMePsp.amd_tctl_c);
            } else {
                t_s[0] = '\0';
            }
            if (gUnlockMePsp.amd_iommu_present) {
                snprintf_ascii(iommu_s, sizeof(iommu_s), "IOMMU:%04X", (UINT32)gUnlockMePsp.amd_iommu_did);
            } else {
                str_cpy(iommu_s, "IOMMU:Off", sizeof(iommu_s));
            }
            snprintf_ascii(b, sizeof(b), "[1022:%04X] %s%s%s",
                           (UINT32)gUnlockMePsp.amd_root_did, smu_s, t_s, iommu_s);
        } else if (gUnlockMePsp.amd_psp_present) {
            snprintf_ascii(b, sizeof(b), "%02X:%02X.%X [%04X:%04X] BAR:0x%lX",
                           (UINT32)gUnlockMePsp.psp_bus, (UINT32)gUnlockMePsp.psp_dev,
                           (UINT32)gUnlockMePsp.psp_func, (UINT32)gUnlockMePsp.psp_vid,
                           (UINT32)gUnlockMePsp.psp_did, gUnlockMePsp.psp_bar);
        } else {
            str_cpy(b, "Virtual / Non-AMD Northbridge", sizeof(b));
        }
        u_draw_kv(lx, y++, lw, "AMD SMN / SMU / IOMMU", b);

        snprintf_ascii(b, sizeof(b), "SMMLock:%s | SVMLock:%s | CPB:%s",
                       gHw.cpu_msr.amd_hwcr_valid ? (gHw.cpu_msr.amd_smm_locked ? "1" : "0") : "N/A",
                       gHw.cpu_msr.amd_vmcr_valid ? (gHw.cpu_msr.amd_svm_locked ? "1" : "0") : "N/A",
                       gHw.cpu_msr.amd_hwcr_valid ? (!gHw.cpu_msr.amd_cpb_disabled ? "On" : "Off") : "N/A");
        u_draw_kv(lx, y++, lw, "AMD Hardware Locks", b);

        if (gUnlockSpi.present && gUnlockSpi.bios_cntl_valid) {
            snprintf_ascii(b, sizeof(b), "%s BLE:%u BIOSWE:%u EISS:%u",
                           gUnlockSpi.controller_name,
                           (UINT32)gUnlockSpi.ble, (UINT32)gUnlockSpi.bioswe, (UINT32)gUnlockSpi.eiss);
        } else if (gUnlockSpi.present) {
            snprintf_ascii(b, sizeof(b), "%s [%04X:%04X] SPI:0x%lX",
                           gUnlockSpi.controller_name, (UINT32)gUnlockSpi.vid,
                           (UINT32)gUnlockSpi.did, gUnlockSpi.spibar_phys);
        } else {
            str_cpy(b, "Standard Virtual / Platform Flash", sizeof(b));
        }
        u_draw_kv(lx, y++, lw, "SPI & BIOS Flash", b);

        snprintf_ascii(b, sizeof(b), "HII:%u (%u Hidden, +%u FV2) | Stores:%u",
                       (UINT32)gHw.hii_question_count, (UINT32)gHw.hii_hidden_count,
                       (UINT32)gHw.hii_fv_pkg_count, (UINT32)gHw.hii_varstore_count);
        u_draw_kv(lx, y++, lw, "Decoded IFR & FV2", b);
        y++;

        UINTN fixed_cnt = 8U;
        UINTN total = fixed_cnt + hq_cnt;
        if (*io_cur >= total) *io_cur = total - 1U;
        UINTN vis = (gUiRows - 2U > y) ? (gUiRows - 2U - y) : 1U;
        if (*io_cur < *io_scroll) *io_scroll = *io_cur;
        if (*io_cur >= *io_scroll + vis) *io_scroll = *io_cur - vis + 1U;

        for (UINTN r = 0; r < vis && (*io_scroll + r) < total; r++) {
            UINTN idx = *io_scroll + r;
            BOOLEAN sel = (idx == *io_cur);
            if (idx == 0) {
                u_draw_opt(lx, y + r, lw, sel, FALSE, "grub-mod-setup_var", "CLI + setup_var2/3/vs/cv...");
            } else if (idx == 1) {
                if (gHw.cpu_msr.amd_pstate_valid && gHw.cpu_msr.amd_p0_mv > 0) {
                    snprintf_ascii(b, sizeof(b), "%u mV (SVI2 VID 0x%02X)",
                                   gHw.cpu_msr.amd_p0_mv, (UINT32)gHw.cpu_msr.amd_p0_vid);
                    u_draw_opt(lx, y + r, lw, sel, FALSE, "AMD P0 Core Undervolt", b);
                } else {
                    u_draw_opt(lx, y + r, lw, sel, TRUE, "AMD P0 Core Undervolt", "MSR Restricted in VM");
                }
            } else if (idx == 2) {
                u_draw_opt(lx, y + r, lw, sel, !gUnlockMePsp.amd_smn_ok, "AMD SMN Inspector",
                           gUnlockMePsp.amd_smn_ok ? "Read 00:00.0 0xB8/0xBC..." : "No AMD Root 00:00.0");
            } else if (idx == 3) {
                INTN q_ftpm = hw_hii_find_question_icase("fTPM", NULL);
                if (q_ftpm < 0) q_ftpm = hw_hii_find_question_icase("PSP", NULL);
                if (q_ftpm >= 0) {
                    format_hii_val_short((UINTN)q_ftpm, b, sizeof(b));
                    u_draw_opt(lx, y + r, lw, sel, FALSE, "AMD PSP / fTPM Mode", b);
                } else {
                    u_draw_opt(lx, y + r, lw, sel, !gUnlockMePsp.amd_psp_present, "AMD PSP / fTPM Mode",
                               gUnlockMePsp.amd_psp_present ? "Inspect PSP PCI..." : "Not Exposed");
                }
            } else if (idx == 4) {
                if (gUnlockSpi.present && gUnlockSpi.bios_cntl_valid) {
                    snprintf_ascii(b, sizeof(b), "BIOSWE:%u BLE:%u EISS:%u",
                                   (UINT32)gUnlockSpi.bioswe, (UINT32)gUnlockSpi.ble, (UINT32)gUnlockSpi.eiss);
                    u_draw_opt(lx, y + r, lw, sel, FALSE, "SPI BIOS Write-Enable", b);
                } else {
                    u_draw_opt(lx, y + r, lw, sel, TRUE, "SPI BIOS Write-Enable", "No 0xDC BIOS_CNTL");
                }
            } else if (idx == 5) {
                u_draw_opt(lx, y + r, lw, sel, FALSE, "BIOS / SPI Flash Locks", "Inspect / Unlock NVRAM...");
            } else if (idx == 6) {
                u_draw_opt(lx, y + r, lw, sel, FALSE, "Startup Auto-Patch",
                           has_autopatch ? "ACTIVE in NVRAM (Edit/Clear)" : "Save Live Tweaks to Boot...");
            } else if (idx == 7) {
                u_draw_opt(lx, y + r, lw, sel, FALSE, ">> Boot OS Directly", "No Reset (Keep Live Tweaks!)");
            } else {
                UINTN qi = s_unlock_q_idx[idx - fixed_cnt];
                const HW_HII_QUESTION *hq = &gHw.hii_questions[qi];
                CHAR8 lbl[28], vs[32];
                snprintf_ascii(lbl, sizeof(lbl), "%s%s", hq->is_suppressed ? "[H] " : "", hq->prompt);
                format_hii_val_short(qi, vs, sizeof(vs));
                u_draw_opt(lx, y + r, lw, sel, hq->read_only, lbl, vs);
            }
        }
        return;
    }

    /* Intel / Generic x86 Unlock Hub */
    const CHAR8 *help_intel =
        "Universal Unlock Hub (Dell / Lenovo / HP / ASUS / MSI / Gigabyte / Intel):\n"
        "- Dortania VerifyMsrE2 & ControlMsrE2 (All-Core MSR 0xE2 CFG Lock Audit + Exact setup_var_cv Command!).\n"
        "- Full datasone/grub-mod-setup_var (setup_var, setup_var2, setup_var_3, setup_var_vs, setup_var_cv) + RouteConfig + Read-Back Verify!\n"
        "- Live Intel FIVR Undervolting (MSR 0x150), Intel ME / HAP / HMRFPO, SPI BIOS_CNTL & Startup Auto-Patch!";
    ui_draw_setup_frame(tab_idx, "Unlock Hub: MSR 0xE2, UV, ME & setup_var", TRUE,
                        "Unlock Hub & MSR 0xE2", help_intel, footer_status);

    if (gUnlockMePsp.me_present) {
        if (gUnlockMePsp.fw_ver_valid) {
            snprintf_ascii(b, sizeof(b), "v%u.%u.%u.%u | %s (%s)",
                           (UINT32)gUnlockMePsp.fw_major, (UINT32)gUnlockMePsp.fw_minor,
                           (UINT32)gUnlockMePsp.fw_hotfix, (UINT32)gUnlockMePsp.fw_build,
                           gUnlockMePsp.working_state_str, gUnlockMePsp.op_mode_str);
        } else {
            snprintf_ascii(b, sizeof(b), "00:%02X.%X [%04X:%04X] %s | %s",
                           (UINT32)gUnlockMePsp.me_dev, (UINT32)gUnlockMePsp.me_func,
                           (UINT32)gUnlockMePsp.me_vid, (UINT32)gUnlockMePsp.me_did,
                           gUnlockMePsp.working_state_str, gUnlockMePsp.op_mode_str);
        }
    } else {
        str_cpy(b, "Not Present on PCI 00:16.0 (VM / Disabled)", sizeof(b));
    }
    u_draw_kv(lx, y++, lw, "Intel ME / CSME", b);

    if (gUnlockMePsp.me_present) {
        snprintf_ascii(b, sizeof(b), "HFSTS1:0x%08X | BtG:%s | Mfg:%u",
                       gUnlockMePsp.hfsts[0],
                       gUnlockMePsp.boot_guard_valid
                           ? (gUnlockMePsp.boot_guard_verified ? "Verified!" : "Off/Meas")
                           : "Off/N/A",
                       (UINT32)gUnlockMePsp.mfg_mode);
    } else {
        snprintf_ascii(b, sizeof(b), "HII:%u (%u Hidden, +%u FV2) | Stores:%u",
                       (UINT32)gHw.hii_question_count, (UINT32)gHw.hii_hidden_count,
                       (UINT32)gHw.hii_fv_pkg_count, (UINT32)gHw.hii_varstore_count);
    }
    u_draw_kv(lx, y++, lw, gUnlockMePsp.me_present ? "ME HFSTS & BootGuard" : "Decoded IFR & FV2", b);

    if (gUnlockSpi.present && gUnlockSpi.bios_cntl_valid) {
        snprintf_ascii(b, sizeof(b), "00:%02X.%X BLE:%u BIOSWE:%u EISS:%u%s",
                       (UINT32)gUnlockSpi.dev, (UINT32)gUnlockSpi.func,
                       (UINT32)gUnlockSpi.ble, (UINT32)gUnlockSpi.bioswe, (UINT32)gUnlockSpi.eiss,
                       gUnlockSpi.spibar_valid
                           ? (gUnlockSpi.flockdn ? " FLOCKDN:1" : " FLOCKDN:0")
                           : "");
    } else {
        str_cpy(b, "Not Exposed (Virtual Chipset)", sizeof(b));
    }
    u_draw_kv(lx, y++, lw, "PCH SPI & BIOS_CNTL", b);

    if (gUnlockFivr.supported) {
        snprintf_ascii(b, sizeof(b), "Core:%dmV Cache:%dmV iGPU:%dmV%s",
                       gUnlockFivr.plane_mv[0], gUnlockFivr.plane_mv[2], gUnlockFivr.plane_mv[1],
                       gUnlockFivr.plundervolt_locked ? " [LOCKED]" : " [RW!]");
    } else {
        snprintf_ascii(b, sizeof(b), "FIVR:%s | CFG:%s OC:%s",
                       gHw.feat_hypervisor ? "VM N/A" : "Locked/Pre-HSW",
                       gHw.cpu_msr.cst_cfg_valid ? (gHw.cpu_msr.cfg_locked ? "LOCK" : "UNLK") : "N/A",
                       gHw.cpu_msr.flex_oc_valid ? (gHw.cpu_msr.oc_locked ? "LOCK" : "UNLK") : "N/A");
    }
    u_draw_kv(lx, y++, lw, "Undervolt & CPU Locks", b);
    y++;

    UINTN fixed_cnt = 14U;
    UINTN total = fixed_cnt + hq_cnt;
    if (*io_cur >= total) *io_cur = total - 1U;
    UINTN vis = (gUiRows - 2U > y) ? (gUiRows - 2U - y) : 1U;
    if (*io_cur < *io_scroll) *io_scroll = *io_cur;
    if (*io_cur >= *io_scroll + vis) *io_scroll = *io_cur - vis + 1U;

    for (UINTN r = 0; r < vis && (*io_scroll + r) < total; r++) {
        UINTN idx = *io_scroll + r;
        BOOLEAN sel = (idx == *io_cur);

        if (idx == 0) {
            u_draw_opt(lx, y + r, lw, sel, FALSE, "One-Click UV Unlock", "Unlock OC + CFG Lock...");
        } else if (idx == 1) {
            const CHAR8 *e2s = gHw.cpu_msr.cst_cfg_valid
                               ? (gHw.cpu_msr.cfg_locked ? "LOCKED -> Audit/Unlock!" : "UNLOCKED (Verify All Cores)")
                               : "Audit All Cores + IFR...";
            u_draw_opt(lx, y + r, lw, sel, FALSE, "VerifyMsrE2 (CFG Lock)", e2s);
        } else if (idx == 2) {
            u_draw_opt(lx, y + r, lw, sel, FALSE, "grub-mod-setup_var", "CLI + setup_var2/3/vs/cv...");
        } else if (idx == 3) {
            if (gUnlockFivr.supported) {
                snprintf_ascii(b, sizeof(b), "%d mV [MSR 0x150]", gUnlockFivr.plane_mv[0]);
                u_draw_opt(lx, y + r, lw, sel, gUnlockFivr.plundervolt_locked, "CPU Core Undervolt", b);
            } else {
                u_draw_opt(lx, y + r, lw, sel, TRUE, "CPU Core Undervolt",
                           gHw.feat_hypervisor ? "Unavailable in VM" : "MSR 0x150 Unavailable");
            }
        } else if (idx == 4) {
            if (gUnlockFivr.supported) {
                snprintf_ascii(b, sizeof(b), "%d mV [MSR 0x150]", gUnlockFivr.plane_mv[2]);
                u_draw_opt(lx, y + r, lw, sel, gUnlockFivr.plundervolt_locked, "CPU Cache Undervolt", b);
            } else {
                u_draw_opt(lx, y + r, lw, sel, TRUE, "CPU Cache Undervolt",
                           gHw.feat_hypervisor ? "Unavailable in VM" : "MSR 0x150 Unavailable");
            }
        } else if (idx == 5) {
            if (gUnlockFivr.supported) {
                snprintf_ascii(b, sizeof(b), "Core %dmV + Cache %dmV",
                               gUnlockFivr.plane_mv[0], gUnlockFivr.plane_mv[2]);
                u_draw_opt(lx, y + r, lw, sel, gUnlockFivr.plundervolt_locked, "Sync Core + Cache UV", b);
            } else {
                u_draw_opt(lx, y + r, lw, sel, TRUE, "Sync Core + Cache UV", "Unavailable");
            }
        } else if (idx == 6) {
            if (gUnlockFivr.supported) {
                snprintf_ascii(b, sizeof(b), "iGPU:%dmV SA:%dmV IO:%dmV",
                               gUnlockFivr.plane_mv[1], gUnlockFivr.plane_mv[3], gUnlockFivr.plane_mv[4]);
                u_draw_opt(lx, y + r, lw, sel, gUnlockFivr.plundervolt_locked, "iGPU / SA / I/O UV", b);
            } else {
                u_draw_opt(lx, y + r, lw, sel, TRUE, "iGPU / SA / I/O UV", "Unavailable");
            }
        } else if (idx == 7) {
            INTN q_me = hw_hii_find_question_icase("ME State", NULL);
            if (q_me < 0) q_me = hw_hii_find_question_icase("High Assurance", NULL);
            if (q_me < 0) q_me = hw_hii_find_question_icase("AltMeDisable", NULL);
            if (q_me >= 0) {
                format_hii_val_short((UINTN)q_me, b, sizeof(b));
                u_draw_opt(lx, y + r, lw, sel, FALSE, "Intel ME / HAP Mode", b);
            } else if (gUnlockMePsp.me_present) {
                u_draw_opt(lx, y + r, lw, sel, FALSE, "Intel ME / HAP Mode", gUnlockMePsp.op_mode_str);
            } else {
                u_draw_opt(lx, y + r, lw, sel, TRUE, "Intel ME / HAP Mode", "No Intel ME Detected");
            }
        } else if (idx == 8) {
            if (gUnlockMePsp.me_present && gUnlockMePsp.heci_mmio_ok) {
                u_draw_opt(lx, y + r, lw, sel, FALSE, "ME HMRFPO Override",
                           (gUnlockMePsp.op_mode == 5U) ? "ACTIVE (Flash Unlocked!)" : "Send MKHI_HMRFPO_ENABLE");
            } else {
                u_draw_opt(lx, y + r, lw, sel, TRUE, "ME HMRFPO Override", "HECI1 MMIO Not Active");
            }
        } else if (idx == 9) {
            INTN q_rf = hw_hii_find_question_icase("ME FW Image Re-Flash", NULL);
            if (q_rf < 0) q_rf = hw_hii_find_question_icase("End of Post", NULL);
            if (q_rf >= 0) {
                format_hii_val_short((UINTN)q_rf, b, sizeof(b));
                u_draw_opt(lx, y + r, lw, sel, FALSE, "ME Re-Flash / EOP", b);
            } else {
                u_draw_opt(lx, y + r, lw, sel, !gUnlockMePsp.me_present, "ME Re-Flash / EOP",
                           gUnlockMePsp.me_present ? "Inspect ME / AMT..." : "Unavailable");
            }
        } else if (idx == 10) {
            if (gUnlockSpi.present && gUnlockSpi.bios_cntl_valid) {
                snprintf_ascii(b, sizeof(b), "BIOSWE:%u BLE:%u EISS:%u",
                               (UINT32)gUnlockSpi.bioswe, (UINT32)gUnlockSpi.ble, (UINT32)gUnlockSpi.eiss);
                u_draw_opt(lx, y + r, lw, sel, FALSE, "SPI BIOS Write-Enable", b);
            } else {
                u_draw_opt(lx, y + r, lw, sel, TRUE, "SPI BIOS Write-Enable", "Unavailable");
            }
        } else if (idx == 11) {
            INTN q_bl = hw_hii_find_question_icase("BIOS Lock", NULL);
            if (q_bl < 0) q_bl = hw_hii_find_question_icase("Flash Protection", NULL);
            if (q_bl >= 0) {
                format_hii_val_short((UINTN)q_bl, b, sizeof(b));
                u_draw_opt(lx, y + r, lw, sel, FALSE, "BIOS Lock & FPRR", b);
            } else {
                u_draw_opt(lx, y + r, lw, sel, !gUnlockSpi.spibar_valid, "BIOS Lock & FPRR",
                           gUnlockSpi.spibar_valid ? "Inspect SPIBAR / HSFSTS..." : "Not in HII");
            }
        } else if (idx == 12) {
            u_draw_opt(lx, y + r, lw, sel, FALSE, "Startup Auto-Patch",
                       has_autopatch ? "ACTIVE in NVRAM (Edit/Clear)" : "Save Live Tweaks to Boot...");
        } else if (idx == 13) {
            u_draw_opt(lx, y + r, lw, sel, FALSE, ">> Boot OS Directly", "No Reset (Keep Live Tweaks!)");
        } else {
            UINTN qi = s_unlock_q_idx[idx - fixed_cnt];
            const HW_HII_QUESTION *hq = &gHw.hii_questions[qi];
            CHAR8 lbl[28], vs[32];
            snprintf_ascii(lbl, sizeof(lbl), "%s%s", hq->is_suppressed ? "[H] " : "", hq->prompt);
            format_hii_val_short(qi, vs, sizeof(vs));
            u_draw_opt(lx, y + r, lw, sel, hq->read_only, lbl, vs);
        }
    }
}

BOOLEAN unlock_handle_submenu_key(const EFI_INPUT_KEY *k, UINTN *io_cur, UINTN *io_scroll) {
    (VOID)io_scroll;
    UINTN hq_cnt    = collect_unlock_hii_questions(s_unlock_q_idx, 256U);
    UINTN fixed_cnt = gHw.cpu_msr.is_amd ? 8U : 14U;
    UINTN total     = fixed_cnt + hq_cnt;
    UINTN vis       = (gUiRows > 9U) ? (gUiRows - 9U) : 8U;

    if (k->ScanCode == SCAN_UP)        { *io_cur = (*io_cur > 0) ? (*io_cur - 1U) : (total - 1U); return TRUE; }
    if (k->ScanCode == SCAN_DOWN)      { *io_cur = (*io_cur + 1U) % total; return TRUE; }
    if (k->ScanCode == SCAN_PAGE_UP)   { *io_cur = (*io_cur > vis) ? (*io_cur - vis) : 0U; return TRUE; }
    if (k->ScanCode == SCAN_PAGE_DOWN) { *io_cur = (*io_cur + vis < total) ? (*io_cur + vis) : (total - 1U); return TRUE; }

    BOOLEAN act = (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n' ||
                   k->UnicodeChar == L' '  || k->UnicodeChar == L'+'  ||
                   k->UnicodeChar == L'='  || k->UnicodeChar == L'-'  ||
                   k->ScanCode == SCAN_F5  || k->ScanCode == SCAN_F6);
    if (!act) return FALSE;

    if (*io_cur >= fixed_cnt) {
        edit_hii_q_modal(s_unlock_q_idx[*io_cur - fixed_cnt]);
        return TRUE;
    }

    if (gHw.cpu_msr.is_amd) {
        if (*io_cur == 0) {
            unlock_open_setup_var_modal();
        } else if (*io_cur == 1) {
            if (!gHw.cpu_msr.amd_pstate_valid) {
                INTN qc = hw_hii_find_question_icase("Curve Optimizer", NULL);
                if (qc >= 0) edit_hii_q_modal((UINTN)qc);
                else ui_message_modal("AMD SVI2 MSR Restricted",
                                      "Hardware P-State MSR 0xC0010064 is restricted by hypervisor/platform.", TRUE);
            } else {
                const UINT8 vids[7] = { 0x48, 0x40, 0x38, 0x30, 0x28, 0x24, 0x20 };
                const CHAR8 *v_opts[7] = {
                    "1100 mV (VID 0x48 - Deep Undervolt)",
                    "1150 mV (VID 0x40 - Cool & Efficient)",
                    "1200 mV (VID 0x38 - Balanced Undervolt)",
                    "1250 mV (VID 0x30 - Nominal)",
                    "1300 mV (VID 0x28 - Boost)",
                    "1325 mV (VID 0x24 - All-Core OC)",
                    "1350 mV (VID 0x20 - High OC)"
                };
                INTN p = ui_pick_option_modal("AMD P0 Core Voltage (SVI2 VID)", v_opts, 7, 2, 2);
                if (p >= 0 && p < 7) {
                    hw_amd_set_p0_vid(vids[p]);
                    hw_refresh_cpu_msrs();
                }
            }
        } else if (*io_cur == 2) {
            handle_amd_smn_inspector_modal();
        } else if (*io_cur == 3) {
            INTN q_ftpm = hw_hii_find_question_icase("fTPM", NULL);
            if (q_ftpm < 0) q_ftpm = hw_hii_find_question_icase("PSP", NULL);
            if (q_ftpm >= 0) edit_hii_q_modal((UINTN)q_ftpm);
            else if (gUnlockMePsp.amd_psp_present && gUnlockMePsp.amd_psp_pci_idx >= 0)
                debug_open_pci_config_editor((UINTN)gUnlockMePsp.amd_psp_pci_idx);
            else ui_message_modal("AMD PSP / fTPM", "No AMD PSP PCI function or fTPM HII setting exposed.", FALSE);
        } else if (*io_cur == 4) {
            handle_spi_bioswe_interactive();
        } else if (*io_cur == 5) {
            handle_bios_flash_nvram_unlock();
        } else if (*io_cur == 6) {
            unlock_manage_autopatch_modal();
        } else if (*io_cur == 7) {
            nvram_boot_os_preserve_live_modal("Boot / Chainload OS (Preserve Live Tweaks)");
        }
        return TRUE;
    }

    /* Intel Action Dispatch */
    switch (*io_cur) {
        case 0:
            run_one_click_undervolt_cfg_unlock();
            break;
        case 1:
            unlock_verify_msr_e2_all_cores_modal();
            break;
        case 2:
            unlock_open_setup_var_modal();
            break;
        case 3:
            unlock_edit_fivr_plane_interactive(0);
            break;
        case 4:
            unlock_edit_fivr_plane_interactive(2);
            break;
        case 5:
            unlock_edit_fivr_core_cache_sync_interactive();
            break;
        case 6: {
            const CHAR8 *pl_opts[3] = {
                "Plane 1: Intel iGPU (Slice) Voltage Offset",
                "Plane 3: System Agent (Uncore) Voltage Offset",
                "Plane 4: Analog I/O Voltage Offset"
            };
            INTN pl = ui_select_modal("Select Secondary FIVR Voltage Plane", pl_opts, 3, 0);
            if (pl == 0) unlock_edit_fivr_plane_interactive(1);
            else if (pl == 1) unlock_edit_fivr_plane_interactive(3);
            else if (pl == 2) unlock_edit_fivr_plane_interactive(4);
            break;
        }
        case 7:
            handle_intel_me_control_menu(FALSE);
            break;
        case 8: {
            if (!gUnlockMePsp.me_present || !gUnlockMePsp.heci_mmio_ok) {
                ui_message_modal("HECI1 MMIO Unavailable",
                    "Intel ME HECI1 (00:16.0) MMIO BAR0 is not mapped or present on this machine.", TRUE);
            } else if (ui_confirm_modal("Send Intel ME MKHI_HMRFPO_ENABLE",
                    "Send MKHI_HMRFPO_ENABLE (Group 0x05, Cmd 0x01) over HECI1 BAR0 MMIO to request pre-EOP ME Flash Protection Override?",
                    FALSE)) {
                CHAR8 rmsg[260];
                BOOLEAN ok = send_me_hmrfpo_enable(rmsg, sizeof(rmsg));
                ui_message_modal(ok ? "HMRFPO Override Active" : "HMRFPO Response", rmsg, !ok);
            }
            break;
        }
        case 9:
            handle_intel_me_control_menu(TRUE);
            break;
        case 10:
            handle_spi_bioswe_interactive();
            break;
        case 11:
            handle_bios_flash_nvram_unlock();
            break;
        case 12:
            unlock_manage_autopatch_modal();
            break;
        case 13:
            nvram_boot_os_preserve_live_modal("Boot / Chainload OS (Preserve Live FIVR/MSR Tweaks)");
            break;
    }
    return TRUE;
}

/* =========================================================================
 * 8. Telemetry Section for F12 EFI Dump (OhMyEFI_Report.txt)
 * ========================================================================= */
static VOID rpt_printf(VOID (*put_fn)(VOID *ctx, const CHAR8 *s), VOID *ctx, const CHAR8 *fmt, ...) {
    CHAR16 wbuf[384];
    CHAR8  abuf[384];
    va_list ap;
    va_start(ap, fmt);
    wvsnprintf(wbuf, 384, fmt, ap);
    va_end(ap);
    UINTN i = 0;
    while (i + 1U < sizeof(abuf) && wbuf[i]) {
        CHAR16 ch = wbuf[i];
        abuf[i] = ((ch >= 0x20U && ch <= 0x7EU) || ch == L'\r' || ch == L'\n' || ch == L'\t')
                  ? (CHAR8)ch : '?';
        i++;
    }
    abuf[i] = '\0';
    put_fn(ctx, abuf);
}

VOID unlock_append_report_section(VOID (*put_fn)(VOID *ctx, const CHAR8 *s), VOID *ctx) {
    if (!put_fn) return;
    unlock_refresh_all(TRUE);

    put_fn(ctx, "[8] SECURITY PROCESSOR (INTEL ME / AMD PSP / SMN), SPI FLASH LOCKS & FIVR\r\n");
    put_fn(ctx, "------------------------------------------------------------------------\r\n");
    rpt_printf(put_fn, ctx, "FV2 Hidden HII Scan : +%u unregistered HII PackageList(s) extracted from Firmware Volumes\r\n",
               (UINT32)gHw.hii_fv_pkg_count);
    rpt_printf(put_fn, ctx, "Startup Auto-Patch  : %s\r\n",
               unlock_has_startup_autopatch() ? "ACTIVE (OhMyEfiAutoPatch stored in NVRAM)" : "Not Configured");

    if (gUnlockMePsp.me_present) {
        rpt_printf(put_fn, ctx, "Intel ME / CSME     : PCI 00:%02X.%X [%04X:%04X] (%s) | BAR0=0x%lX (%s)\r\n",
                   (UINT32)gUnlockMePsp.me_dev, (UINT32)gUnlockMePsp.me_func,
                   (UINT32)gUnlockMePsp.me_vid, (UINT32)gUnlockMePsp.me_did,
                   gUnlockMePsp.me_enumerated_pci ? "Enumerated" : "Hidden PCI",
                   gUnlockMePsp.heci_bar0, gUnlockMePsp.heci_mmio_ok ? "MMIO Ready" : "No MMIO");
        if (gUnlockMePsp.fw_ver_valid) {
            rpt_printf(put_fn, ctx, "Intel ME FW Version : %u.%u.%u.%u (via HECI1 MKHI)\r\n",
                       (UINT32)gUnlockMePsp.fw_major, (UINT32)gUnlockMePsp.fw_minor,
                       (UINT32)gUnlockMePsp.fw_hotfix, (UINT32)gUnlockMePsp.fw_build);
        }
        rpt_printf(put_fn, ctx, "ME HFSTS1..HFSTS6   : %08X %08X %08X %08X %08X %08X\r\n",
                   gUnlockMePsp.hfsts[0], gUnlockMePsp.hfsts[1], gUnlockMePsp.hfsts[2],
                   gUnlockMePsp.hfsts[3], gUnlockMePsp.hfsts[4], gUnlockMePsp.hfsts[5]);
        rpt_printf(put_fn, ctx, "ME Decoded State    : WorkState=%s (%u) | OpMode=%s (%u) | MfgMode=%u | FPT_Bad=%u | Err=%u\r\n",
                   gUnlockMePsp.working_state_str, (UINT32)gUnlockMePsp.working_state,
                   gUnlockMePsp.op_mode_str, (UINT32)gUnlockMePsp.op_mode,
                   (UINT32)gUnlockMePsp.mfg_mode, (UINT32)gUnlockMePsp.fpt_bad,
                   (UINT32)gUnlockMePsp.error_code);
        if (gUnlockMePsp.boot_guard_valid) {
            rpt_printf(put_fn, ctx, "Intel Boot Guard    : HFSTS6=0x%08X | VerifiedBoot=%u | MeasuredBoot=%u | FPF_Locked=%u\r\n",
                       gUnlockMePsp.hfsts[5],
                       (UINT32)gUnlockMePsp.boot_guard_verified,
                       (UINT32)gUnlockMePsp.boot_guard_measured,
                       (UINT32)gUnlockMePsp.boot_guard_fpf_locked);
        }
    } else if (gHw.cpu_msr.is_amd) {
        if (gUnlockMePsp.amd_smn_ok) {
            rpt_printf(put_fn, ctx, "AMD Root Complex    : PCI 00:00.0 [1022:%04X] (SMN 0xB8/0xBC Active)\r\n",
                       (UINT32)gUnlockMePsp.amd_root_did);
            if (gUnlockMePsp.smu_ver_valid) {
                rpt_printf(put_fn, ctx, "AMD MP1 SMU FW Ver  : %u.%u.%u\r\n",
                           (UINT32)gUnlockMePsp.smu_major, (UINT32)gUnlockMePsp.smu_minor,
                           (UINT32)gUnlockMePsp.smu_patch);
            }
            if (gUnlockMePsp.amd_tctl_valid) {
                rpt_printf(put_fn, ctx, "AMD Zen Tctl Temp   : %d C (SMN 0x00059800 THM_TCON_CUR_TMP)\r\n",
                           gUnlockMePsp.amd_tctl_c);
            }
            rpt_printf(put_fn, ctx, "AMD System IOMMU    : %s\r\n",
                       gUnlockMePsp.amd_iommu_present ? "Present on PCI 00:00.2" : "Disabled / Not Enumerated");
        }
        if (gUnlockMePsp.amd_psp_present) {
            rpt_printf(put_fn, ctx, "AMD PSP / CCP       : PCI %02X:%02X.%X [%04X:%04X] BAR=0x%lX Cmd=0x%04X\r\n",
                       (UINT32)gUnlockMePsp.psp_bus, (UINT32)gUnlockMePsp.psp_dev,
                       (UINT32)gUnlockMePsp.psp_func, (UINT32)gUnlockMePsp.psp_vid,
                       (UINT32)gUnlockMePsp.psp_did, gUnlockMePsp.psp_bar, (UINT32)gUnlockMePsp.psp_cmd);
        } else {
            put_fn(ctx, "AMD PSP / CCP       : Not Exposed on PCI Bus\r\n");
        }
    } else {
        put_fn(ctx, "Intel ME / CSME     : Not Present / Disabled on PCI 00:16.0\r\n");
    }

    if (gUnlockSpi.present) {
        rpt_printf(put_fn, ctx, "SPI / LPC Controller: %s [%04X:%04X]\r\n",
                   gUnlockSpi.controller_name, (UINT32)gUnlockSpi.vid, (UINT32)gUnlockSpi.did);
        if (gUnlockSpi.bios_cntl_valid) {
            rpt_printf(put_fn, ctx, "  BIOS_CNTL (0xDC)  : 0x%02X | BIOSWE=%u | BLE=%u | EISS/SMM_BWP=%u\r\n",
                       (UINT32)gUnlockSpi.bios_cntl, (UINT32)gUnlockSpi.bioswe,
                       (UINT32)gUnlockSpi.ble, (UINT32)gUnlockSpi.eiss);
        }
        if (gUnlockSpi.spibar_valid) {
            rpt_printf(put_fn, ctx, "  SPIBAR @ 0x%08lX: HSFSTS=0x%04X (FLOCKDN=%u FDV=%u FDOPSS=%u) | FRAP=0x%08X (BRRA=0x%02X BRWA=0x%02X)\r\n",
                       gUnlockSpi.spibar_phys, (UINT32)gUnlockSpi.hsfsts,
                       (UINT32)gUnlockSpi.flockdn, (UINT32)gUnlockSpi.fdv, (UINT32)gUnlockSpi.fdopss,
                       gUnlockSpi.frap, (UINT32)gUnlockSpi.brra, (UINT32)gUnlockSpi.brwa);
            rpt_printf(put_fn, ctx, "  SPI FPR0..FPR4    : %08X %08X %08X %08X %08X (%u Active WPE Ranges)\r\n",
                       gUnlockSpi.fpr[0], gUnlockSpi.fpr[1], gUnlockSpi.fpr[2],
                       gUnlockSpi.fpr[3], gUnlockSpi.fpr[4], (UINT32)gUnlockSpi.fpr_wpe_count);
        }
    }

    if (gUnlockFivr.supported) {
        rpt_printf(put_fn, ctx, "Intel FIVR (0x150)  : Core=%dmV | iGPU=%dmV | Cache=%dmV | SA=%dmV | AnalogIO=%dmV%s\r\n",
                   gUnlockFivr.plane_mv[0], gUnlockFivr.plane_mv[1], gUnlockFivr.plane_mv[2],
                   gUnlockFivr.plane_mv[3], gUnlockFivr.plane_mv[4],
                   gUnlockFivr.plundervolt_locked ? " [Plundervolt/OC Locked]" : " [Unlocked]");
    } else if (!gHw.cpu_msr.is_amd) {
        rpt_printf(put_fn, ctx, "Intel FIVR (0x150)  : Unavailable (%s)\r\n",
                   gHw.feat_hypervisor ? "Hypervisor/VM MSR Masked" : "Not Exposed on This CPU");
    }
    put_fn(ctx, "\r\n");
}
