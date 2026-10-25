#include "dump.h"
#include "hwinfo.h"
#include "nvram.h"
#include "unlock.h"
#include "spoof.h"
#include "ui.h"
#include "util.h"

typedef struct {
    CHAR8 *buf;
    UINTN  len;
    UINTN  cap;
} DYN_TEXT;

static BOOLEAN dtxt_init(DYN_TEXT *t, UINTN init_cap) {
    t->len = 0;
    t->cap = (init_cap < 4096) ? 4096 : init_cap;
    t->buf = (CHAR8 *)alloc_pool(t->cap);
    if (!t->buf) {
        t->cap = 0;
        return FALSE;
    }
    t->buf[0] = '\0';
    return TRUE;
}

static VOID dtxt_free(DYN_TEXT *t) {
    if (t->buf) free_pool(t->buf);
    t->buf = NULL;
    t->len = 0;
    t->cap = 0;
}

static BOOLEAN dtxt_ensure(DYN_TEXT *t, UINTN extra) {
    if (!t->buf) return FALSE;
    if (t->len + extra + 2 <= t->cap) return TRUE;
    UINTN ncap = t->cap * 2;
    while (ncap < t->len + extra + 2) ncap *= 2;
    CHAR8 *nb = (CHAR8 *)alloc_pool(ncap);
    if (!nb) return FALSE;
    memcpy(nb, t->buf, t->len + 1);
    free_pool(t->buf);
    t->buf = nb;
    t->cap = ncap;
    return TRUE;
}

static VOID dtxt_puts(DYN_TEXT *t, const CHAR8 *s) {
    if (!s) return;
    UINTN l = str_len(s);
    if (!dtxt_ensure(t, l)) return;
    memcpy(t->buf + t->len, s, l);
    t->len += l;
    t->buf[t->len] = '\0';
}

static VOID dtxt_printf(DYN_TEXT *t, const CHAR8 *fmt, ...) {
    CHAR16 wbuf[512];
    CHAR8  abuf[512];
    va_list ap;
    va_start(ap, fmt);
    wvsnprintf(wbuf, 512, fmt, ap);
    va_end(ap);
    UINTN i = 0;
    while (i + 1 < sizeof(abuf) && wbuf[i]) {
        CHAR16 ch = wbuf[i];
        if ((ch >= 0x20 && ch <= 0x7E) || ch == L'\n' || ch == L'\r' || ch == L'\t') {
            abuf[i] = (CHAR8)ch;
        } else {
            abuf[i] = '?';
        }
        i++;
    }
    abuf[i] = '\0';
    dtxt_puts(t, abuf);
}

static VOID draw_dump_progress(const CHAR8 *step_msg, UINTN files_done) {
    UINTN mw = 58, mh = 7;
    if (mw > gUiCols - 4) mw = gUiCols - 4;
    UINTN mx = (gUiCols - mw) / 2;
    UINTN my = (gUiRows - mh) / 2;

    ui_draw_box(mx, my, mw, mh, gTheme.modal_border_attr, gTheme.modal_attr, TRUE);
    ui_puts(mx + 2, my, "[ Oh my EFI! - EFI Dump ]", gTheme.modal_border_attr);
    ui_puts_n(mx + 3, my + 2, step_msg ? step_msg : "Writing files...", mw - 6, gTheme.modal_attr);
    ui_printf(mx + 3, my + 4, gTheme.modal_border_attr, "Files Saved: %u", (UINT32)files_done);
    ui_present();
}

static BOOLEAN write_file_in_dir(
    EFI_FILE_PROTOCOL *dir,
    const CHAR16 *fname_w,
    const VOID *data,
    UINTN size
) {
    if (!dir || !fname_w || (!data && size > 0)) return FALSE;

    /* Delete pre-existing file first so truncated re-dumps never leave stale tail bytes */
    EFI_FILE_PROTOCOL *old_fh = NULL;
    if (!EFI_ERROR(dir->Open(dir, &old_fh, (CHAR16 *)fname_w,
                             EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0)) && old_fh) {
        if (old_fh->Delete) {
            old_fh->Delete(old_fh);
        } else {
            old_fh->Close(old_fh);
        }
    }

    EFI_FILE_PROTOCOL *fh = NULL;
    EFI_STATUS st = dir->Open(
        dir, &fh, (CHAR16 *)fname_w,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
        0
    );
    if (EFI_ERROR(st) || !fh) return FALSE;

    UINTN to_write = size;
    st = (size > 0) ? fh->Write(fh, &to_write, (VOID *)data) : EFI_SUCCESS;
    if (fh->Flush) fh->Flush(fh);
    fh->Close(fh);
    return (!EFI_ERROR(st) && to_write == size);
}

static VOID resolve_boot_dir_from_loaded_image(
    EFI_HANDLE *out_boot_dev,
    CHAR16 *out_boot_dir_w,
    UINTN max_wchars
) {
    *out_boot_dev = NULL;
    wstr_cpy(out_boot_dir_w, L"\\", max_wchars);
    if (!gBS || !gImageHandle) return;

    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    if (EFI_ERROR(gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&li)) || !li) {
        return;
    }
    *out_boot_dev = li->DeviceHandle;
    if (!li->FilePath) return;

    CHAR16 full_path[192];
    full_path[0] = 0;

    const EFI_DEVICE_PATH_PROTOCOL *n = li->FilePath;
    for (UINTN guard = 0; guard < 32; guard++) {
        UINT16 nl = (UINT16)n->Length[0] | ((UINT16)n->Length[1] << 8);
        if (nl < 4 || n->Type == 0x7F) break;
        if (n->Type == 0x04 && n->SubType == 0x04 && nl > 4) {
            CHAR16 seg[128];
            UINTN wcnt = (nl - 4) / sizeof(CHAR16);
            if (wcnt >= 128) wcnt = 127;
            memcpy(seg, (const UINT8 *)n + 4, wcnt * sizeof(CHAR16));
            seg[wcnt] = 0;
            if (seg[0] != L'\\' && full_path[0] == 0) {
                wstr_cat(full_path, L"\\", 192);
            } else if (seg[0] != L'\\' && full_path[wstr_len(full_path) - 1] != L'\\') {
                wstr_cat(full_path, L"\\", 192);
            }
            wstr_cat(full_path, seg, 192);
        }
        n = (const EFI_DEVICE_PATH_PROTOCOL *)((const UINT8 *)n + nl);
    }

    /* Normalize forward slashes if any and strip executable filename to get directory */
    UINTN flen = wstr_len(full_path);
    for (UINTN i = 0; i < flen; i++) {
        if (full_path[i] == L'/') full_path[i] = L'\\';
    }
    INTN last_sep = -1;
    for (UINTN i = 0; i < flen; i++) {
        if (full_path[i] == L'\\') last_sep = (INTN)i;
    }
    if (last_sep <= 0) {
        wstr_cpy(out_boot_dir_w, L"\\", max_wchars);
    } else {
        full_path[last_sep] = 0;
        wstr_cpy(out_boot_dir_w, full_path, max_wchars);
    }
}

static BOOLEAN open_writable_dump_dirs(
    EFI_FILE_PROTOCOL **out_root,
    EFI_FILE_PROTOCOL **out_boot_dir,
    EFI_FILE_PROTOCOL **out_dump_subdir,
    CHAR8 *out_display_path,
    UINTN max_disp
) {
    *out_root        = NULL;
    *out_boot_dir    = NULL;
    *out_dump_subdir = NULL;

    EFI_HANDLE boot_dev = NULL;
    CHAR16 boot_dir_w[160];
    resolve_boot_dir_from_loaded_image(&boot_dev, boot_dir_w, 160);

    /* 1. Try exact volume & directory that booted this .efi */
    if (boot_dev) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs = NULL;
        if (!EFI_ERROR(gBS->HandleProtocol(boot_dev, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&sfs)) && sfs) {
            EFI_FILE_PROTOCOL *root = NULL;
            if (!EFI_ERROR(sfs->OpenVolume(sfs, &root)) && root) {
                EFI_FILE_PROTOCOL *bdir = NULL;
                if (EFI_ERROR(root->Open(root, &bdir, boot_dir_w, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0)) || !bdir) {
                    wstr_cpy(boot_dir_w, L"\\", 160);
                    root->Open(root, &bdir, boot_dir_w, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
                }
                if (bdir) {
                    EFI_FILE_PROTOCOL *sub = NULL;
                    EFI_STATUS st = bdir->Open(
                        bdir, &sub, L"OhMyEFI_Dump",
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                        EFI_FILE_DIRECTORY
                    );
                    if (!EFI_ERROR(st) && sub) {
                        *out_root        = root;
                        *out_boot_dir    = bdir;
                        *out_dump_subdir = sub;
                        CHAR8 bdir_a[120];
                        wstr_to_ascii(bdir_a, boot_dir_w, sizeof(bdir_a));
                        if (str_cmp(bdir_a, "\\") == 0) {
                            snprintf_ascii(out_display_path, max_disp, "[BootVol]:\\OhMyEFI_Dump\\");
                        } else {
                            snprintf_ascii(out_display_path, max_disp, "[BootVol]:%s\\OhMyEFI_Dump\\", bdir_a);
                        }
                        return TRUE;
                    }
                    bdir->Close(bdir);
                }
                root->Close(root);
            }
        }
    }

    /* 2. Fallback if boot media is Read-Only (e.g. CD/ISO): find first writable EFI FAT volume */
    UINTN cnt = 0;
    EFI_HANDLE *hs = NULL;
    if (!EFI_ERROR(efi_locate_handles(&gEfiSimpleFileSystemProtocolGuid, &cnt, &hs)) && hs) {
        for (UINTN i = 0; i < cnt; i++) {
            EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs = NULL;
            if (EFI_ERROR(gBS->HandleProtocol(hs[i], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&sfs)) || !sfs)
                continue;
            EFI_FILE_PROTOCOL *root = NULL;
            if (EFI_ERROR(sfs->OpenVolume(sfs, &root)) || !root) continue;

            EFI_FILE_PROTOCOL *sub = NULL;
            EFI_STATUS st = root->Open(
                root, &sub, L"OhMyEFI_Dump",
                EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                EFI_FILE_DIRECTORY
            );
            if (!EFI_ERROR(st) && sub) {
                EFI_FILE_PROTOCOL *bdir = NULL;
                root->Open(root, &bdir, L"\\", EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
                *out_root        = root;
                *out_boot_dir    = bdir ? bdir : root;
                *out_dump_subdir = sub;
                snprintf_ascii(out_display_path, max_disp, "[FS%u]:\\OhMyEFI_Dump\\", (UINT32)i);
                free_pool(hs);
                return TRUE;
            }
            root->Close(root);
        }
        free_pool(hs);
    }
    return FALSE;
}

static VOID sanitize_filename_ascii(const CHAR8 *in, CHAR8 *out, UINTN max_len) {
    UINTN oi = 0;
    for (UINTN i = 0; in && in[i] && oi + 1 < max_len; i++) {
        CHAR8 c = in[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_') {
            out[oi++] = c;
        } else {
            out[oi++] = '_';
        }
    }
    if (oi == 0 && max_len > 1) out[oi++] = 'X';
    out[oi] = '\0';
}

static VOID dtxt_put_cb(VOID *ctx, const CHAR8 *s) {
    dtxt_puts((DYN_TEXT *)ctx, s);
}

static VOID build_full_system_report(DYN_TEXT *r, const CHAR8 *saved_loc) {
    dtxt_puts(r, "========================================================================\r\n");
    dtxt_printf(r, "  %s - EFI Dump Report\r\n", OHMYEFI_TITLE);
    dtxt_printf(r, "  %s\r\n", OHMYEFI_COPYRIGHT);
    dtxt_printf(r, "  Saved Location: %s\r\n", saved_loc);
    if (gRT && gRT->GetTime) {
        EFI_TIME tm;
        if (!EFI_ERROR(gRT->GetTime(&tm, NULL))) {
            dtxt_printf(r, "  Timestamp (RTC): %04u-%02u-%02u %02u:%02u:%02u\r\n",
                        (UINT32)tm.Year, (UINT32)tm.Month, (UINT32)tm.Day,
                        (UINT32)tm.Hour, (UINT32)tm.Minute, (UINT32)tm.Second);
        }
    }
    dtxt_puts(r, "========================================================================\r\n\r\n");

    /* 1. Firmware & SMBIOS Identity */
    dtxt_puts(r, "[1] FIRMWARE & SMBIOS SYSTEM IDENTITY\r\n");
    dtxt_puts(r, "------------------------------------------------------------------------\r\n");
    dtxt_printf(r, "EFI Firmware Vendor : %s (Rev 0x%08X, UEFI %u.%02u)\r\n",
                gHw.fw_vendor, gHw.fw_revision, (UINT32)gHw.uefi_major, (UINT32)gHw.uefi_minor);
    dtxt_printf(r, "Platform Class      : %s (%s)\r\n",
                gHw.is_apple_mac ? "Apple Intel Mac EFI" : "Standard UEFI PC/VM", gHw.hypervisor_name);
    dtxt_printf(r, "BIOS Vendor / Ver   : %s | %s (%s)\r\n", gHw.bios_vendor, gHw.bios_version, gHw.bios_date);
    dtxt_printf(r, "System Manufacturer : %s\r\n", gHw.sys_manufacturer);
    dtxt_printf(r, "System Product/Model: %s (Version: %s)\r\n", gHw.sys_product, gHw.sys_version);
    dtxt_printf(r, "System Serial No.   : %s\r\n", gHw.sys_serial);
    dtxt_printf(r, "Hardware UUID       : %s\r\n", gHw.sys_uuid);
    dtxt_printf(r, "%-20s: %s %s | Serial: %s\r\n",
                gHw.is_apple_mac ? "Baseboard / MLB" : "Baseboard / Serial",
                gHw.board_manufacturer, gHw.board_product, gHw.board_serial);
    dtxt_printf(r, "Chassis Type        : %s (%s) | Asset: %s\r\n",
                gHw.chassis_type, gHw.chassis_manufacturer, gHw.chassis_asset_tag);
    dtxt_printf(r, "SMBIOS Table        : @ 0x%lX (%u bytes, %s) | Temp Spoof: %s\r\n\r\n",
                gHw.smbios_table_addr, gHw.smbios_table_size,
                gHw.smbios_writable ? "RAM-Writable" : "Read-Only",
                gSpoofActive ? "ACTIVE (Temporary RAM Table!)" : "None (Factory)");

    /* 2. CPU Topology, CPUID & Hardware MSRs */
    dtxt_puts(r, "[2] PROCESSOR TOPOLOGY, CPUID & HARDWARE MSRs (FREQ / OVERCLOCK / LOCKS)\r\n");
    dtxt_puts(r, "------------------------------------------------------------------------\r\n");
    dtxt_printf(r, "Processor Brand     : %s (%s)\r\n", gHw.cpu_brand, gHw.cpu_vendor);
    dtxt_printf(r, "CPUID Signature     : 0x%08X (Family %u, Model 0x%02X [%u], Stepping %u)\r\n",
                gHw.cpu_signature, gHw.cpu_family, gHw.cpu_model, gHw.cpu_model, gHw.cpu_stepping);
    dtxt_printf(r, "Resolved Topology   : %u Physical Core(s) / %u Logical Thread(s)\r\n",
                gHw.cpu_cores, gHw.cpu_threads);
    dtxt_printf(r, "Topology Sources    : SMT/Core=%u | MADT_APIC=%u | MP_Services=%u | SMBIOS=%uC/%uT\r\n",
                gHw.cpu_smt_per_core, gHw.cpu_madt_threads, gHw.cpu_mp_threads,
                gHw.cpu_smbios_cores, gHw.cpu_smbios_threads);
    dtxt_printf(r, "Max / Current Clock : %u MHz / %u MHz | Addr Bits: %u Phys / %u Virt\r\n",
                gHw.cpu_max_mhz, gHw.cpu_cur_mhz, (UINT32)gHw.phys_addr_bits, (UINT32)gHw.virt_addr_bits);

    UINT32 leaves[] = { 0x00U, 0x01U, 0x04U, 0x06U, 0x07U, 0x0BU, 0x1FU, 0x80000000U, 0x80000001U, 0x80000008U };
    for (UINTN i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
        UINT32 a = 0, b = 0, c = 0, d = 0;
        cpu_cpuid(leaves[i], 0, &a, &b, &c, &d);
        dtxt_printf(r, "  CPUID[0x%08X.0]: EAX=%08X EBX=%08X ECX=%08X EDX=%08X\r\n",
                    leaves[i], a, b, c, d);
        if (leaves[i] == 0x0BU || leaves[i] == 0x1FU) {
            cpu_cpuid(leaves[i], 1, &a, &b, &c, &d);
            dtxt_printf(r, "  CPUID[0x%08X.1]: EAX=%08X EBX=%08X ECX=%08X EDX=%08X\r\n",
                        leaves[i], a, b, c, d);
        }
    }

    hw_refresh_cpu_msrs();
    if (gHw.cpu_msr.cst_cfg_valid) {
        dtxt_printf(r, "  MSR 0x00E2 (PKG_CST_CONFIG): 0x%016lX | CFG Lock=%s | PkgCStateLimit=0x%X\r\n",
                    gHw.cpu_msr.cst_cfg_val,
                    gHw.cpu_msr.cfg_locked ? "LOCKED (Bit15=1)" : "UNLOCKED (Bit15=0)",
                    (UINT32)gHw.cpu_msr.pkg_cstate_limit);
    }
    if (gHw.cpu_msr.misc_valid) {
        dtxt_printf(r, "  MSR 0x01A0 (IA32_MISC_EN)  : 0x%016lX | EIST=%u | TurboDisable=%u | FastStr=%u | TCC=%u\r\n",
                    gHw.cpu_msr.misc_val,
                    (UINT32)gHw.cpu_msr.eist_enabled,
                    (UINT32)gHw.cpu_msr.turbo_disabled,
                    (UINT32)gHw.cpu_msr.fast_strings,
                    (UINT32)gHw.cpu_msr.auto_tcc);
    }
    if (gHw.cpu_msr.power_ctl_valid) {
        dtxt_printf(r, "  MSR 0x01FC (MSR_POWER_CTL) : 0x%016lX | BD_PROCHOT=%u | C1E=%u\r\n",
                    gHw.cpu_msr.power_ctl_val,
                    (UINT32)gHw.cpu_msr.bd_prochot,
                    (UINT32)gHw.cpu_msr.c1e_enable);
    }
    if (gHw.cpu_msr.feat_ctl_valid) {
        dtxt_printf(r, "  MSR 0x003A (FEATURE_CTRL)  : 0x%016lX | Lock=%u | VMX_Outside_SMX=%u\r\n",
                    gHw.cpu_msr.feat_ctl_val,
                    (UINT32)gHw.cpu_msr.vmx_locked,
                    (UINT32)gHw.cpu_msr.vmx_outside_smx);
    }
    if (gHw.cpu_msr.plat_info_valid) {
        dtxt_printf(r, "  MSR 0x00CE (PLATFORM_INFO) : 0x%016lX | BaseRatio=%ux | MinRatio=%ux | TurboRatioUnl=%u\r\n",
                    gHw.cpu_msr.plat_info_val,
                    (UINT32)gHw.cpu_msr.intel_base_ratio,
                    (UINT32)gHw.cpu_msr.intel_min_ratio,
                    (UINT32)gHw.cpu_msr.intel_tdp_ratio_unl);
    }
    if (gHw.cpu_msr.perf_valid) {
        dtxt_printf(r, "  MSR 0x0198/0x0199 (PERF)   : CurRatio=%ux (%u MHz) | TargetRatio=%ux (%u MHz)\r\n",
                    (UINT32)gHw.cpu_msr.intel_cur_ratio, (UINT32)gHw.cpu_msr.intel_cur_ratio * 100U,
                    (UINT32)gHw.cpu_msr.intel_target_ratio, (UINT32)gHw.cpu_msr.intel_target_ratio * 100U);
    }
    if (gHw.cpu_msr.turbo_limit_valid) {
        dtxt_printf(r, "  MSR 0x01AD (TURBO_LIMIT)   : 0x%016lX | 1C=%ux | AllCore=%ux\r\n",
                    gHw.cpu_msr.turbo_limit_val,
                    (UINT32)gHw.cpu_msr.intel_turbo_1c,
                    (UINT32)gHw.cpu_msr.intel_turbo_allc);
    }
    if (gHw.cpu_msr.flex_oc_valid) {
        dtxt_printf(r, "  MSR 0x0194 (FLEX_OC_LOCK)  : 0x%016lX | OC_Lock=%s | FlexEn=%u | FlexRatio=%ux\r\n",
                    gHw.cpu_msr.flex_oc_val,
                    gHw.cpu_msr.oc_locked ? "LOCKED (Bit20=1)" : "UNLOCKED (Bit20=0)",
                    (UINT32)gHw.cpu_msr.flex_enabled,
                    (UINT32)gHw.cpu_msr.flex_ratio);
    }
    if (gHw.cpu_msr.pkg_pwr_valid) {
        dtxt_printf(r, "  MSR 0x0610 (PKG_PWR_LIMIT) : 0x%016lX | PL1=%uW | PL2=%uW | Lock=%u\r\n",
                    gHw.cpu_msr.pkg_pwr_val,
                    (UINT32)gHw.cpu_msr.pl1_watts,
                    (UINT32)gHw.cpu_msr.pl2_watts,
                    (UINT32)gHw.cpu_msr.pkg_pwr_locked);
    }
    if (gHw.cpu_msr.amd_hwcr_valid) {
        dtxt_printf(r, "  MSR 0xC0010015 (AMD_HWCR)  : 0x%016lX | CPB_Boost=%s | SMMLock=%u\r\n",
                    gHw.cpu_msr.amd_hwcr_val,
                    gHw.cpu_msr.amd_cpb_disabled ? "Disabled" : "Enabled",
                    (UINT32)gHw.cpu_msr.amd_smm_locked);
    }
    if (gHw.cpu_msr.amd_pstate_valid) {
        dtxt_printf(r, "  MSR 0xC0010064 (AMD_PSTATE): P0=%u MHz @ %u mV (VID 0x%02X, Raw 0x%016lX) | P1=%u MHz | P2=%u MHz | Cur=P%u\r\n",
                    gHw.cpu_msr.amd_p0_mhz, gHw.cpu_msr.amd_p0_mv,
                    (UINT32)gHw.cpu_msr.amd_p0_vid, gHw.cpu_msr.amd_p0_raw,
                    gHw.cpu_msr.amd_p1_mhz, gHw.cpu_msr.amd_p2_mhz,
                    (UINT32)gHw.cpu_msr.amd_cur_pstate);
    }
    if (gHw.cpu_msr.amd_vmcr_valid) {
        dtxt_printf(r, "  MSR 0xC0010114 (AMD_VM_CR) : 0x%016lX | SVM=%s | SVMLock=%u\r\n",
                    gHw.cpu_msr.amd_vmcr_val,
                    gHw.cpu_msr.amd_svm_disabled ? "Disabled" : "Enabled",
                    (UINT32)gHw.cpu_msr.amd_svm_locked);
    }
    dtxt_puts(r, "\r\n");

    /* 3. GPU, VRAM & Resizable BAR */
    dtxt_puts(r, "[3] GPU, VRAM APERTURE, UMA / STOLEN MEMORY & RESIZABLE BAR\r\n");
    dtxt_puts(r, "------------------------------------------------------------------------\r\n");
    if (gHw.gop_present) {
        dtxt_printf(r, "UEFI GOP Console    : %ux%u (%s) | FB Base=0x%lX | FB Size=%lu KB\r\n",
                    gHw.gop_width, gHw.gop_height, gHw.gop_format,
                    gHw.gop_fb_base, gHw.gop_fb_size >> 10);
    }
    if (gHw.igd_ggc_present) {
        dtxt_printf(r, "Intel 00:00.0 GGC   : 0x%04X | Stolen VRAM=%u MB | GTT=%u MB | GGCLCK=%s | IVD=%u\r\n",
                    (UINT32)gHw.igd_ggc_raw, gHw.igd_stolen_mb, gHw.igd_gtt_mb,
                    gHw.igd_ggc_locked ? "Locked(1)" : "Unlocked(0)",
                    (UINT32)gHw.igd_vga_disable);
    }
    for (UINTN g = 0; g < gHw.gpu_count; g++) {
        const HW_PCI_DEV_INFO *pd = &gHw.pci_devs[gHw.gpu_pci_indices[g]];
        CHAR8 rb_info[48];
        if (pd->rebar_supported) {
            snprintf_ascii(rb_info, sizeof(rb_info), "Supported (Active=%luMB / Max=%luMB)",
                           (1ULL << pd->rebar_cur_size_exp), (1ULL << pd->rebar_max_size_exp));
        } else {
            str_cpy(rb_info, "No", sizeof(rb_info));
        }
        dtxt_printf(r, "GPU #%u              : %02X:%02X.%X [%04X:%04X] %s %s | VRAM BAR=0x%lX (%lu MB) | ReBAR=%s\r\n",
                    (UINT32)g, (UINT32)pd->bus, (UINT32)pd->dev, (UINT32)pd->func,
                    (UINT32)pd->vendor_id, (UINT32)pd->device_id,
                    pd->vendor_name, pd->class_name,
                    pd->vram_bar_base, pd->vram_bar_size >> 20, rb_info);
    }
    dtxt_puts(r, "\r\n");

    /* 4. Memory & DIMM Inventory */
    dtxt_puts(r, "[4] PHYSICAL MEMORY & SMBIOS DIMM INVENTORY\r\n");
    dtxt_puts(r, "------------------------------------------------------------------------\r\n");
    dtxt_printf(r, "Total Physical RAM  : %lu MB | Usable Free: %lu MB | ACPI: %lu KB | RT: %lu KB\r\n",
                gHw.total_ram_bytes >> 20, gHw.usable_ram_bytes >> 20,
                gHw.acpi_ram_bytes >> 10, gHw.runtime_ram_bytes >> 10);
    for (UINTN i = 0; i < gHw.dimm_count; i++) {
        const HW_DIMM_INFO *dm = &gHw.dimms[i];
        dtxt_printf(r, "  DIMM[%02u] %-12s : %5u MB %-6s %4u MHz | %s | PN:%s | SN:%s\r\n",
                    (UINT32)i, dm->locator, dm->size_mb, dm->mem_type, (UINT32)dm->speed_mhz,
                    dm->manufacturer, dm->part_number, dm->serial);
    }
    dtxt_puts(r, "\r\n");

    /* 5. PCI / PCIe Devices & Full 256B Config Space Dump */
    dtxt_puts(r, "[5] PCI / PCIe DEVICES, LINK SPEED/ASPM & 256-BYTE CONFIG SPACES\r\n");
    dtxt_puts(r, "------------------------------------------------------------------------\r\n");
    for (UINTN i = 0; i < gHw.pci_count; i++) {
        const HW_PCI_DEV_INFO *pd = &gHw.pci_devs[i];
        dtxt_printf(r, "PCI %04X:%02X:%02X.%X [%04X:%04X] Subsys[%04X:%04X] Class %02X.%02X.%02X (%s %s)\r\n",
                    (UINT32)pd->seg, (UINT32)pd->bus, (UINT32)pd->dev, (UINT32)pd->func,
                    (UINT32)pd->vendor_id, (UINT32)pd->device_id,
                    (UINT32)pd->subsys_vendor_id, (UINT32)pd->subsys_id,
                    (UINT32)pd->class_code, (UINT32)pd->subclass, (UINT32)pd->prog_if,
                    pd->vendor_name, pd->class_name);
        if (pd->pcie_cap_off != 0) {
            const CHAR8 *aspm_s[4] = { "Disabled", "L0s", "L1", "L0s+L1" };
            dtxt_printf(r, "  PCIe Cap @0x%02X (v%u): Link Cur=Gen%u x%u (Max=Gen%u x%u) | ASPM=%s (Sup=0x%X) | TargetGen=%u | RelaxOrd=%u\r\n",
                        (UINT32)pd->pcie_cap_off, (UINT32)pd->pcie_cap_ver,
                        (UINT32)pd->pcie_cur_speed, (UINT32)pd->pcie_cur_width,
                        (UINT32)pd->pcie_max_speed, (UINT32)pd->pcie_max_width,
                        aspm_s[pd->pcie_aspm_cur & 3U], (UINT32)pd->pcie_aspm_sup,
                        (UINT32)pd->pcie_target_speed, (UINT32)pd->pcie_relaxed_ord);
        }
        UINT8 cfg256[256];
        if (pd->pci_io && !EFI_ERROR(pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint8, 0, 256, cfg256))) {
            for (UINTN row = 0; row < 256; row += 16) {
                dtxt_printf(r, "    %02X: ", (UINT32)row);
                for (UINTN col = 0; col < 16; col++) {
                    dtxt_printf(r, "%02X ", (UINT32)cfg256[row + col]);
                }
                dtxt_puts(r, "\r\n");
            }
        }
    }
    dtxt_puts(r, "\r\n");

    /* 6. ACPI Tables */
    dtxt_puts(r, "[6] ACPI FIRMWARE TABLES\r\n");
    dtxt_puts(r, "------------------------------------------------------------------------\r\n");
    dtxt_printf(r, "RSDP @ 0x%lX (Rev %u, OEM: %s) | MCFG ECAM @ 0x%lX\r\n",
                gHw.acpi_rsdp_addr, (UINT32)gHw.acpi_revision, gHw.acpi_oem_id, gHw.mcfg_ecam_base);
    for (UINTN i = 0; i < gHw.acpi_count; i++) {
        const HW_ACPI_TABLE_INFO *ti = &gHw.acpi_tables[i];
        dtxt_printf(r, "  [%02u] %-4s @ 0x%012lX | %7u B | Rev %u | OEM:%-6s %-8s | %s | %s\r\n",
                    (UINT32)i, ti->signature, ti->phys_addr, ti->length, (UINT32)ti->revision,
                    ti->oem_id, ti->oem_table_id,
                    ti->checksum_ok ? "CSUM_OK" : "CSUM_BAD",
                    ti->writable ? "RW" : "RO");
    }
    dtxt_puts(r, "\r\n");

    /* 7. NVRAM Variables */
    dtxt_puts(r, "[7] UEFI NVRAM VARIABLES\r\n");
    dtxt_puts(r, "------------------------------------------------------------------------\r\n");
    for (UINTN i = 0; i < gVarCount; i++) {
        const NVRAM_VAR_ENTRY *v = &gVarList[i];
        CHAR8 gstr[40];
        guid_to_str(&v->guid, gstr, sizeof(gstr));
        dtxt_printf(r, "  [%03u] %-28s {%s} Attr=0x%02X %6uB  %s\r\n",
                    (UINT32)i, v->name, gstr, v->attributes, (UINT32)v->data_size, v->preview_str);
    }
    dtxt_puts(r, "\r\n");

    /* 8. Intel ME / Boot Guard / AMD PSP, SPI Flash Locks & FIVR Undervolt */
    unlock_append_report_section(dtxt_put_cb, r);
}

static VOID build_hii_decoded_report(DYN_TEXT *h) {
    dtxt_puts(h, "========================================================================\r\n");
    dtxt_puts(h, "  Oh my EFI! - Decoded HII / IFR Options Dump\r\n");
    dtxt_puts(h, "  Decoded motherboard HII VarStore names, VarOffsets, widths & options.\r\n");
    dtxt_puts(h, "========================================================================\r\n\r\n");

    dtxt_printf(h, "HII Package Lists : %u (+%u extracted from Firmware Volumes FV2)\r\n",
                (UINT32)gHw.hii_pkg_list_count, (UINT32)gHw.hii_fv_pkg_count);
    dtxt_printf(h, "IFR FormSets      : %u\r\n", (UINT32)gHw.hii_formset_count);
    dtxt_printf(h, "IFR VarStores     : %u\r\n", (UINT32)gHw.hii_varstore_count);
    dtxt_printf(h, "Decoded Questions : %u (%u Hidden/Suppressed)\r\n\r\n",
                (UINT32)gHw.hii_question_count, (UINT32)gHw.hii_hidden_count);

    dtxt_puts(h, "--- IFR VARSTORES ---\r\n");
    for (UINTN i = 0; i < gHw.hii_varstore_count; i++) {
        const HW_HII_VARSTORE_INFO *vs = &gHw.hii_varstores[i];
        CHAR8 gstr[40];
        guid_to_str(&vs->guid, gstr, sizeof(gstr));
        dtxt_printf(h, "  VarStore[0x%04X] Name=\"%s\" GUID={%s} Size=0x%04X (%uB) Type=%s\r\n",
                    (UINT32)vs->varstore_id, vs->name, gstr,
                    (UINT32)vs->size, (UINT32)vs->size,
                    vs->is_efi_varstore ? "EfiVarStore" : "BufferVarStore");
    }
    dtxt_puts(h, "\r\n--- DECODED IFR QUESTIONS & VAROFFSETS ---\r\n");

    if (!gHw.hii_questions || gHw.hii_question_count == 0) {
        dtxt_puts(h, "  (No IFR OneOf/CheckBox/Numeric questions exported in HII Database)\r\n");
        return;
    }

    for (UINTN i = 0; i < gHw.hii_question_count; i++) {
        const HW_HII_QUESTION *q = &gHw.hii_questions[i];
        const CHAR8 *vs_name = (q->varstore_idx >= 0 && (UINTN)q->varstore_idx < gHw.hii_varstore_count)
                               ? gHw.hii_varstores[q->varstore_idx].name : "Unknown";
        const CHAR8 *qt = (q->qtype == HII_QTYPE_ONE_OF) ? "OneOf" :
                          (q->qtype == HII_QTYPE_CHECKBOX) ? "CheckBox" : "Numeric";
        UINT64 cur_v = 0;
        BOOLEAN in_nv = FALSE;
        hw_hii_read_question_val(i, &cur_v, &in_nv);

        dtxt_printf(h, "[Q#%04u] [%s] (%s)%s%s \"%s\"\r\n",
                    (UINT32)i, q->formset_title, qt,
                    q->is_suppressed ? " [HIDDEN/SUPPRESSED]" : "",
                    q->is_grayout ? " [GRAYOUT]" : "",
                    q->prompt);
        if (q->help[0]) {
            dtxt_printf(h, "        Help     : %s\r\n", q->help);
        }
        if (q->is_bitfield) {
            UINTN b_off = (UINTN)q->var_offset / 8U;
            UINTN b_lo  = (UINTN)q->var_offset % 8U;
            UINTN b_hi  = b_lo + (q->width ? q->width : 1U) - 1U;
            if (in_nv) {
                dtxt_printf(h, "        Location : VarStore=\"%s\" (ID 0x%04X) | BitOffset=0x%04X (Byte 0x%04X[%u:%u]) | Width=%ub | Current=0x%lX [EDK2 Bit-VarStore]\r\n",
                            vs_name, (UINT32)q->varstore_id, (UINT32)q->var_offset,
                            (UINT32)b_off, (UINT32)b_hi, (UINT32)b_lo, (UINT32)q->width, cur_v);
            } else {
                dtxt_printf(h, "        Location : VarStore=\"%s\" (ID 0x%04X) | BitOffset=0x%04X (Byte 0x%04X[%u:%u]) | Width=%ub | Current=<Not in NVRAM> [EDK2 Bit-VarStore]\r\n",
                            vs_name, (UINT32)q->varstore_id, (UINT32)q->var_offset,
                            (UINT32)b_off, (UINT32)b_hi, (UINT32)b_lo, (UINT32)q->width);
            }
        } else if (in_nv) {
            dtxt_printf(h, "        Location : VarStore=\"%s\" (ID 0x%04X) | VarOffset=0x%04X | Width=%uB | Current=0x%lX\r\n",
                        vs_name, (UINT32)q->varstore_id, (UINT32)q->var_offset, (UINT32)q->width, cur_v);
            dtxt_printf(h, "        setup_var: setup_var_cv %s 0x%04X 0x%02X 0x%02lX\r\n",
                        vs_name, (UINT32)q->var_offset, (UINT32)q->width, cur_v);
        } else {
            dtxt_printf(h, "        Location : VarStore=\"%s\" (ID 0x%04X) | VarOffset=0x%04X | Width=%uB | Current=<Not in NVRAM>\r\n",
                        vs_name, (UINT32)q->varstore_id, (UINT32)q->var_offset, (UINT32)q->width);
        }
        if (q->qtype == HII_QTYPE_NUMERIC) {
            dtxt_printf(h, "        Range    : Min=0x%lX (%lu), Max=0x%lX (%lu), Step=0x%lX\r\n",
                        q->min_val, q->min_val, q->max_val, q->max_val, q->step_val);
        }
        for (UINT8 oi = 0; oi < q->opt_count; oi++) {
            BOOLEAN active = (in_nv && cur_v == q->opts[oi].value);
            dtxt_printf(h, "          %s 0x%02lX = %s\r\n",
                        active ? "(*)" : "( )", q->opts[oi].value, q->opts[oi].label);
        }
        dtxt_puts(h, "\r\n");
    }
}

BOOLEAN dump_everything_to_boot_dir(CHAR8 *summary_out, UINTN max_summary) {
    EFI_FILE_PROTOCOL *root     = NULL;
    EFI_FILE_PROTOCOL *boot_dir = NULL;
    EFI_FILE_PROTOCOL *dump_dir = NULL;
    CHAR8 disp_path[128];

    if (!open_writable_dump_dirs(&root, &boot_dir, &dump_dir, disp_path, sizeof(disp_path))) {
        if (summary_out) {
            str_cpy(summary_out,
                    "Could not open a writable FAT/EFI directory on boot media or any mounted volume.",
                    max_summary);
        }
        return FALSE;
    }

    UINTN saved_files = 0;
    nvram_enumerate_all();

    /* 1. Full System & Feature-Unlock Text Report (saved right in BootDir AND in OhMyEFI_Dump!) */
    draw_dump_progress("Generating OhMyEFI_Report.txt (Specs, CPUID, MSRs, PCI, Vars)...", saved_files);
    DYN_TEXT rep;
    if (dtxt_init(&rep, 131072U)) {
        build_full_system_report(&rep, disp_path);
        if (write_file_in_dir(boot_dir, L"OhMyEFI_Report.txt", rep.buf, rep.len)) saved_files++;
        if (write_file_in_dir(dump_dir, L"OhMyEFI_Report.txt", rep.buf, rep.len)) saved_files++;
        dtxt_free(&rep);
    }

    /* 2. Raw HII / IFR Binary Packages (for ifrextractor) + Decoded IFR Offset Guide */
    draw_dump_progress("Exporting HII_IFR_Packages.bin & HII_Decoded_Options.txt...", saved_files);
    UINT8 *hii_raw = NULL;
    UINTN hii_sz = 0;
    if (!EFI_ERROR(hw_export_raw_hii_packages(&hii_raw, &hii_sz)) && hii_raw && hii_sz > 0) {
        if (write_file_in_dir(dump_dir, L"HII_IFR_Packages.bin", hii_raw, hii_sz)) saved_files++;
        free_pool(hii_raw);
    }
    DYN_TEXT hii_txt;
    if (dtxt_init(&hii_txt, 65536U)) {
        build_hii_decoded_report(&hii_txt);
        if (write_file_in_dir(dump_dir, L"HII_Decoded_Options.txt", hii_txt.buf, hii_txt.len)) saved_files++;
        dtxt_free(&hii_txt);
    }

    /* 3. Raw SMBIOS Binary Table */
    draw_dump_progress("Saving raw SMBIOS_Table.bin...", saved_files);
    if (gHw.smbios_present && gHw.smbios_table_addr != 0 && gHw.smbios_table_size > 0 &&
        gHw.smbios_table_size <= 0x100000U) {
        UINT8 *sm_buf = (UINT8 *)alloc_pool(gHw.smbios_table_size);
        if (sm_buf) {
            if (safe_read_mem(gHw.smbios_table_addr, sm_buf, gHw.smbios_table_size)) {
                if (write_file_in_dir(dump_dir, L"SMBIOS_Table.bin", sm_buf, gHw.smbios_table_size))
                    saved_files++;
            }
            free_pool(sm_buf);
        }
    }

    /* 4. Raw ACPI Binary Tables (.aml) */
    draw_dump_progress("Dumping ACPI DSDT / FACP / APIC / SSDT (.aml) tables...", saved_files);
    for (UINTN i = 0; i < gHw.acpi_count; i++) {
        const HW_ACPI_TABLE_INFO *ti = &gHw.acpi_tables[i];
        if (ti->phys_addr == 0 || ti->length == 0 || ti->length > 0x200000U) continue;
        UINT8 *abuf = (UINT8 *)alloc_pool(ti->length);
        if (!abuf) continue;
        if (safe_read_mem(ti->phys_addr, abuf, ti->length)) {
            CHAR8 sig_clean[8];
            sanitize_filename_ascii(ti->signature, sig_clean, sizeof(sig_clean));
            CHAR16 afname[48];
            wsnprintf(afname, 48, "ACPI_%02u_%s.aml", (UINT32)i, sig_clean);
            if (write_file_in_dir(dump_dir, afname, abuf, ti->length)) saved_files++;
        }
        free_pool(abuf);
    }

    /* 5. Raw NVRAM VarStore Binary Dumps (Setup, SaSetup, CpuSetup, Platform, Boot, Apple, etc.) */
    draw_dump_progress("Dumping NVRAM Setup / Platform / Boot VarStore binaries...", saved_files);
    UINTN var_dumped = 0;
    for (UINTN i = 0; i < gVarCount && var_dumped < 128; i++) {
        const NVRAM_VAR_ENTRY *v = &gVarList[i];
        if (v->data_size == 0 || v->data_size > 65536U) continue;
        UINT8 *vdata = NULL;
        UINTN vsz = 0;
        if (!EFI_ERROR(nvram_read_var(v->name_w, (EFI_GUID *)&v->guid, NULL, &vsz, &vdata)) && vdata && vsz > 0) {
            CHAR8 clean_nm[36];
            sanitize_filename_ascii(v->name, clean_nm, sizeof(clean_nm));
            CHAR16 vfname[64];
            wsnprintf(vfname, 64, "Var_%s_%08X.bin", clean_nm, v->guid.Data1);
            if (write_file_in_dir(dump_dir, vfname, vdata, vsz)) {
                saved_files++;
                var_dumped++;
            }
            free_pool(vdata);
        }
    }

    if (dump_dir->Flush) dump_dir->Flush(dump_dir);
    dump_dir->Close(dump_dir);
    if (boot_dir && boot_dir != root) {
        if (boot_dir->Flush) boot_dir->Flush(boot_dir);
        boot_dir->Close(boot_dir);
    }
    if (root->Flush) root->Flush(root);
    root->Close(root);

    if (summary_out) {
        snprintf_ascii(summary_out, max_summary,
            "Successfully dumped %u files!\n"
            "Location: %s\n"
            "Includes: OhMyEFI_Report.txt, HII_IFR_Packages.bin, HII_Decoded_Options.txt, "
            "SMBIOS_Table.bin, %u ACPI .aml tables, and %u NVRAM .bin varstores.",
            (UINT32)saved_files, disp_path, (UINT32)gHw.acpi_count, (UINT32)var_dumped);
    }
    return TRUE;
}

VOID dump_run_interactive_modal(VOID) {
    if (!ui_confirm_modal(
            "EFI Dump",
            "Save EFI Dump (hardware report, HII/IFR packages, ACPI .aml, SMBIOS & NVRAM) to boot directory?",
            TRUE)) {
        return;
    }
    CHAR8 summary[320];
    BOOLEAN ok = dump_everything_to_boot_dir(summary, sizeof(summary));
    ui_force_redraw();
    ui_message_modal(ok ? "EFI Dump Complete" : "EFI Dump Failed", summary, !ok);
}
