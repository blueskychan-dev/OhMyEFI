#include "memscan.h"
#include "debug.h"
#include "hwinfo.h"
#include "nvram.h"
#include "ui.h"
#include "util.h"

MEMSCAN_STATE gMemScan;

static UINTN gMsCursor = 0;
static UINTN gMsScroll = 0;
static BOOLEAN gMsViewingHits = FALSE;
static UINTN gHitsCursor = 0;
static UINTN gHitsScroll = 0;
static CHAR8 gMsLastStatus[80] = "Ready - Select a Firmware Target or Run a Custom Scan";

static const CHAR8 *kScanTypeNames[SCAN_TYPE_COUNT] = {
    "ASCII String",
    "UTF-16LE Wide String",
    "Hex Byte Pattern",
    "8-bit Byte (UInt8)",
    "16-bit Word (UInt16)",
    "32-bit DWord (UInt32)",
    "64-bit QWord (UInt64)"
};

static const CHAR8 *kScanScopeNames[SCAN_SCOPE_COUNT] = {
    "Firmware Persist (ACPI+RT_Data)",
    "ACPI Tables & ACPI NVS Only",
    "Firmware + DXE Heap (ACPI+RT+BS)",
    "All Safe Mapped RAM (excl. MMIO)"
};

static VOID add_target(
    MEMSCAN_TARGET_KIND kind,
    const CHAR8 *cat,
    const CHAR8 *name,
    UINT64 addr,
    UINT64 len,
    UINTN aux,
    BOOLEAN writable,
    const CHAR8 *detail
) {
    if (gMemScan.target_count >= MEMSCAN_MAX_TARGETS) return;
    MEMSCAN_MOD_TARGET *t = &gMemScan.targets[gMemScan.target_count++];
    memset(t, 0, sizeof(*t));
    t->kind      = kind;
    t->phys_addr = addr;
    t->length    = len;
    t->aux_index = aux;
    t->writable  = writable;
    str_cpy(t->category, cat, sizeof(t->category));
    str_cpy(t->name, name, sizeof(t->name));
    str_cpy(t->detail, detail, sizeof(t->detail));
}

VOID memscan_discover_targets(VOID) {
    gMemScan.target_count = 0;
    cpu_invalidate_probe_cache();
    hw_refresh_acpi_status();

    /* 1. SMBIOS Live Strings & Table in RAM */
    if (gHw.smbios_present && gHw.smbios_table_addr != 0) {
        BOOLEAN m = FALSE, w = FALSE;
        cpu_probe_address(gHw.smbios_table_addr, &m, &w);
        CHAR8 det[48];
        snprintf_ascii(det, sizeof(det), "SMBIOS %u.%u (%uB) %s",
                       gHw.smbios_major, gHw.smbios_minor, gHw.smbios_table_size,
                       w ? "[RAM RW]" : "[ROM RO]");
        add_target(TARGET_KIND_SMBIOS_TBL, "SMBIOS", "SMBIOS Structure Table",
                   gHw.smbios_table_addr, gHw.smbios_table_size, 0, w, det);

        if (gHw.sys_serial_ram_addr && gHw.sys_serial_ram_maxlen > 0) {
            cpu_probe_address(gHw.sys_serial_ram_addr, &m, &w);
            snprintf_ascii(det, sizeof(det), "\"%s\" (max %u ch)",
                           gHw.sys_serial, (UINT32)gHw.sys_serial_ram_maxlen);
            add_target(TARGET_KIND_SMBIOS_STR, "SMBIOS_Str", "System Serial Number",
                       gHw.sys_serial_ram_addr, gHw.sys_serial_ram_maxlen, 1, w, det);
        }
        if (gHw.sys_product_ram_addr && gHw.sys_product_ram_maxlen > 0) {
            cpu_probe_address(gHw.sys_product_ram_addr, &m, &w);
            snprintf_ascii(det, sizeof(det), "\"%s\" (max %u ch)",
                           gHw.sys_product, (UINT32)gHw.sys_product_ram_maxlen);
            add_target(TARGET_KIND_SMBIOS_STR, "SMBIOS_Str", "System Product Name",
                       gHw.sys_product_ram_addr, gHw.sys_product_ram_maxlen, 2, w, det);
        }
        if (gHw.board_serial_ram_addr && gHw.board_serial_ram_maxlen > 0) {
            cpu_probe_address(gHw.board_serial_ram_addr, &m, &w);
            snprintf_ascii(det, sizeof(det), "\"%s\" (max %u ch)",
                           gHw.board_serial, (UINT32)gHw.board_serial_ram_maxlen);
            add_target(TARGET_KIND_SMBIOS_STR, "SMBIOS_Str",
                       gHw.is_apple_mac ? "Logic Board Serial / MLB" : "Baseboard Serial Number",
                       gHw.board_serial_ram_addr, gHw.board_serial_ram_maxlen, 3, w, det);
        }
        if (gHw.bios_ver_ram_addr && gHw.bios_ver_ram_maxlen > 0) {
            cpu_probe_address(gHw.bios_ver_ram_addr, &m, &w);
            snprintf_ascii(det, sizeof(det), "\"%s\" (max %u ch)",
                           gHw.bios_version, (UINT32)gHw.bios_ver_ram_maxlen);
            add_target(TARGET_KIND_SMBIOS_STR, "SMBIOS_Str", "BIOS / EFI Version Str",
                       gHw.bios_ver_ram_addr, gHw.bios_ver_ram_maxlen, 4, w, det);
        }
    }

    /* 2. ACPI Tables in RAM (DSDT, FACP, SSDT, MCFG, APIC, etc.) */
    for (UINTN i = 0; i < gHw.acpi_count; i++) {
        const HW_ACPI_TABLE_INFO *ti = &gHw.acpi_tables[i];
        CHAR8 tname[32], det[48];
        snprintf_ascii(tname, sizeof(tname), "ACPI %s (%s)",
                       ti->signature, ti->oem_table_id[0] ? ti->oem_table_id : ti->oem_id);
        snprintf_ascii(det, sizeof(det), "%uB %s %s",
                       ti->length,
                       ti->checksum_ok ? "[CSUM:OK]" : "[CSUM:BAD]",
                       ti->writable ? "[RW]" : "[RO]");
        add_target(TARGET_KIND_ACPI_TBL, "ACPI_Tbl", tname,
                   ti->phys_addr, ti->length, i, ti->writable, det);
    }

    /* 3. ACPI NVS (GNVS) & Runtime Services Data Regions from Memory Map */
    if (gBS && gBS->GetMemoryMap) {
        UINTN msz = 0, mkey = 0, dsz = 0;
        UINT32 dver = 0;
        if (gBS->GetMemoryMap(&msz, NULL, &mkey, &dsz, &dver) == EFI_BUFFER_TOO_SMALL && msz > 0) {
            msz += 8 * (dsz ? dsz : sizeof(EFI_MEMORY_DESCRIPTOR));
            UINT8 *mbuf = (UINT8 *)alloc_pool(msz);
            if (mbuf && !EFI_ERROR(gBS->GetMemoryMap(&msz, (EFI_MEMORY_DESCRIPTOR *)mbuf, &mkey, &dsz, &dver))) {
                UINTN nvs_idx = 0, rt_idx = 0;
                for (UINTN off = 0; off + dsz <= msz; off += dsz) {
                    const EFI_MEMORY_DESCRIPTOR *d = (const EFI_MEMORY_DESCRIPTOR *)(mbuf + off);
                    if (d->PhysicalStart < 0x1000ULL || d->NumberOfPages == 0) continue;
                    UINT64 bytes = d->NumberOfPages << 12;
                    BOOLEAN mp = FALSE, wr = FALSE;
                    if (!cpu_probe_address(d->PhysicalStart, &mp, &wr) || !mp) continue;

                    if (d->Type == EfiACPIMemoryNVS && nvs_idx < 12) {
                        CHAR8 nm[32], det[48];
                        snprintf_ascii(nm, sizeof(nm), "ACPI NVS Region #%u", (UINT32)nvs_idx++);
                        snprintf_ascii(det, sizeof(det), "%lu KB Firmware NVS %s",
                                       bytes >> 10, wr ? "[RW]" : "[RO]");
                        add_target(TARGET_KIND_ACPI_NVS, "ACPI_NVS", nm,
                                   d->PhysicalStart, bytes, 0, wr, det);
                    } else if (d->Type == EfiRuntimeServicesData && rt_idx < 8) {
                        CHAR8 nm[32], det[48];
                        snprintf_ascii(nm, sizeof(nm), "EFI Runtime Data #%u", (UINT32)rt_idx++);
                        snprintf_ascii(det, sizeof(det), "%lu KB RT_Data %s",
                                       bytes >> 10, wr ? "[RW]" : "[RO]");
                        add_target(TARGET_KIND_RT_DATA, "RT_Data", nm,
                                   d->PhysicalStart, bytes, 0, wr, det);
                    }
                }
            }
            free_pool(mbuf);
        }
    }

    /* 4. Modifiable Firmware Setup / Boot / Platform NVRAM VarStores */
    nvram_enumerate_all();
    for (UINTN i = 0; i < gVarCount && gMemScan.target_count < MEMSCAN_MAX_TARGETS; i++) {
        const NVRAM_VAR_ENTRY *v = &gVarList[i];
        if (!v->is_writable_hint || v->data_size == 0) continue;

        /* Highlight Setup VarStores, HII-linked stores, Boot, and Apple vars */
        BOOLEAN interesting = FALSE;
        if (str_contains_icase(v->name, "Setup") ||
            str_contains_icase(v->name, "Cfg") ||
            str_contains_icase(v->name, "Config") ||
            str_contains_icase(v->name, "Pch") ||
            str_contains_icase(v->name, "Cpu") ||
            str_contains_icase(v->name, "SaSetup") ||
            str_cmp(v->name, "BootOrder") == 0 ||
            str_cmp(v->name, "Timeout") == 0 ||
            str_cmp(v->name, "boot-args") == 0 ||
            str_cmp(v->name, "csr-active-config") == 0 ||
            str_cmp(v->name, "SystemAudioVolume") == 0 ||
            str_cmp(v->name, "gpu-power-prefs") == 0) {
            interesting = TRUE;
        }
        for (UINTN h = 0; h < gHw.hii_varstore_count && !interesting; h++) {
            if (str_icmp(v->name, gHw.hii_varstores[h].name) == 0) {
                interesting = TRUE;
            }
        }
        if (interesting) {
            CHAR8 det[48];
            const CHAR8 *gname = guid_friendly_name(&v->guid);
            snprintf_ascii(det, sizeof(det), "%uB [%s] %s",
                           (UINT32)v->data_size,
                           gname ? gname : "VendorVar",
                           v->preview_str);
            add_target(TARGET_KIND_NVRAM_VAR, "NVRAM_Var", v->name,
                       0, v->data_size, i, TRUE, det);
        }
    }
}

VOID memscan_init(VOID) {
    memset(&gMemScan, 0, sizeof(gMemScan));
    gMemScan.data_type = SCAN_TYPE_ASCII;
    gMemScan.scope     = SCAN_SCOPE_FW_PERSIST;
    gMemScan.hits_alloc_size = sizeof(MEMSCAN_HIT) * MEMSCAN_MAX_HITS;
    gMemScan.hits = (MEMSCAN_HIT *)alloc_zero_pool(gMemScan.hits_alloc_size);
    memscan_discover_targets();
}

static BOOLEAN encode_query_to_pattern(
    MEMSCAN_DATA_TYPE dtype,
    const CHAR8 *q,
    UINT8 *out_pat,
    UINTN *out_len
) {
    if (!q || !q[0] || !out_pat || !out_len) return FALSE;
    *out_len = 0;

    if (dtype == SCAN_TYPE_ASCII) {
        UINTN l = str_len(q);
        if (l == 0 || l > 60) return FALSE;
        memcpy(out_pat, q, l);
        *out_len = l;
        return TRUE;
    } else if (dtype == SCAN_TYPE_UTF16) {
        UINTN l = str_len(q);
        if (l == 0 || l > 30) return FALSE;
        for (UINTN i = 0; i < l; i++) {
            out_pat[i * 2 + 0] = (UINT8)q[i];
            out_pat[i * 2 + 1] = 0x00;
        }
        *out_len = l * 2;
        return TRUE;
    } else if (dtype == SCAN_TYPE_HEX) {
        UINTN n = parse_hex_bytes(q, out_pat, 60);
        if (n == 0) return FALSE;
        *out_len = n;
        return TRUE;
    } else {
        UINT64 val = 0;
        if (!parse_dec_u64(q, &val)) return FALSE;
        UINTN sz = 1;
        if (dtype == SCAN_TYPE_UINT8)  sz = 1;
        if (dtype == SCAN_TYPE_UINT16) sz = 2;
        if (dtype == SCAN_TYPE_UINT32) sz = 4;
        if (dtype == SCAN_TYPE_UINT64) sz = 8;
        for (UINTN i = 0; i < sz; i++) {
            out_pat[i] = (UINT8)((val >> (i * 8)) & 0xFFULL);
        }
        *out_len = sz;
        return TRUE;
    }
}

static BOOLEAN region_in_scope(UINT32 mtype, MEMSCAN_SCOPE scope) {
    if (mtype == EfiACPIReclaimMemory || mtype == EfiACPIMemoryNVS) {
        return TRUE;
    }
    if (scope == SCAN_SCOPE_ACPI_ONLY) return FALSE;

    if (mtype == EfiRuntimeServicesData) {
        return TRUE;
    }
    if (scope == SCAN_SCOPE_FW_PERSIST) return FALSE;

    if (mtype == EfiBootServicesData) {
        return TRUE;
    }
    if (scope == SCAN_SCOPE_FW_ALL) return FALSE;

    if (mtype == EfiConventionalMemory || mtype == EfiLoaderData) {
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN overlaps_self_buffers(UINT64 addr, UINTN len) {
    UINT64 end = addr + len;
    /* Skip our own loaded .efi image (code + static globals incl. gMemScan) */
    if (gHw.image_base != 0 && gHw.image_size != 0) {
        if (end > gHw.image_base && addr < (gHw.image_base + gHw.image_size)) {
            return TRUE;
        }
    }
    /* Skip our dynamically allocated hits buffer */
    if (gMemScan.hits != NULL) {
        UINT64 hb = (UINT64)(UINTN)gMemScan.hits;
        UINT64 he = hb + gMemScan.hits_alloc_size;
        if (end > hb && addr < he) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN match_at_ptr(const volatile UINT8 *p, const UINT8 *pat, UINTN plen, BOOLEAN icase_ascii) {
    if (!icase_ascii) {
        for (UINTN i = 0; i < plen; i++) {
            if (p[i] != pat[i]) return FALSE;
        }
        return TRUE;
    }
    for (UINTN i = 0; i < plen; i++) {
        UINT8 a = p[i];
        UINT8 b = pat[i];
        if (a >= 'A' && a <= 'Z') a = (UINT8)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (UINT8)(b + 32);
        if (a != b) return FALSE;
    }
    return TRUE;
}

BOOLEAN memscan_run_first_scan(const CHAR8 *query_str, CHAR8 *status_out, UINTN max_status) {
    if (!gMemScan.hits || !gBS || !gBS->GetMemoryMap) return FALSE;

    UINT8 pat[64];
    UINTN plen = 0;
    if (!encode_query_to_pattern(gMemScan.data_type, query_str, pat, &plen)) {
        if (status_out) str_cpy(status_out, "Invalid search value/pattern format.", max_status);
        return FALSE;
    }

    str_cpy(gMemScan.last_query, query_str, sizeof(gMemScan.last_query));
    memcpy(gMemScan.pattern, pat, plen);
    gMemScan.pattern_len         = plen;
    gMemScan.hit_count           = 0;
    gMemScan.total_matches_found = 0;
    gMemScan.bytes_scanned       = 0;
    cpu_invalidate_probe_cache();

    UINTN msz = 0, mkey = 0, dsz = 0;
    UINT32 dver = 0;
    if (gBS->GetMemoryMap(&msz, NULL, &mkey, &dsz, &dver) != EFI_BUFFER_TOO_SMALL || msz == 0) {
        if (status_out) str_cpy(status_out, "GetMemoryMap failed.", max_status);
        return FALSE;
    }
    msz += 8 * (dsz ? dsz : sizeof(EFI_MEMORY_DESCRIPTOR));
    UINT8 *mbuf = (UINT8 *)alloc_pool(msz);
    if (!mbuf) return FALSE;

    if (EFI_ERROR(gBS->GetMemoryMap(&msz, (EFI_MEMORY_DESCRIPTOR *)mbuf, &mkey, &dsz, &dver))) {
        free_pool(mbuf);
        return FALSE;
    }

    BOOLEAN icase = (gMemScan.data_type == SCAN_TYPE_ASCII);
    UINT64 next_ui_tick = 0x400000ULL; /* Update progress modal every 4 MB */
    BOOLEAN aborted = FALSE;

    for (UINTN off = 0; off + dsz <= msz && !aborted; off += dsz) {
        const EFI_MEMORY_DESCRIPTOR *d = (const EFI_MEMORY_DESCRIPTOR *)(mbuf + off);
        if (!region_in_scope(d->Type, gMemScan.scope) || d->NumberOfPages == 0) continue;

        UINT64 r_start = d->PhysicalStart;
        UINT64 r_end   = r_start + (d->NumberOfPages << 12);
        if (r_start < 0x1000ULL) r_start = 0x1000ULL;
#if !defined(__x86_64__) && !defined(_M_X64)
        if (r_start >= 0xFFFFFFFFULL) continue;
        if (r_end > 0xFFFFFFFFULL) r_end = 0xFFFFFFFFULL;
#endif
        /* Cap All-RAM scan at 2048 MB unless user aborts early with ESC */
        if (gMemScan.bytes_scanned > (2048ULL << 20)) break;

        for (UINT64 page = r_start; page < r_end && !aborted; page += 0x1000ULL) {
            if (overlaps_self_buffers(page, 0x1000U)) continue;

            BOOLEAN mapped = FALSE, writable = FALSE;
            if (!cpu_probe_address(page, &mapped, &writable) || !mapped) continue;

            /* Also ensure next page is mapped if matching across page boundary */
            UINTN page_limit = 0x1000U;
            if (page + 0x1000ULL < r_end && !overlaps_self_buffers(page + 0x1000ULL, plen)) {
                BOOLEAN m2 = FALSE;
                if (cpu_probe_address(page + 0x1000ULL, &m2, NULL) && m2) {
                    page_limit = 0x1000U + plen - 1;
                }
            }
            if (page_limit < plen) continue;
            UINTN max_off = page_limit - plen;

            const volatile UINT8 *pbase = (const volatile UINT8 *)(UINTN)page;
            UINT8 first_b = pat[0];
            UINT8 first_lo = (first_b >= 'A' && first_b <= 'Z') ? (UINT8)(first_b + 32) : first_b;
            UINT8 first_hi = (first_b >= 'a' && first_b <= 'z') ? (UINT8)(first_b - 32) : first_b;

            for (UINTN bo = 0; bo <= max_off; bo++) {
                UINT8 b0 = pbase[bo];
                if (icase) {
                    if (b0 != first_lo && b0 != first_hi) continue;
                } else {
                    if (b0 != first_b) continue;
                }

                if (match_at_ptr(pbase + bo, pat, plen, icase)) {
                    gMemScan.total_matches_found++;
                    if (gMemScan.hit_count < MEMSCAN_MAX_HITS) {
                        MEMSCAN_HIT *h = &gMemScan.hits[gMemScan.hit_count++];
                        h->addr     = page + bo;
                        h->mem_type = d->Type;
                        h->writable = writable;
                        memset(h->cur_bytes, 0, 8);
                        UINTN cp = (plen < 8) ? plen : 8;
                        for (UINTN k = 0; k < cp; k++) h->cur_bytes[k] = pbase[bo + k];
                        memcpy(h->prev_bytes, h->cur_bytes, 8);
                    }
                }
            }

            gMemScan.bytes_scanned += 0x1000ULL;
            if (gMemScan.bytes_scanned >= next_ui_tick) {
                next_ui_tick = gMemScan.bytes_scanned + 0x400000ULL;
                /* Draw lightweight progress box and check ESC key */
                UINTN mw = 52, mh = 6;
                UINTN mx = (gUiCols - mw) / 2, my = (gUiRows - mh) / 2;
                ui_draw_box(mx, my, mw, mh, gTheme.modal_border_attr, gTheme.modal_attr, TRUE);
                ui_puts(mx + 2, my, "[ Scanning UEFI Physical Memory ]", gTheme.modal_border_attr);
                ui_printf(mx + 3, my + 2, gTheme.modal_attr,
                          "Scanned: %lu MB   Matches: %u",
                          gMemScan.bytes_scanned >> 20, (UINT32)gMemScan.total_matches_found);
                ui_puts(mx + 3, my + 3, "Press ESC to stop early with current results", gTheme.modal_attr);
                ui_present();

                EFI_INPUT_KEY key;
                if (gST->ConIn->ReadKeyStroke(gST->ConIn, &key) == EFI_SUCCESS) {
                    if (key.ScanCode == SCAN_ESC || key.UnicodeChar == 0x1B) {
                        aborted = TRUE;
                    }
                }
            }
        }
    }

    free_pool(mbuf);
    if (status_out) {
        snprintf_ascii(status_out, max_status,
            "%sScanned %lu KB -> %u match(es) (showing %u).",
            aborted ? "[Stopped] " : "",
            gMemScan.bytes_scanned >> 10,
            (UINT32)gMemScan.total_matches_found,
            (UINT32)gMemScan.hit_count);
    }
    return TRUE;
}

BOOLEAN memscan_run_next_exact(const CHAR8 *query_str, CHAR8 *status_out, UINTN max_status) {
    if (!gMemScan.hits || gMemScan.hit_count == 0) {
        if (status_out) str_cpy(status_out, "No active hits to filter. Run New Scan first.", max_status);
        return FALSE;
    }
    UINT8 pat[64];
    UINTN plen = 0;
    if (!encode_query_to_pattern(gMemScan.data_type, query_str, pat, &plen)) {
        if (status_out) str_cpy(status_out, "Invalid filter value/pattern.", max_status);
        return FALSE;
    }

    str_cpy(gMemScan.last_query, query_str, sizeof(gMemScan.last_query));
    BOOLEAN icase = (gMemScan.data_type == SCAN_TYPE_ASCII);
    UINTN kept = 0;

    for (UINTN i = 0; i < gMemScan.hit_count; i++) {
        MEMSCAN_HIT *h = &gMemScan.hits[i];
        UINT8 live[64];
        if (!safe_read_mem(h->addr, live, plen)) continue;
        if (match_at_ptr(live, pat, plen, icase)) {
            MEMSCAN_HIT *dst = &gMemScan.hits[kept++];
            *dst = *h;
            memcpy(dst->prev_bytes, dst->cur_bytes, 8);
            UINTN cp = (plen < 8) ? plen : 8;
            memcpy(dst->cur_bytes, live, cp);
        }
    }
    gMemScan.hit_count           = kept;
    gMemScan.total_matches_found = kept;
    gMemScan.pattern_len         = plen;
    memcpy(gMemScan.pattern, pat, plen);

    if (status_out) {
        snprintf_ascii(status_out, max_status, "Next Scan (Exact): %u address(es) remain.", (UINT32)kept);
    }
    return TRUE;
}

UINTN memscan_run_next_diff(BOOLEAN changed_only, CHAR8 *status_out, UINTN max_status) {
    if (!gMemScan.hits || gMemScan.hit_count == 0) {
        if (status_out) str_cpy(status_out, "No active hits. Run New Scan first.", max_status);
        return 0;
    }
    UINTN check_len = (gMemScan.pattern_len > 0 && gMemScan.pattern_len <= 8) ? gMemScan.pattern_len : 8;
    UINTN kept = 0;

    for (UINTN i = 0; i < gMemScan.hit_count; i++) {
        MEMSCAN_HIT *h = &gMemScan.hits[i];
        UINT8 live[8];
        memset(live, 0, 8);
        if (!safe_read_mem(h->addr, live, check_len)) continue;
        BOOLEAN diff = (memcmp(live, h->cur_bytes, check_len) != 0);
        if ((changed_only && diff) || (!changed_only && !diff)) {
            MEMSCAN_HIT *dst = &gMemScan.hits[kept++];
            *dst = *h;
            memcpy(dst->prev_bytes, dst->cur_bytes, 8);
            memcpy(dst->cur_bytes, live, 8);
        }
    }
    gMemScan.hit_count           = kept;
    gMemScan.total_matches_found = kept;

    if (status_out) {
        snprintf_ascii(status_out, max_status, "Next Scan (%s): %u address(es) remain.",
                       changed_only ? "Changed" : "Unchanged", (UINT32)kept);
    }
    return kept;
}

#define MS_FIXED_CONTROLS 7

static VOID draw_hits_subscreen(VOID) {
    CHAR8 sub[64];
    snprintf_ascii(sub, sizeof(sub), "Custom Memory Scan Hits (%u matches for \"%s\")",
                   (UINT32)gMemScan.hit_count, gMemScan.last_query);
    ui_draw_setup_frame(2, sub, FALSE, NULL, NULL,
                        "Enter: Open in Live Hex Editor | F: Filter Exact | C: Filter Changed | ESC: Back");

    UINTN x = 2;
    UINTN w = gUiCols - 4;
    UINTN top_y = 4;
    UINTN vis_rows = (gUiRows > 8) ? (gUiRows - 8) : 12;

    ui_puts_n(x, 3, " #   Phys Address    Region    RW     Live Bytes (Hex)         ASCII", w, gTheme.section_attr);

    if (gMemScan.hit_count == 0) {
        ui_puts_n(x + 2, top_y + 1, "No scan hits remaining. Press ESC to return and start a New Scan.", w - 4, gTheme.label_attr);
        return;
    }

    if (gHitsCursor >= gMemScan.hit_count) gHitsCursor = gMemScan.hit_count - 1;
    if (gHitsCursor < gHitsScroll) gHitsScroll = gHitsCursor;
    if (gHitsCursor >= gHitsScroll + vis_rows) gHitsScroll = gHitsCursor - vis_rows + 1;

    for (UINTN r = 0; r < vis_rows && (gHitsScroll + r) < gMemScan.hit_count; r++) {
        UINTN idx = gHitsScroll + r;
        MEMSCAN_HIT *h = &gMemScan.hits[idx];
        UINT8 live[8];
        memset(live, 0, 8);
        BOOLEAN ok = safe_read_mem(h->addr, live, 8);
        if (ok) memcpy(h->cur_bytes, live, 8);

        CHAR8 hex_part[28], asc_part[10];
        for (UINTN b = 0; b < 8; b++) {
            if (ok) {
                snprintf_ascii(hex_part + b * 3, 4, "%02X ", live[b]);
                asc_part[b] = (live[b] >= 0x20 && live[b] <= 0x7E) ? (CHAR8)live[b] : '.';
            } else {
                str_cpy(hex_part + b * 3, "-- ", 4);
                asc_part[b] = '?';
            }
        }
        hex_part[24] = '\0';
        asc_part[8]  = '\0';

        UINT8 attr = (idx == gHitsCursor) ? gTheme.item_sel_attr : gTheme.item_attr;
        ui_hline(x, top_y + r, w, L' ', attr);
        ui_printf(x, top_y + r, attr, "%3u  0x%012lX  %-8s  %-5s  %s|%s|",
                  (UINT32)idx, h->addr, efi_mem_type_short(h->mem_type),
                  h->writable ? "[RW]" : "[RO]", hex_part, asc_part);
    }
}

VOID memscan_draw_tab(VOID) {
    if (gMsViewingHits) {
        draw_hits_subscreen();
        return;
    }

    UINTN total_items = MS_FIXED_CONTROLS + gMemScan.target_count;
    if (gMsCursor >= total_items) gMsCursor = (total_items > 0) ? (total_items - 1) : 0;

    /* Context-sensitive right-panel help */
    const CHAR8 *htitle = "UEFI Memory Scanner";
    CHAR8 hbody[320];
    if (gMsCursor == 0) {
        str_cpy(hbody, "Choose the data type to scan for in UEFI RAM:\nASCII strings, UTF-16LE wide UEFI strings, raw Hex byte signatures, or 8/16/32/64-bit integers.", sizeof(hbody));
    } else if (gMsCursor == 1) {
        str_cpy(hbody, "Select which UEFI memory regions to scan.\nMMIO & unmapped guard pages are automatically skipped via CR3 page-table probing.", sizeof(hbody));
    } else if (gMsCursor <= 6) {
        snprintf_ascii(hbody, sizeof(hbody),
            "Scan physical memory like RU.efi / Cheat Engine to find modifiable tables, strings, or config flags.\nActive Hits: %u\nLast Query: %s",
            (UINT32)gMemScan.hit_count, gMemScan.last_query[0] ? gMemScan.last_query : "<none>");
    } else {
        const MEMSCAN_MOD_TARGET *t = &gMemScan.targets[gMsCursor - MS_FIXED_CONTROLS];
        htitle = t->name;
        if (t->kind == TARGET_KIND_NVRAM_VAR) {
            snprintf_ascii(hbody, sizeof(hbody),
                "Writable UEFI NVRAM VarStore\nSize: %lu bytes\n%s\n\nPress Enter to inspect/edit raw variable offsets in real NVRAM.",
                t->length, t->detail);
        } else {
            snprintf_ascii(hbody, sizeof(hbody),
                "Category: %s\nPhys Addr: 0x%lX\nLength: %lu bytes\nPage Access: %s\n%s\n\nPress Enter to inspect or live-patch in RAM.",
                t->category, t->phys_addr, t->length,
                t->writable ? "WRITABLE (RAM)" : "READ-ONLY",
                t->detail);
        }
    }

    ui_draw_setup_frame(2, NULL, TRUE, htitle, hbody, gMsLastStatus);

    UINTN split_x = (gUiCols * 2) / 3;
    if (split_x < 50 && gUiCols >= 80) split_x = 52;
    if (gUiCols - split_x < 27 && gUiCols >= 80) split_x = gUiCols - 28;
    UINTN lx = 2;
    UINTN lw = split_x - 3;

    UINTN list_top = 3;
    UINTN vis_rows = gUiRows - 5;
    if (gMsCursor < gMsScroll) gMsScroll = gMsCursor;
    if (gMsCursor >= gMsScroll + vis_rows) gMsScroll = gMsCursor - vis_rows + 1;

    for (UINTN r = 0; r < vis_rows && (gMsScroll + r) < total_items; r++) {
        UINTN idx = gMsScroll + r;
        UINTN y = list_top + r;
        BOOLEAN sel = (idx == gMsCursor);
        UINT8 attr = sel ? gTheme.item_sel_attr : gTheme.item_attr;
        ui_hline(lx, y, lw, L' ', sel ? attr : gTheme.body_attr);

        CHAR8 line[128];
        if (idx == 0) {
            snprintf_ascii(line, sizeof(line), "Scan Data Type        [%s]", kScanTypeNames[gMemScan.data_type]);
            ui_puts_n(lx, y, line, lw, attr);
        } else if (idx == 1) {
            snprintf_ascii(line, sizeof(line), "Scan Scope            [%s]", kScanScopeNames[gMemScan.scope]);
            ui_puts_n(lx, y, line, lw, attr);
        } else if (idx == 2) {
            ui_putc(lx, y, gBox.arrow_r, attr);
            ui_puts_n(lx + 2, y, "Start New Memory Scan (Value / Pattern)...", lw - 2, attr);
        } else if (idx == 3) {
            ui_putc(lx, y, gBox.arrow_r, attr);
            snprintf_ascii(line, sizeof(line), "Next Scan: Filter Exact Value (%u hits)", (UINT32)gMemScan.hit_count);
            ui_puts_n(lx + 2, y, line, lw - 2, attr);
        } else if (idx == 4) {
            ui_putc(lx, y, gBox.arrow_r, attr);
            ui_puts_n(lx + 2, y, "Next Scan: Filter Changed / Unchanged...", lw - 2, attr);
        } else if (idx == 5) {
            ui_putc(lx, y, gBox.arrow_r, attr);
            snprintf_ascii(line, sizeof(line), "Browse & Patch Scan Hits (%u matches)", (UINT32)gMemScan.hit_count);
            ui_puts_n(lx + 2, y, line, lw - 2, attr);
        } else if (idx == 6) {
            ui_putc(lx, y, gBox.arrow_r, attr);
            snprintf_ascii(line, sizeof(line), "Re-Scan Modifiable UEFI Targets (%u found)", (UINT32)gMemScan.target_count);
            ui_puts_n(lx + 2, y, line, lw - 2, attr);
        } else {
            const MEMSCAN_MOD_TARGET *t = &gMemScan.targets[idx - MS_FIXED_CONTROLS];
            if (t->kind == TARGET_KIND_NVRAM_VAR) {
                snprintf_ascii(line, sizeof(line), "[Var] %-18s %s", t->name, t->detail);
            } else {
                snprintf_ascii(line, sizeof(line), "%s %-20s @%08lX %s",
                               t->writable ? "[RW]" : "[RO]",
                               t->name, t->phys_addr, t->detail);
            }
            ui_puts_n(lx, y, line, lw, sel ? attr : (t->writable ? gTheme.item_attr : gTheme.value_attr));
        }
    }

    if (gMsScroll > 0) {
        ui_putc(split_x - 1, list_top, gBox.arrow_u, gTheme.border_attr);
    }
    if (gMsScroll + vis_rows < total_items) {
        ui_putc(split_x - 1, list_top + vis_rows - 1, gBox.arrow_d, gTheme.border_attr);
    }
}

BOOLEAN memscan_handle_key(const EFI_INPUT_KEY *k) {
    if (gMsViewingHits) {
        UINTN vis_rows = (gUiRows > 8) ? (gUiRows - 8) : 12;
        if (k->ScanCode == SCAN_ESC || k->UnicodeChar == 0x1B) {
            gMsViewingHits = FALSE;
            return TRUE;
        } else if (k->ScanCode == SCAN_UP) {
            if (gHitsCursor > 0) gHitsCursor--;
            return TRUE;
        } else if (k->ScanCode == SCAN_DOWN) {
            if (gHitsCursor + 1 < gMemScan.hit_count) gHitsCursor++;
            return TRUE;
        } else if (k->ScanCode == SCAN_PAGE_UP || k->UnicodeChar == 0x15) {
            gHitsCursor = (gHitsCursor > vis_rows) ? (gHitsCursor - vis_rows) : 0;
            return TRUE;
        } else if (k->ScanCode == SCAN_PAGE_DOWN || k->UnicodeChar == 0x04) {
            if (gHitsCursor + vis_rows < gMemScan.hit_count) gHitsCursor += vis_rows;
            else if (gMemScan.hit_count > 0) gHitsCursor = gMemScan.hit_count - 1;
            return TRUE;
        } else if ((k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') && gHitsCursor < gMemScan.hit_count) {
            debug_open_hex_editor(gMemScan.hits[gHitsCursor].addr, "Memory Scan Hit");
            return TRUE;
        } else if (k->UnicodeChar == L'f' || k->UnicodeChar == L'F') {
            CHAR8 q[64];
            if (ui_input_modal("Next Scan: Exact Value", "Enter new value/pattern to filter current hits:",
                               gMemScan.last_query, q, sizeof(q), FALSE)) {
                memscan_run_next_exact(q, gMsLastStatus, sizeof(gMsLastStatus));
                gHitsCursor = 0;
                gHitsScroll = 0;
            }
            return TRUE;
        } else if (k->UnicodeChar == L'c' || k->UnicodeChar == L'C') {
            memscan_run_next_diff(TRUE, gMsLastStatus, sizeof(gMsLastStatus));
            gHitsCursor = 0;
            gHitsScroll = 0;
            return TRUE;
        }
        return FALSE;
    }

    UINTN total_items = MS_FIXED_CONTROLS + gMemScan.target_count;
    UINTN vis_rows = gUiRows - 5;

    if (k->ScanCode == SCAN_UP) {
        gMsCursor = (gMsCursor > 0) ? (gMsCursor - 1) : (total_items - 1);
        return TRUE;
    } else if (k->ScanCode == SCAN_DOWN) {
        gMsCursor = (gMsCursor + 1 < total_items) ? (gMsCursor + 1) : 0;
        return TRUE;
    } else if (k->ScanCode == SCAN_PAGE_UP || k->UnicodeChar == 0x15) {
        gMsCursor = (gMsCursor > vis_rows) ? (gMsCursor - vis_rows) : 0;
        return TRUE;
    } else if (k->ScanCode == SCAN_PAGE_DOWN || k->UnicodeChar == 0x04) {
        gMsCursor = (gMsCursor + vis_rows < total_items) ? (gMsCursor + vis_rows) : (total_items - 1);
        return TRUE;
    } else if (k->ScanCode == SCAN_HOME) {
        gMsCursor = 0;
        return TRUE;
    } else if (k->ScanCode == SCAN_END) {
        gMsCursor = total_items - 1;
        return TRUE;
    }

    BOOLEAN plus  = (k->UnicodeChar == L'+' || k->UnicodeChar == L'=' || k->ScanCode == SCAN_F6);
    BOOLEAN minus = (k->UnicodeChar == L'-' || k->ScanCode == SCAN_F5);
    BOOLEAN enter = (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n' || k->UnicodeChar == L' ');

    if ((plus || minus || enter) && (gMsCursor == 0 || gMsCursor == 1)) {
        if (gMsCursor == 0) {
            UINTN cur = (UINTN)gMemScan.data_type;
            UINTN init_s = plus ? ((cur + 1) % SCAN_TYPE_COUNT) :
                           (minus ? ((cur + SCAN_TYPE_COUNT - 1) % SCAN_TYPE_COUNT) : cur);
            INTN c = ui_pick_option_modal("Scan Data Type", kScanTypeNames, SCAN_TYPE_COUNT, cur, init_s);
            if (c >= 0) gMemScan.data_type = (MEMSCAN_DATA_TYPE)c;
            return TRUE;
        } else {
            UINTN cur = (UINTN)gMemScan.scope;
            UINTN init_s = plus ? ((cur + 1) % SCAN_SCOPE_COUNT) :
                           (minus ? ((cur + SCAN_SCOPE_COUNT - 1) % SCAN_SCOPE_COUNT) : cur);
            INTN c = ui_pick_option_modal("Memory Scan Scope", kScanScopeNames, SCAN_SCOPE_COUNT, cur, init_s);
            if (c >= 0) gMemScan.scope = (MEMSCAN_SCOPE)c;
            return TRUE;
        }
    }

    if (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') {
        if (gMsCursor == 2) {
            CHAR8 q[64];
            const CHAR8 *prompt = "Enter search string, hex bytes (e.g. 5F 53 4D 5F), or number:";
            if (ui_input_modal("New UEFI Memory Scan", prompt, gMemScan.last_query, q, sizeof(q), FALSE)) {
                if (memscan_run_first_scan(q, gMsLastStatus, sizeof(gMsLastStatus)) && gMemScan.hit_count > 0) {
                    gHitsCursor = 0;
                    gHitsScroll = 0;
                    gMsViewingHits = TRUE;
                }
            }
        } else if (gMsCursor == 3) {
            CHAR8 q[64];
            if (ui_input_modal("Next Scan: Exact Value", "Filter active hits by new value/pattern:",
                               gMemScan.last_query, q, sizeof(q), FALSE)) {
                memscan_run_next_exact(q, gMsLastStatus, sizeof(gMsLastStatus));
                if (gMemScan.hit_count > 0) gMsViewingHits = TRUE;
            }
        } else if (gMsCursor == 4) {
            const CHAR8 *opts[2] = {
                "Filter Values That CHANGED Since Last Scan",
                "Filter Values That Remained UNCHANGED"
            };
            INTN c = ui_select_modal("Next Scan Differential Filter", opts, 2, 0);
            if (c >= 0) {
                memscan_run_next_diff(c == 0, gMsLastStatus, sizeof(gMsLastStatus));
                if (gMemScan.hit_count > 0) gMsViewingHits = TRUE;
            }
        } else if (gMsCursor == 5) {
            gHitsCursor = 0;
            gHitsScroll = 0;
            gMsViewingHits = TRUE;
        } else if (gMsCursor == 6) {
            memscan_discover_targets();
            snprintf_ascii(gMsLastStatus, sizeof(gMsLastStatus),
                           "Re-scanned UEFI tables & memory: %u modifiable targets.",
                           (UINT32)gMemScan.target_count);
        } else {
            MEMSCAN_MOD_TARGET *t = &gMemScan.targets[gMsCursor - MS_FIXED_CONTROLS];
            if (t->kind == TARGET_KIND_NVRAM_VAR) {
                debug_open_var_editor(t->aux_index);
                memscan_discover_targets();
            } else if (t->kind == TARGET_KIND_SMBIOS_STR) {
                const CHAR8 *opts[2] = {
                    "Edit SMBIOS String Safely in RAM (In-Place)",
                    "Inspect / Patch Raw Memory in Live Hex Editor"
                };
                INTN act = ui_select_modal(t->name, opts, 2, 0);
                if (act == 0) {
                    if (!t->writable) {
                        ui_message_modal("Read-Only Memory",
                            "This SMBIOS table resides in write-protected shadow RAM/ROM on this firmware.",
                            TRUE);
                    } else {
                        CHAR8 cur_val[64], new_val[64], pr[96];
                        UINTN ml = (t->length < 60) ? (UINTN)t->length : 60;
                        memset(cur_val, 0, sizeof(cur_val));
                        safe_read_mem(t->phys_addr, cur_val, ml);
                        snprintf_ascii(pr, sizeof(pr), "Enter new string (max %u chars in-place):", (UINT32)t->length);
                        if (ui_input_modal(t->name, pr, cur_val, new_val, ml + 1, FALSE)) {
                            if (hw_patch_smbios_string_in_ram(t->phys_addr, (UINTN)t->length, new_val)) {
                                hw_collect_all();
                                memscan_discover_targets();
                                ui_message_modal("SMBIOS Patched",
                                    "Live SMBIOS string updated in RAM! Chainload an OS from the Boot tab to pass modified SMBIOS to the OS.",
                                    FALSE);
                            } else {
                                ui_message_modal("Write Failed", "Hardware rejected write to SMBIOS RAM.", TRUE);
                            }
                        }
                    }
                } else if (act == 1) {
                    debug_open_hex_editor(t->phys_addr, t->name);
                    memscan_discover_targets();
                }
            } else if (t->kind == TARGET_KIND_ACPI_TBL) {
                const CHAR8 *opts[2] = {
                    "Open ACPI Table in Live Memory Hex Editor",
                    "Recalculate & Fix ACPI Table Checksum"
                };
                INTN act = ui_select_modal(t->name, opts, 2, 0);
                if (act == 0) {
                    debug_open_hex_editor(t->phys_addr, t->name);
                    memscan_discover_targets();
                } else if (act == 1) {
                    if (hw_acpi_fix_checksum(t->aux_index)) {
                        memscan_discover_targets();
                        ui_message_modal("Checksum Updated", "ACPI SDT header checksum recalculated and verified!", FALSE);
                    } else {
                        ui_message_modal("Checksum Failed", "Could not write ACPI checksum (table may be FACS or Read-Only).", TRUE);
                    }
                }
            } else {
                debug_open_hex_editor(t->phys_addr, t->name);
                memscan_discover_targets();
            }
        }
        return TRUE;
    }

    return FALSE;
}
