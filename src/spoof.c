#include "spoof.h"
#include "hwinfo.h"
#include "memscan.h"
#include "nvram.h"
#include "ui.h"
#include "util.h"

BOOLEAN gSpoofActive    = FALSE;
UINTN   gSpoofEditCount = 0;

/* =========================================================================
 * Factory Hardware Backup & Staged Spoof Overrides (In RAM Only!)
 * ========================================================================= */
static BOOLEAN s_spoof_inited       = FALSE;
static UINT8  *s_orig_smbios_buf    = NULL;
static UINT32  s_orig_smbios_len    = 0;
static UINT8   s_orig_smbios_major  = 3;
static UINT8   s_orig_smbios_minor  = 0;
static VOID   *s_orig_ep2_ptr       = NULL;
static VOID   *s_orig_ep3_ptr       = NULL;

/* Runtime-allocated EfiACPIMemoryNVS pages (<4GB) surviving ExitBootServices() */
static UINT8  *s_nvs_alloc_base     = NULL;
static UINTN   s_nvs_alloc_pages    = 0;

/* Original ACPI OEM IDs for clean factory restore */
static CHAR8   s_orig_acpi_oem[HW_MAX_ACPI_TABLES][6];
static CHAR8   s_orig_acpi_tbl_id[HW_MAX_ACPI_TABLES][8];
static CHAR8   s_orig_rsdp_oem[6];
static BOOLEAN s_acpi_spoofed       = FALSE;

typedef struct {
    /* Type 0: BIOS */
    BOOLEAN set_bios_vendor;
    CHAR8   bios_vendor[64];
    BOOLEAN set_bios_version;
    CHAR8   bios_version[64];
    BOOLEAN set_bios_date;
    CHAR8   bios_date[24];

    /* Type 1: System / Vendor / Product / Serial / UUID */
    BOOLEAN set_sys_vendor;
    CHAR8   sys_vendor[64];
    BOOLEAN set_sys_product;
    CHAR8   sys_product[64];
    BOOLEAN set_sys_version;
    CHAR8   sys_version[48];
    BOOLEAN set_sys_serial;
    CHAR8   sys_serial[64];
    BOOLEAN set_sys_sku;
    CHAR8   sys_sku[48];
    BOOLEAN set_sys_family;
    CHAR8   sys_family[48];
    BOOLEAN set_sys_uuid;
    UINT8   sys_uuid_wire[16];

    /* Type 2: Baseboard / Motherboard */
    BOOLEAN set_board_vendor;
    CHAR8   board_vendor[64];
    BOOLEAN set_board_product;
    CHAR8   board_product[64];
    BOOLEAN set_board_serial;
    CHAR8   board_serial[64];

    /* Type 3: Chassis / Enclosure */
    BOOLEAN set_chassis_vendor;
    CHAR8   chassis_vendor[64];
    BOOLEAN set_chassis_type;
    UINT8   chassis_type_code;
    BOOLEAN set_chassis_serial;
    CHAR8   chassis_serial[64];
    BOOLEAN set_chassis_asset;
    CHAR8   chassis_asset[48];

    /* Type 4: Processor SMBIOS Strings */
    BOOLEAN set_cpu_vendor;
    CHAR8   cpu_vendor[48];
    BOOLEAN set_cpu_brand;
    CHAR8   cpu_brand[64];

    /* Type 17: RAM DIMM Vendor / Part / Serial Anonymizer */
    BOOLEAN set_dimm_vendor;
    CHAR8   dimm_vendor[36];
    BOOLEAN set_dimm_part;
    CHAR8   dimm_part[36];
    BOOLEAN set_dimm_serial_seed;
    UINT32  dimm_serial_seed;
} SPOOF_SMBIOS_STATE;

static SPOOF_SMBIOS_STATE s_sp;
static UINT64 s_rng_state = 0x9E3779B97F4A7C15ULL;

static UINT32 spoof_rand32(VOID) {
    UINT32 lo = 0, hi = 0;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    s_rng_state ^= ((UINT64)hi << 32) | (UINT64)lo;
    s_rng_state ^= s_rng_state >> 12;
    s_rng_state ^= s_rng_state << 25;
    s_rng_state ^= s_rng_state >> 27;
    return (UINT32)((s_rng_state * 0x2545F4914F6CDD1DULL) >> 32);
}

static VOID gen_random_alnum(CHAR8 *out, UINTN len, const CHAR8 *prefix) {
    static const CHAR8 kChars[] = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    UINTN pos = 0;
    if (prefix) {
        while (prefix[pos] && pos + 1 < len) {
            out[pos] = prefix[pos];
            pos++;
        }
    }
    while (pos < len) {
        out[pos++] = kChars[spoof_rand32() % 34U];
    }
    out[len] = '\0';
}

VOID spoof_init(VOID) {
    if (s_spoof_inited) return;
    s_spoof_inited = TRUE;
    memset(&s_sp, 0, sizeof(s_sp));

    if (gST && gST->ConfigurationTable) {
        for (UINTN i = 0; i < gST->NumberOfTableEntries; i++) {
            if (guid_equal(&gST->ConfigurationTable[i].VendorGuid, &gEfiSmbiosTableGuid)) {
                s_orig_ep2_ptr = gST->ConfigurationTable[i].VendorTable;
            } else if (guid_equal(&gST->ConfigurationTable[i].VendorGuid, &gEfiSmbios3TableGuid)) {
                s_orig_ep3_ptr = gST->ConfigurationTable[i].VendorTable;
            }
        }
    }

    if (gHw.smbios_present && gHw.smbios_table_addr != 0 &&
        gHw.smbios_table_size >= 16 && gHw.smbios_table_size <= 0x40000U) {
        s_orig_smbios_buf = (UINT8 *)alloc_pool(gHw.smbios_table_size);
        if (s_orig_smbios_buf) {
            if (safe_read_mem(gHw.smbios_table_addr, s_orig_smbios_buf, gHw.smbios_table_size)) {
                s_orig_smbios_len   = gHw.smbios_table_size;
                s_orig_smbios_major = gHw.smbios_major ? gHw.smbios_major : 3;
                s_orig_smbios_minor = gHw.smbios_minor;
            } else {
                free_pool(s_orig_smbios_buf);
                s_orig_smbios_buf = NULL;
            }
        }
    }

    if (gHw.acpi_rsdp_addr != 0) {
        safe_read_mem(gHw.acpi_rsdp_addr + 9U, s_orig_rsdp_oem, 6);
    }
    for (UINTN i = 0; i < gHw.acpi_count && i < HW_MAX_ACPI_TABLES; i++) {
        if (gHw.acpi_tables[i].phys_addr != 0 && gHw.acpi_tables[i].length >= sizeof(ACPI_SDT_HEADER)) {
            safe_read_mem(gHw.acpi_tables[i].phys_addr + 10U, s_orig_acpi_oem[i], 6);
            safe_read_mem(gHw.acpi_tables[i].phys_addr + 16U, s_orig_acpi_tbl_id[i], 8);
        }
    }
}

static UINT8 calc_sum8(const UINT8 *buf, UINTN len) {
    UINT8 s = 0;
    for (UINTN i = 0; i < len; i++) s = (UINT8)(s + buf[i]);
    return s;
}

static BOOLEAN ensure_nvs_smbios_buffer(VOID) {
    if (s_nvs_alloc_base != NULL) return TRUE;
    if (!gBS || !gBS->AllocatePages) return FALSE;

    /* 16 pages = 64 KiB in EfiACPIMemoryNVS (<4GB so both 32-bit _SM_ & 64-bit _SM3_ work!) */
    UINTN pages = 16;
    EFI_PHYSICAL_ADDRESS phys = 0xFFFF0000ULL;
    EFI_STATUS st = gBS->AllocatePages(AllocateMaxAddress, EfiACPIMemoryNVS, pages, &phys);
    if (EFI_ERROR(st)) {
        phys = 0;
        st = gBS->AllocatePages(AllocateAnyPages, EfiACPIMemoryNVS, pages, &phys);
    }
    if (EFI_ERROR(st) || phys == 0) return FALSE;

    s_nvs_alloc_base  = (UINT8 *)(UINTN)phys;
    s_nvs_alloc_pages = pages;
    memset(s_nvs_alloc_base, 0, pages * 4096U);
    return TRUE;
}

static VOID assign_spoof_string(
    UINT8 *fmt,
    UINT8 hlen,
    UINTN field_off,
    CHAR8 strs[32][68],
    UINTN *io_str_cnt,
    const CHAR8 *new_val
) {
    if (field_off >= hlen) return;
    if (!new_val || !new_val[0]) {
        fmt[field_off] = 0;
        return;
    }
    /* Append a dedicated string entry so shared "Default string" slots never collide! */
    if (*io_str_cnt < 31U) {
        UINTN idx = *io_str_cnt;
        str_cpy(strs[idx], new_val, sizeof(strs[idx]));
        (*io_str_cnt)++;
        fmt[field_off] = (UINT8)(idx + 1U);
    } else if (fmt[field_off] >= 1U && fmt[field_off] <= *io_str_cnt) {
        str_cpy(strs[fmt[field_off] - 1U], new_val, sizeof(strs[0]));
    }
}

static BOOLEAN spoof_rebuild_and_install_smbios(CHAR8 *err_out, UINTN max_err) {
    spoof_init();
    if (!s_orig_smbios_buf || s_orig_smbios_len < 8) {
        if (err_out) str_cpy(err_out, "No factory SMBIOS table found to clone.", max_err);
        return FALSE;
    }
    if (!ensure_nvs_smbios_buffer()) {
        if (err_out) str_cpy(err_out, "Failed to allocate EfiACPIMemoryNVS pages for temporary SMBIOS.", max_err);
        return FALSE;
    }

    /*
     * Layout inside 64 KiB s_nvs_alloc_base:
     *   +0x0000 : SMBIOS 2.1 Entry Point (_SM_, 31 bytes)
     *   +0x0040 : SMBIOS 3.0 Entry Point (_SM3_, 24 bytes)
     *   +0x0100 : Rebuilt SMBIOS Structure Stream (up to 65,280 bytes)
     */
    SMBIOS_ENTRY_POINT_21 *ep2 = (SMBIOS_ENTRY_POINT_21 *)(s_nvs_alloc_base + 0x0000U);
    SMBIOS_ENTRY_POINT_30 *ep3 = (SMBIOS_ENTRY_POINT_30 *)(s_nvs_alloc_base + 0x0040U);
    UINT8 *dst_tbl             = s_nvs_alloc_base + 0x0100U;
    UINTN  dst_cap             = (s_nvs_alloc_pages * 4096U) - 0x0100U;
    UINTN  dst_len             = 0;

    UINT16 num_structs     = 0;
    UINT16 max_struct_size = 0;
    UINTN  dimm_seq        = 0;

    UINTN off = 0;
    while (off + 4 <= s_orig_smbios_len) {
        const UINT8 *s = s_orig_smbios_buf + off;
        UINT8 type = s[0];
        UINT8 hlen = s[1];
        if (hlen < 4 || off + hlen > s_orig_smbios_len) break;

        /* Parse original string table for this structure */
        CHAR8 strs[32][68];
        memset(strs, 0, sizeof(strs));
        UINTN str_cnt = 0;

        UINTN p = off + hlen;
        if (p + 1 < s_orig_smbios_len && s_orig_smbios_buf[p] == 0 && s_orig_smbios_buf[p + 1] == 0) {
            p += 2;
        } else {
            while (p < s_orig_smbios_len && s_orig_smbios_buf[p] != 0) {
                UINTN sl = 0;
                while (p + sl < s_orig_smbios_len && s_orig_smbios_buf[p + sl] != 0) sl++;
                if (str_cnt < 31U) {
                    UINTN cp = (sl < 67U) ? sl : 67U;
                    memcpy(strs[str_cnt], s_orig_smbios_buf + p, cp);
                    strs[str_cnt][cp] = '\0';
                    str_cnt++;
                }
                p += sl + 1U;
            }
            if (p < s_orig_smbios_len && s_orig_smbios_buf[p] == 0) p++;
        }

        UINT8 fmt[256];
        memset(fmt, 0, sizeof(fmt));
        memcpy(fmt, s, hlen);
        UINT8 out_hlen = hlen;

        if (type == 0 && out_hlen >= 8) {
            if (s_sp.set_bios_vendor)  assign_spoof_string(fmt, out_hlen, 4, strs, &str_cnt, s_sp.bios_vendor);
            if (s_sp.set_bios_version) assign_spoof_string(fmt, out_hlen, 5, strs, &str_cnt, s_sp.bios_version);
            if (s_sp.set_bios_date && out_hlen >= 9)
                assign_spoof_string(fmt, out_hlen, 8, strs, &str_cnt, s_sp.bios_date);
        } else if (type == 1 && out_hlen >= 8) {
            if (s_sp.set_sys_vendor)  assign_spoof_string(fmt, out_hlen, 4, strs, &str_cnt, s_sp.sys_vendor);
            if (s_sp.set_sys_product) assign_spoof_string(fmt, out_hlen, 5, strs, &str_cnt, s_sp.sys_product);
            if (s_sp.set_sys_version) assign_spoof_string(fmt, out_hlen, 6, strs, &str_cnt, s_sp.sys_version);
            if (s_sp.set_sys_serial)  assign_spoof_string(fmt, out_hlen, 7, strs, &str_cnt, s_sp.sys_serial);
            if (s_sp.set_sys_uuid && out_hlen >= 24) {
                memcpy(fmt + 8, s_sp.sys_uuid_wire, 16);
            }
            if (s_sp.set_sys_sku && out_hlen >= 27)
                assign_spoof_string(fmt, out_hlen, 25, strs, &str_cnt, s_sp.sys_sku);
            if (s_sp.set_sys_family && out_hlen >= 27)
                assign_spoof_string(fmt, out_hlen, 26, strs, &str_cnt, s_sp.sys_family);
        } else if (type == 2 && out_hlen >= 8) {
            if (s_sp.set_board_vendor)  assign_spoof_string(fmt, out_hlen, 4, strs, &str_cnt, s_sp.board_vendor);
            if (s_sp.set_board_product) assign_spoof_string(fmt, out_hlen, 5, strs, &str_cnt, s_sp.board_product);
            if (s_sp.set_board_serial)  assign_spoof_string(fmt, out_hlen, 7, strs, &str_cnt, s_sp.board_serial);
        } else if (type == 3 && out_hlen >= 8) {
            if (s_sp.set_chassis_vendor) assign_spoof_string(fmt, out_hlen, 4, strs, &str_cnt, s_sp.chassis_vendor);
            if (s_sp.set_chassis_type)   fmt[5] = s_sp.chassis_type_code;
            if (s_sp.set_chassis_serial) assign_spoof_string(fmt, out_hlen, 7, strs, &str_cnt, s_sp.chassis_serial);
            if (s_sp.set_chassis_asset && out_hlen >= 9)
                assign_spoof_string(fmt, out_hlen, 8, strs, &str_cnt, s_sp.chassis_asset);
        } else if (type == 4 && out_hlen >= 0x18) {
            if (s_sp.set_cpu_vendor) assign_spoof_string(fmt, out_hlen, 7, strs, &str_cnt, s_sp.cpu_vendor);
            if (s_sp.set_cpu_brand)  assign_spoof_string(fmt, out_hlen, 0x10, strs, &str_cnt, s_sp.cpu_brand);
        } else if (type == 17 && out_hlen >= 0x1B) {
            UINT16 raw_sz = (UINT16)fmt[0x0C] | ((UINT16)fmt[0x0D] << 8);
            if (raw_sz != 0 && raw_sz != 0xFFFFU) {
                if (s_sp.set_dimm_vendor) assign_spoof_string(fmt, out_hlen, 0x17, strs, &str_cnt, s_sp.dimm_vendor);
                if (s_sp.set_dimm_part)   assign_spoof_string(fmt, out_hlen, 0x1A, strs, &str_cnt, s_sp.dimm_part);
                if (s_sp.set_dimm_serial_seed) {
                    CHAR8 dsn[16];
                    snprintf_ascii(dsn, sizeof(dsn), "%08X",
                                   (UINT32)(s_sp.dimm_serial_seed + (UINT32)(dimm_seq * 0x13579BDFU)));
                    assign_spoof_string(fmt, out_hlen, 0x18, strs, &str_cnt, dsn);
                }
                dimm_seq++;
            }
        }

        /* Emit rebuilt structure into dst_tbl */
        UINTN struct_start = dst_len;
        if (dst_len + out_hlen + 256U >= dst_cap) break;
        memcpy(dst_tbl + dst_len, fmt, out_hlen);
        dst_len += out_hlen;

        if (str_cnt == 0) {
            dst_tbl[dst_len++] = 0;
            dst_tbl[dst_len++] = 0;
        } else {
            for (UINTN si = 0; si < str_cnt; si++) {
                UINTN sl = str_len(strs[si]);
                if (sl == 0) {
                    dst_tbl[dst_len++] = ' ';
                    dst_tbl[dst_len++] = 0;
                } else {
                    if (dst_len + sl + 2U >= dst_cap) break;
                    memcpy(dst_tbl + dst_len, strs[si], sl);
                    dst_len += sl;
                    dst_tbl[dst_len++] = 0;
                }
            }
            dst_tbl[dst_len++] = 0; /* Final double-NUL terminator */
        }

        UINTN this_sz = dst_len - struct_start;
        if (this_sz > max_struct_size) max_struct_size = (UINT16)this_sz;
        num_structs++;

        if (type == 127) break;
        if (p <= off) break;
        off = p;
    }

    /* Guarantee a Type 127 End-of-Table structure if original didn't terminate with 127 */
    if (num_structs == 0 || dst_len < 6) {
        if (err_out) str_cpy(err_out, "Rebuilt SMBIOS structure stream was empty.", max_err);
        return FALSE;
    }

    UINT64 new_tbl_phys = (UINT64)(UINTN)dst_tbl;

    /* Build SMBIOS 3.0 Entry Point (_SM3_) */
    memset(ep3, 0, sizeof(*ep3));
    memcpy(ep3->Anchor, "_SM3_", 5);
    ep3->EntryPointLength = sizeof(SMBIOS_ENTRY_POINT_30); /* 24 (0x18) */
    ep3->MajorVersion     = s_orig_smbios_major;
    ep3->MinorVersion     = s_orig_smbios_minor;
    ep3->Docrev           = 0;
    ep3->EntryPointRevision = 0x01;
    ep3->TableMaximumSize = (UINT32)dst_len;
    ep3->TableAddress     = new_tbl_phys;
    ep3->EntryPointChecksum = (UINT8)(0U - calc_sum8((const UINT8 *)ep3, sizeof(*ep3)));

    /* Build SMBIOS 2.1 Entry Point (_SM_) if table is < 4 GiB */
    BOOLEAN can_ep2 = (new_tbl_phys <= 0xFFFFFFFFULL && dst_len <= 0xFFFFU);
    if (can_ep2) {
        memset(ep2, 0, sizeof(*ep2));
        memcpy(ep2->Anchor, "_SM_", 4);
        ep2->EntryPointLength   = sizeof(SMBIOS_ENTRY_POINT_21); /* 31 (0x1F) */
        ep2->MajorVersion       = (s_orig_smbios_major < 3) ? s_orig_smbios_major : 2;
        ep2->MinorVersion       = (s_orig_smbios_major < 3) ? s_orig_smbios_minor : 8;
        ep2->MaxStructureSize   = max_struct_size;
        ep2->EntryPointRevision = 0;
        memcpy(ep2->IntermediateAnchor, "_DMI_", 5);
        ep2->TableLength        = (UINT16)dst_len;
        ep2->TableAddress       = (UINT32)new_tbl_phys;
        ep2->NumberOfSmbiosStructures = num_structs;
        ep2->SmbiosBcdRevision  = (UINT8)((ep2->MajorVersion << 4) | (ep2->MinorVersion & 0x0FU));
        ep2->IntermediateChecksum = (UINT8)(0U - calc_sum8(((const UINT8 *)ep2) + 0x10U, 0x0FU));
        ep2->EntryPointChecksum   = (UINT8)(0U - calc_sum8((const UINT8 *)ep2, sizeof(*ep2)));
    }

    /* Install updated SMBIOS Configuration Tables in gST->ConfigurationTable */
    if (gBS && gBS->InstallConfigurationTable) {
        gBS->InstallConfigurationTable(&gEfiSmbios3TableGuid, ep3);
        if (can_ep2) {
            gBS->InstallConfigurationTable(&gEfiSmbiosTableGuid, ep2);
        }
    }

    /* Refresh gHw SMBIOS/ACPI state + MemScan targets */
    hw_refresh_smbios_and_acpi_only();
    memscan_discover_targets();
    gSpoofActive = TRUE;
    gSpoofEditCount++;
    return TRUE;
}

static UINTN spoof_apply_acpi_oem(const CHAR8 *new_oem6, const CHAR8 *new_tbl8) {
    spoof_init();
    CHAR8 pad6[6], pad8[8];
    memset(pad6, ' ', 6);
    memset(pad8, ' ', 8);
    for (UINTN i = 0; i < 6 && new_oem6 && new_oem6[i]; i++) pad6[i] = new_oem6[i];
    for (UINTN i = 0; i < 8 && new_tbl8 && new_tbl8[i]; i++) pad8[i] = new_tbl8[i];

    UINTN patched = 0;
    /* Patch RSDP OEMID (6 bytes at +9, fix 20-byte checksum at +8 and 36-byte ext checksum at +32) */
    if (gHw.acpi_rsdp_addr != 0) {
        BOOLEAN v = FALSE;
        BOOLEAN ok = TRUE;
        for (UINTN b = 0; b < 6; b++) {
            if (!safe_write_byte(gHw.acpi_rsdp_addr + 9U + b, (UINT8)pad6[b], &v) || !v) { ok = FALSE; break; }
        }
        if (ok) {
            UINT8 rsdp_b[36];
            if (safe_read_mem(gHw.acpi_rsdp_addr, rsdp_b, 20)) {
                rsdp_b[8] = 0;
                UINT8 c1 = (UINT8)(0U - calc_sum8(rsdp_b, 20));
                safe_write_byte(gHw.acpi_rsdp_addr + 8U, c1, &v);
                if (rsdp_b[15] >= 2 && safe_read_mem(gHw.acpi_rsdp_addr, rsdp_b, 36)) {
                    rsdp_b[32] = 0;
                    UINT8 c2 = (UINT8)(0U - calc_sum8(rsdp_b, 36));
                    safe_write_byte(gHw.acpi_rsdp_addr + 32U, c2, &v);
                }
            }
        }
    }

    for (UINTN i = 0; i < gHw.acpi_count && i < HW_MAX_ACPI_TABLES; i++) {
        if (str_cmp(gHw.acpi_tables[i].signature, "FACS") == 0) continue;
        UINT64 a = gHw.acpi_tables[i].phys_addr;
        if (a == 0 || !gHw.acpi_tables[i].writable) continue;
        BOOLEAN ok = TRUE, v = FALSE;
        if (new_oem6 && new_oem6[0]) {
            for (UINTN b = 0; b < 6; b++) {
                if (!safe_write_byte(a + 10U + b, (UINT8)pad6[b], &v) || !v) { ok = FALSE; break; }
            }
        }
        if (ok && new_tbl8 && new_tbl8[0]) {
            for (UINTN b = 0; b < 8; b++) {
                if (!safe_write_byte(a + 16U + b, (UINT8)pad8[b], &v) || !v) { ok = FALSE; break; }
            }
        }
        if (ok) {
            hw_acpi_fix_checksum(i);
            patched++;
        }
    }

    if (patched > 0) {
        s_acpi_spoofed = TRUE;
        gSpoofActive   = TRUE;
        gSpoofEditCount++;
        hw_refresh_smbios_and_acpi_only();
    }
    return patched;
}

BOOLEAN spoof_restore_factory_identity(CHAR8 *msg_out, UINTN max_msg) {
    spoof_init();
    memset(&s_sp, 0, sizeof(s_sp));

    if (gBS && gBS->InstallConfigurationTable) {
        if (s_orig_ep3_ptr) gBS->InstallConfigurationTable(&gEfiSmbios3TableGuid, s_orig_ep3_ptr);
        if (s_orig_ep2_ptr) gBS->InstallConfigurationTable(&gEfiSmbiosTableGuid, s_orig_ep2_ptr);
    }

    if (s_acpi_spoofed) {
        BOOLEAN v = FALSE;
        if (gHw.acpi_rsdp_addr != 0) {
            for (UINTN b = 0; b < 6; b++) safe_write_byte(gHw.acpi_rsdp_addr + 9U + b, (UINT8)s_orig_rsdp_oem[b], &v);
            UINT8 rb[36];
            if (safe_read_mem(gHw.acpi_rsdp_addr, rb, 20)) {
                rb[8] = 0;
                safe_write_byte(gHw.acpi_rsdp_addr + 8U, (UINT8)(0U - calc_sum8(rb, 20)), &v);
                if (rb[15] >= 2 && safe_read_mem(gHw.acpi_rsdp_addr, rb, 36)) {
                    rb[32] = 0;
                    safe_write_byte(gHw.acpi_rsdp_addr + 32U, (UINT8)(0U - calc_sum8(rb, 36)), &v);
                }
            }
        }
        for (UINTN i = 0; i < gHw.acpi_count && i < HW_MAX_ACPI_TABLES; i++) {
            if (str_cmp(gHw.acpi_tables[i].signature, "FACS") == 0) continue;
            UINT64 a = gHw.acpi_tables[i].phys_addr;
            if (a == 0 || !gHw.acpi_tables[i].writable) continue;
            for (UINTN b = 0; b < 6; b++) safe_write_byte(a + 10U + b, (UINT8)s_orig_acpi_oem[i][b], &v);
            for (UINTN b = 0; b < 8; b++) safe_write_byte(a + 16U + b, (UINT8)s_orig_acpi_tbl_id[i][b], &v);
            hw_acpi_fix_checksum(i);
        }
        s_acpi_spoofed = FALSE;
    }

    gSpoofActive    = FALSE;
    gSpoofEditCount = 0;
    hw_refresh_smbios_and_acpi_only();
    memscan_discover_targets();
    if (msg_out) {
        str_cpy(msg_out, "Restored original factory SMBIOS & ACPI hardware identity in RAM.", max_msg);
    }
    return TRUE;
}

/* =========================================================================
 * UUID String Parser ("XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -> SMBIOS wire)
 * ========================================================================= */
static INTN hex_nibble(CHAR8 c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static BOOLEAN parse_uuid_to_smbios_wire(const CHAR8 *s, UINT8 wire[16]) {
    UINT8 raw_be[16];
    UINTN bi = 0;
    for (UINTN i = 0; s && s[i] && bi < 16;) {
        if (s[i] == '-' || s[i] == ' ' || s[i] == '{' || s[i] == '}') { i++; continue; }
        INTN hi = hex_nibble(s[i]);
        INTN lo = s[i + 1] ? hex_nibble(s[i + 1]) : -1;
        if (hi < 0 || lo < 0) return FALSE;
        raw_be[bi++] = (UINT8)((hi << 4) | lo);
        i += 2;
    }
    if (bi != 16) return FALSE;
    /* SMBIOS 2.6+ wire order: Data1 LE (4B), Data2 LE (2B), Data3 LE (2B), Data4 big-endian (8B) */
    wire[0] = raw_be[3]; wire[1] = raw_be[2]; wire[2] = raw_be[1]; wire[3] = raw_be[0];
    wire[4] = raw_be[5]; wire[5] = raw_be[4];
    wire[6] = raw_be[7]; wire[7] = raw_be[6];
    memcpy(wire + 8, raw_be + 8, 8);
    return TRUE;
}

static VOID gen_random_uuid_wire(UINT8 wire[16]) {
    for (UINTN i = 0; i < 4; i++) {
        UINT32 r = spoof_rand32();
        memcpy(wire + i * 4, &r, 4);
    }
    /* RFC 4122 v4 UUID bits in SMBIOS wire layout (Data3 high nibble = 4, Data4[0] = 10xx) */
    wire[7] = (UINT8)((wire[7] & 0x0FU) | 0x40U);
    wire[8] = (UINT8)((wire[8] & 0x3FU) | 0x80U);
}

static VOID show_post_spoof_temp_notice(const CHAR8 *field_label, const CHAR8 *new_value) {
    CHAR8 msg[360];
    snprintf_ascii(msg, sizeof(msg),
        "%s -> \"%s\"\n\n"
        "WARNING - TEMPORARY SPOOF ONLY:\n"
        "This spoof lives in RAM (EfiACPIMemoryNVS) for this boot only.\n"
        "If you Reset or Reboot, all spoofs WILL NOT APPLY (wiped on reset)!\n"
        "Select \">> Boot / Chainload OS From This Page <<\" right here to boot with spoofs active!",
        field_label, new_value);
    ui_message_modal("Temporary Device Spoof Active", msg, FALSE);
}

/* =========================================================================
 * Interactive Sub-Modals for Rich Vendor / Presets / PCI Spoofing
 * ========================================================================= */
static VOID handle_oneclick_spoof_presets(VOID) {
    const CHAR8 *presets[7] = {
        "Randomize All Serials, UUID, Board, Chassis & DIMMs (Keep Current Vendor)",
        "Preset: ASUS ROG Crosshair / Republic of Gamers Desktop",
        "Preset: MSI MEG / Micro-Star Gaming Workstation",
        "Preset: Lenovo ThinkPad P-Series Enterprise Workstation",
        "Preset: Dell Inc. XPS / Precision Workstation",
        gHw.is_apple_mac
            ? "Preset: Apple Inc. MacPro7,1 SMBIOS Identity"
            : "Preset: Gigabyte Technology Co., Ltd. X570S AORUS Master",
        "Restore Original Factory Hardware Identity (Undo All Spoofs)"
    };
    INTN p = ui_select_modal("One-Click Temporary Device & Vendor Spoof Presets", presets, 7, 0);
    if (p < 0) return;

    if (p == 6) {
        CHAR8 rmsg[160];
        spoof_restore_factory_identity(rmsg, sizeof(rmsg));
        ui_message_modal("Factory Identity Restored", rmsg, FALSE);
        return;
    }

    spoof_init();

    /* Randomize all serials/UUID/DIMM serials in every preset */
    gen_random_alnum(s_sp.sys_serial,     12, "SN");
    gen_random_alnum(s_sp.board_serial,   14, "MB");
    gen_random_alnum(s_sp.chassis_serial, 12, "CH");
    gen_random_alnum(s_sp.chassis_asset,  10, "AT-");
    gen_random_uuid_wire(s_sp.sys_uuid_wire);
    s_sp.set_sys_serial       = TRUE;
    s_sp.set_board_serial     = TRUE;
    s_sp.set_chassis_serial   = TRUE;
    s_sp.set_chassis_asset    = TRUE;
    s_sp.set_sys_uuid         = TRUE;
    s_sp.set_dimm_serial_seed = TRUE;
    s_sp.dimm_serial_seed     = spoof_rand32();

    const CHAR8 *preset_desc = "Randomized Hardware Serials + UUID + DIMMs";

    if (p == 1) {
        str_cpy(s_sp.sys_vendor,     "ASUSTeK COMPUTER INC.", sizeof(s_sp.sys_vendor));
        str_cpy(s_sp.sys_product,    "ROG CROSSHAIR HERO", sizeof(s_sp.sys_product));
        str_cpy(s_sp.sys_version,    "Rev 1.xx", sizeof(s_sp.sys_version));
        str_cpy(s_sp.board_vendor,   "ASUSTeK COMPUTER INC.", sizeof(s_sp.board_vendor));
        str_cpy(s_sp.board_product,  "ROG CROSSHAIR HERO", sizeof(s_sp.board_product));
        str_cpy(s_sp.chassis_vendor, "ASUSTeK COMPUTER INC.", sizeof(s_sp.chassis_vendor));
        str_cpy(s_sp.bios_vendor,    "American Megatrends Inc.", sizeof(s_sp.bios_vendor));
        s_sp.chassis_type_code = 0x03; /* Desktop */
        s_sp.set_sys_vendor = s_sp.set_sys_product = s_sp.set_sys_version = TRUE;
        s_sp.set_board_vendor = s_sp.set_board_product = TRUE;
        s_sp.set_chassis_vendor = s_sp.set_chassis_type = s_sp.set_bios_vendor = TRUE;
        spoof_apply_acpi_oem("ALASKA", "A M I   ");
        preset_desc = "ASUS ROG Desktop + Random Serials/UUID";
    } else if (p == 2) {
        str_cpy(s_sp.sys_vendor,     "Micro-Star International Co., Ltd.", sizeof(s_sp.sys_vendor));
        str_cpy(s_sp.sys_product,    "MEG ACE WORKSTATION", sizeof(s_sp.sys_product));
        str_cpy(s_sp.sys_version,    "2.0", sizeof(s_sp.sys_version));
        str_cpy(s_sp.board_vendor,   "Micro-Star International Co., Ltd.", sizeof(s_sp.board_vendor));
        str_cpy(s_sp.board_product,  "MEG ACE (MS-7D70)", sizeof(s_sp.board_product));
        str_cpy(s_sp.chassis_vendor, "Micro-Star International Co., Ltd.", sizeof(s_sp.chassis_vendor));
        s_sp.chassis_type_code = 0x03;
        s_sp.set_sys_vendor = s_sp.set_sys_product = s_sp.set_sys_version = TRUE;
        s_sp.set_board_vendor = s_sp.set_board_product = TRUE;
        s_sp.set_chassis_vendor = s_sp.set_chassis_type = TRUE;
        spoof_apply_acpi_oem("ALASKA", "A M I   ");
        preset_desc = "MSI MEG Workstation + Random Serials/UUID";
    } else if (p == 3) {
        str_cpy(s_sp.sys_vendor,     "LENOVO", sizeof(s_sp.sys_vendor));
        str_cpy(s_sp.sys_product,    "20HHCTO1WW", sizeof(s_sp.sys_product));
        str_cpy(s_sp.sys_version,    "ThinkPad P51", sizeof(s_sp.sys_version));
        str_cpy(s_sp.sys_family,     "ThinkPad P51", sizeof(s_sp.sys_family));
        str_cpy(s_sp.board_vendor,   "LENOVO", sizeof(s_sp.board_vendor));
        str_cpy(s_sp.board_product,  "20HHCTO1WW", sizeof(s_sp.board_product));
        str_cpy(s_sp.chassis_vendor, "LENOVO", sizeof(s_sp.chassis_vendor));
        str_cpy(s_sp.bios_vendor,    "LENOVO", sizeof(s_sp.bios_vendor));
        s_sp.chassis_type_code = 0x0A; /* Notebook */
        s_sp.set_sys_vendor = s_sp.set_sys_product = s_sp.set_sys_version = s_sp.set_sys_family = TRUE;
        s_sp.set_board_vendor = s_sp.set_board_product = TRUE;
        s_sp.set_chassis_vendor = s_sp.set_chassis_type = s_sp.set_bios_vendor = TRUE;
        spoof_apply_acpi_oem("LENOVO", "TP-N1U  ");
        preset_desc = "LENOVO ThinkPad P51 + Random Serials/UUID";
    } else if (p == 4) {
        str_cpy(s_sp.sys_vendor,     "Dell Inc.", sizeof(s_sp.sys_vendor));
        str_cpy(s_sp.sys_product,    "XPS 15 9530", sizeof(s_sp.sys_product));
        str_cpy(s_sp.board_vendor,   "Dell Inc.", sizeof(s_sp.board_vendor));
        str_cpy(s_sp.board_product,  "0PHRDD", sizeof(s_sp.board_product));
        str_cpy(s_sp.chassis_vendor, "Dell Inc.", sizeof(s_sp.chassis_vendor));
        str_cpy(s_sp.bios_vendor,    "Dell Inc.", sizeof(s_sp.bios_vendor));
        s_sp.chassis_type_code = 0x09; /* Laptop */
        s_sp.set_sys_vendor = s_sp.set_sys_product = TRUE;
        s_sp.set_board_vendor = s_sp.set_board_product = TRUE;
        s_sp.set_chassis_vendor = s_sp.set_chassis_type = s_sp.set_bios_vendor = TRUE;
        spoof_apply_acpi_oem("DELL  ", "CBX3    ");
        preset_desc = "Dell Inc. XPS + Random Serials/UUID";
    } else if (p == 5) {
        if (gHw.is_apple_mac) {
            str_cpy(s_sp.sys_vendor,     "Apple Inc.", sizeof(s_sp.sys_vendor));
            str_cpy(s_sp.sys_product,    "MacPro7,1", sizeof(s_sp.sys_product));
            str_cpy(s_sp.sys_version,    "1.0", sizeof(s_sp.sys_version));
            str_cpy(s_sp.sys_family,     "MacPro", sizeof(s_sp.sys_family));
            str_cpy(s_sp.board_vendor,   "Apple Inc.", sizeof(s_sp.board_vendor));
            str_cpy(s_sp.board_product,  "Mac-27AD2F918AE68F61", sizeof(s_sp.board_product));
            str_cpy(s_sp.chassis_vendor, "Apple Inc.", sizeof(s_sp.chassis_vendor));
            str_cpy(s_sp.bios_vendor,    "Apple Inc.", sizeof(s_sp.bios_vendor));
            str_cpy(s_sp.bios_version,   "2020.80.5.0.0", sizeof(s_sp.bios_version));
            gen_random_alnum(s_sp.sys_serial,   12, "F5K");
            gen_random_alnum(s_sp.board_serial, 17, "F5K012300");
            s_sp.chassis_type_code = 0x07; /* Tower */
            s_sp.set_sys_vendor = s_sp.set_sys_product = s_sp.set_sys_version = s_sp.set_sys_family = TRUE;
            s_sp.set_board_vendor = s_sp.set_board_product = TRUE;
            s_sp.set_chassis_vendor = s_sp.set_chassis_type = TRUE;
            s_sp.set_bios_vendor = s_sp.set_bios_version = TRUE;
            spoof_apply_acpi_oem("APPLE ", "Apple00 ");
            preset_desc = "Apple MacPro7,1 SMBIOS + Random MLB/SSN/UUID";
        } else {
            str_cpy(s_sp.sys_vendor,     "Gigabyte Technology Co., Ltd.", sizeof(s_sp.sys_vendor));
            str_cpy(s_sp.sys_product,    "X570S AORUS MASTER", sizeof(s_sp.sys_product));
            str_cpy(s_sp.sys_version,    "1.0", sizeof(s_sp.sys_version));
            str_cpy(s_sp.board_vendor,   "Gigabyte Technology Co., Ltd.", sizeof(s_sp.board_vendor));
            str_cpy(s_sp.board_product,  "X570S AORUS MASTER", sizeof(s_sp.board_product));
            str_cpy(s_sp.chassis_vendor, "Gigabyte Technology Co., Ltd.", sizeof(s_sp.chassis_vendor));
            str_cpy(s_sp.bios_vendor,    "American Megatrends International, LLC.", sizeof(s_sp.bios_vendor));
            s_sp.chassis_type_code = 0x03; /* Desktop */
            s_sp.set_sys_vendor = s_sp.set_sys_product = s_sp.set_sys_version = TRUE;
            s_sp.set_board_vendor = s_sp.set_board_product = TRUE;
            s_sp.set_chassis_vendor = s_sp.set_chassis_type = s_sp.set_bios_vendor = TRUE;
            spoof_apply_acpi_oem("ALASKA", "A M I   ");
            preset_desc = "Gigabyte X570S AORUS MASTER + Random Serials/UUID";
        }
    }

    CHAR8 err[128];
    if (spoof_rebuild_and_install_smbios(err, sizeof(err))) {
        show_post_spoof_temp_notice("Applied Spoof Preset", preset_desc);
    } else {
        ui_message_modal("Spoof Failed", err, TRUE);
    }
}

static VOID handle_pci_subsys_spoof(VOID) {
    if (gHw.pci_count == 0) {
        ui_message_modal("No PCI Devices", "No enumerated PCI devices found.", TRUE);
        return;
    }
    CHAR8 dbufs[HW_MAX_PCI_DEVS][72];
    const CHAR8 *dptrs[HW_MAX_PCI_DEVS];
    for (UINTN i = 0; i < gHw.pci_count; i++) {
        const HW_PCI_DEV_INFO *pd = &gHw.pci_devs[i];
        snprintf_ascii(dbufs[i], sizeof(dbufs[i]),
                       "%02X:%02X.%X [%04X:%04X] Subsys[%04X:%04X] %s",
                       pd->bus, pd->dev, pd->func,
                       pd->vendor_id, pd->device_id,
                       pd->subsys_vendor_id, pd->subsys_id,
                       pd->class_name);
        dptrs[i] = dbufs[i];
    }

    INTN idx = ui_select_modal("Select PCI Device for Temporary Subsystem Vendor/ID Spoof",
                               dptrs, gHw.pci_count, 0);
    if (idx < 0) return;

    HW_PCI_DEV_INFO *pd = &gHw.pci_devs[idx];
    CHAR8 def_sv[16], def_sd[16], in_sv[16], in_sd[16];
    snprintf_ascii(def_sv, sizeof(def_sv), "0x%04X", pd->subsys_vendor_id);
    snprintf_ascii(def_sd, sizeof(def_sd), "0x%04X", pd->subsys_id);

    if (!ui_input_modal("Spoof PCI Subsystem Vendor ID (Hex)",
                        "Enter 16-bit Subsystem Vendor ID (e.g. 0x1043 ASUS, 0x1458 Gigabyte, 0x17AA Lenovo):",
                        def_sv, in_sv, sizeof(in_sv), FALSE)) return;
    if (!ui_input_modal("Spoof PCI Subsystem Device ID (Hex)",
                        "Enter 16-bit Subsystem Device ID (e.g. 0x8877):",
                        def_sd, in_sd, sizeof(in_sd), FALSE)) return;

    UINT64 sv = 0, sd = 0;
    if (!parse_hex_u64(in_sv, &sv) || !parse_hex_u64(in_sd, &sd) || sv > 0xFFFFULL || sd > 0xFFFFULL) {
        ui_message_modal("Invalid Hex", "Enter valid 16-bit hex IDs (0x0000 .. 0xFFFF).", TRUE);
        return;
    }

    UINT32 combined = (UINT32)(sv & 0xFFFFULL) | ((UINT32)(sd & 0xFFFFULL) << 16);
    /* Write standard Type 0 Subsystem register (0x2C), plus common mirror shadow offsets (0x4C on AMD/NVIDIA!) */
    hw_pci_cfg_write32_raw(pd->bus, pd->dev, pd->func, 0x2CU, combined);
    if (pd->vendor_id == 0x1002U || pd->vendor_id == 0x1022U || pd->vendor_id == 0x10DEU) {
        /* Note: only write 0x2C unless 0x4C currently holds the old subsystem ID mirror */
        UINT32 mir = 0;
        UINT32 old_comb = (UINT32)pd->subsys_vendor_id | ((UINT32)pd->subsys_id << 16);
        if (old_comb != 0 && hw_pci_cfg_read32_raw(pd->bus, pd->dev, pd->func, 0x4CU, &mir) && mir == old_comb) {
            hw_pci_cfg_write32_raw(pd->bus, pd->dev, pd->func, 0x4CU, combined);
        }
    }

    UINT32 rb = 0;
    hw_pci_cfg_read32_raw(pd->bus, pd->dev, pd->func, 0x2CU, &rb);
    pd->subsys_vendor_id = (UINT16)(rb & 0xFFFFU);
    pd->subsys_id        = (UINT16)((rb >> 16) & 0xFFFFU);

    CHAR8 res[320];
    if (rb == combined) {
        gSpoofActive = TRUE;
        gSpoofEditCount++;
        gVolatileHwTweakActive = TRUE;
        snprintf_ascii(res, sizeof(res),
            "PCI %02X:%02X.%X Subsystem ID updated to [%04X:%04X]!\n"
            "WARNING: Hardware resets clear PCI registers — Boot OS directly from this page!",
            pd->bus, pd->dev, pd->func, pd->subsys_vendor_id, pd->subsys_id);
        ui_message_modal("PCI Subsystem Spoof Applied", res, FALSE);
    } else {
        snprintf_ascii(res, sizeof(res),
            "PCI %02X:%02X.%X Subsystem register 0x2C is hardware Write-Once / Read-Only on this device\n"
            "(Read-back remained [%04X:%04X]). SMBIOS & ACPI spoofs still work in RAM!",
            pd->bus, pd->dev, pd->func, pd->subsys_vendor_id, pd->subsys_id);
        ui_message_modal("PCI Register Write-Once", res, TRUE);
    }
}

/* =========================================================================
 * Security & Temporary Device Spoof Tab UI + Keyboard Controller
 * ========================================================================= */
#define SEC_ITEM_COUNT 16

static VOID sec_draw_kv(UINTN lx, UINTN y, UINTN lw, const CHAR8 *label, const CHAR8 *val) {
    if (y >= gUiRows - 2U) return;
    ui_puts_n(lx, y, label, 21U, gTheme.label_attr);
    if (lw > 22U) ui_puts_n(lx + 22U, y, val, lw - 22U, gTheme.value_attr);
}

static VOID sec_draw_opt(
    UINTN lx, UINTN y, UINTN lw,
    BOOLEAN sel, BOOLEAN warn_highlight,
    const CHAR8 *label, const CHAR8 *val
) {
    if (y >= gUiRows - 2U) return;
    UINT8 a = sel ? gTheme.item_sel_attr : (warn_highlight ? gTheme.warn_attr : gTheme.item_attr);
    ui_hline(lx, y, lw, L' ', sel ? a : (warn_highlight ? gTheme.warn_attr : gTheme.body_attr));
    ui_puts_n(lx, y, label, 22U, a);
    if (lw > 23U && val) {
        CHAR8 tmp[64];
        snprintf_ascii(tmp, sizeof(tmp), "[%s]", val);
        ui_puts_n(lx + 23U, y, tmp, lw - 23U, a);
    }
}

VOID spoof_draw_security_tab(const CHAR8 *footer_status, UINTN *io_cur, UINTN *io_scroll) {
    spoof_init();

    const CHAR8 *help_txt =
        "WARNING: TEMP SPOOF!\n"
        "All Vendor/Serial/UUID/\n"
        "DIMM/ACPI/PCI spoofs\n"
        "live in RAM only.\n"
        "MUST boot OS via\n"
        "\">> Boot OS Here <<\"!\n"
        "Reset wipes all spoofs!";

    ui_draw_setup_frame(3 /* TAB_SECURITY */, NULL, TRUE, "Security & Temp Spoof", help_txt, footer_status);

    UINTN split_x = (gUiCols * 2U) / 3U;
    if (split_x < 50U && gUiCols >= 80U) split_x = 52U;
    if (gUiCols - split_x < 27U && gUiCols >= 80U) split_x = gUiCols - 28U;
    UINTN lx = 2U;
    UINTN lw = split_x - 3U;
    UINTN y  = 3U;

    CHAR8 b[96];
    snprintf_ascii(b, sizeof(b), "%s | %s (PK:%s db:%s)",
                   gSetup.secure_boot_enabled ? "SecureBoot:ON" : "SecureBoot:OFF",
                   gSetup.setup_mode_enabled ? "SetupMode" : "UserMode",
                   gSetup.pk_present ? "Y" : "N",
                   gSetup.db_present ? "Y" : "N");
    sec_draw_kv(lx, y++, lw, "UEFI Auth & Keys", b);

    snprintf_ascii(b, sizeof(b), "%s (%u edit%s)",
                   gSpoofActive ? "ACTIVE - BOOT FROM THIS PAGE!" : "Factory Hardware Identity",
                   (UINT32)gSpoofEditCount, gSpoofEditCount == 1 ? "" : "s");
    sec_draw_kv(lx, y++, lw, "Temp Spoof Status", b);

    /* High-visibility Warning Banner right on the Security Page! */
    ui_hline(lx, y, lw, L' ', gTheme.warn_attr);
    ui_puts_n(lx + 1U, y, "! TEMP SPOOF: BOOT OS FROM THIS PAGE OR LOST !", lw - 1U, gTheme.warn_attr);
    y += 2U;

    if (*io_cur >= SEC_ITEM_COUNT) *io_cur = SEC_ITEM_COUNT - 1U;
    UINTN vis = (gUiRows - 2U > y) ? (gUiRows - 2U - y) : 1U;
    if (*io_cur < *io_scroll) *io_scroll = *io_cur;
    if (*io_cur >= *io_scroll + vis) *io_scroll = *io_cur - vis + 1U;

    for (UINTN r = 0; r < vis && (*io_scroll + r) < SEC_ITEM_COUNT; r++) {
        UINTN idx = *io_scroll + r;
        UINTN ry  = y + r;
        BOOLEAN sel = (idx == *io_cur);

        switch (idx) {
            case 0:
                sec_draw_opt(lx, ry, lw, sel, gSpoofActive,
                             ">> Boot OS Here <<", "Chainload OS Now (Apply Temp Spoof!)");
                break;
            case 1:
                sec_draw_opt(lx, ry, lw, sel, FALSE,
                             "One-Click Spoof", "Presets / Randomize All / Restore...");
                break;
            case 2:
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof System Vendor", gHw.sys_manufacturer);
                break;
            case 3:
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof Product Model", gHw.sys_product);
                break;
            case 4:
                snprintf_ascii(b, sizeof(b), "%s | %s", gHw.sys_version,
                               gHw.sys_family[0] ? gHw.sys_family : "Default");
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof Ver / SKU / Fam", b);
                break;
            case 5:
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof System Serial", gHw.sys_serial);
                break;
            case 6:
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof Hardware UUID", gHw.sys_uuid);
                break;
            case 7:
                snprintf_ascii(b, sizeof(b), "%s | %s (%s)",
                               gHw.bios_vendor, gHw.bios_version, gHw.bios_date);
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof BIOS Vendor/Ver", b);
                break;
            case 8:
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof Board Vendor",
                             gHw.board_manufacturer[0] ? gHw.board_manufacturer : gHw.sys_manufacturer);
                break;
            case 9:
                snprintf_ascii(b, sizeof(b), "%s | SN:%s", gHw.board_product, gHw.board_serial);
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof Board & Serial", b);
                break;
            case 10:
                snprintf_ascii(b, sizeof(b), "%s (%s) SN:%s",
                               gHw.chassis_manufacturer[0] ? gHw.chassis_manufacturer : gHw.sys_manufacturer,
                               gHw.chassis_type, gHw.chassis_serial);
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof Chassis/Vendor", b);
                break;
            case 11:
                snprintf_ascii(b, sizeof(b), "%s | %s",
                               gHw.cpu_smbios_manufacturer[0] ? gHw.cpu_smbios_manufacturer : gHw.cpu_vendor,
                               gHw.cpu_smbios_version[0] ? gHw.cpu_smbios_version : gHw.cpu_brand);
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof CPU Brand(DMI)", b);
                break;
            case 12:
                if (gHw.dimm_populated_count > 0) {
                    snprintf_ascii(b, sizeof(b), "%u DIMMs (%s SN:%s)",
                                   (UINT32)gHw.dimm_populated_count,
                                   gHw.dimms[0].manufacturer[0] ? gHw.dimms[0].manufacturer : "RAM",
                                   gHw.dimms[0].serial[0] ? gHw.dimms[0].serial : "N/A");
                } else {
                    str_cpy(b, "No Type 17 DIMMs", sizeof(b));
                }
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof RAM DIMM Info", b);
                break;
            case 13:
                snprintf_ascii(b, sizeof(b), "OEM:\"%s\" (%u ACPI Tables)",
                               gHw.acpi_oem_id[0] ? gHw.acpi_oem_id : "N/A", (UINT32)gHw.acpi_count);
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof ACPI OEM ID", b);
                break;
            case 14:
                snprintf_ascii(b, sizeof(b), "Select from %u PCI Devices...", (UINT32)gHw.pci_count);
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Spoof PCI Subsys ID", b);
                break;
            case 15:
                sec_draw_opt(lx, ry, lw, sel, FALSE, "Supervisor Password",
                             gSetup.cfg.has_supervisor_pw ? "Installed (Change/Clear)" : "Not Installed");
                break;
        }
    }
}

static BOOLEAN edit_smbios_str_field(
    const CHAR8 *title,
    const CHAR8 *prompt,
    const CHAR8 *cur_val,
    CHAR8 *dst_buf,
    UINTN dst_cap,
    BOOLEAN *dst_flag
) {
    CHAR8 out[64];
    if (!ui_input_modal(title, prompt, cur_val ? cur_val : "", out, sizeof(out), FALSE)) {
        return FALSE;
    }
    str_cpy(dst_buf, out, dst_cap);
    *dst_flag = TRUE;
    CHAR8 err[128];
    if (!spoof_rebuild_and_install_smbios(err, sizeof(err))) {
        ui_message_modal("Spoof Error", err, TRUE);
        return FALSE;
    }
    show_post_spoof_temp_notice(title, out);
    return TRUE;
}

BOOLEAN spoof_handle_security_key(const EFI_INPUT_KEY *k, UINTN *io_cur) {
    UINTN vis = (gUiRows > 9U) ? (gUiRows - 9U) : 8U;
    if (k->ScanCode == SCAN_UP) {
        *io_cur = (*io_cur > 0) ? (*io_cur - 1U) : (SEC_ITEM_COUNT - 1U);
        return TRUE;
    }
    if (k->ScanCode == SCAN_DOWN) {
        *io_cur = (*io_cur + 1U) % SEC_ITEM_COUNT;
        return TRUE;
    }
    if (k->ScanCode == SCAN_PAGE_UP) {
        *io_cur = (*io_cur > vis) ? (*io_cur - vis) : 0U;
        return TRUE;
    }
    if (k->ScanCode == SCAN_PAGE_DOWN) {
        *io_cur = (*io_cur + vis < SEC_ITEM_COUNT) ? (*io_cur + vis) : (SEC_ITEM_COUNT - 1U);
        return TRUE;
    }
    if (k->UnicodeChar != L'\r' && k->UnicodeChar != L'\n' && k->UnicodeChar != L' ') {
        return FALSE;
    }

    spoof_init();
    CHAR8 err[128];

    switch (*io_cur) {
        case 0:
            nvram_boot_os_preserve_live_modal("Boot OS From Security Page (Apply Temporary Spoofs!)");
            return TRUE;

        case 1:
            handle_oneclick_spoof_presets();
            return TRUE;

        case 2: {
            const CHAR8 *vopts[8] = {
                "Enter Custom System Vendor / Manufacturer...",
                "ASUSTeK COMPUTER INC.",
                "Micro-Star International Co., Ltd.",
                "Gigabyte Technology Co., Ltd.",
                "LENOVO",
                "Dell Inc.",
                "HP",
                "Apple Inc."
            };
            INTN c = ui_select_modal("Spoof System Manufacturer / Vendor (SMBIOS Type 1)", vopts, 8, 0);
            if (c == 0) {
                edit_smbios_str_field("Spoof System Vendor",
                    "Enter custom Manufacturer string (up to 63 chars, TEMP in RAM):",
                    gHw.sys_manufacturer, s_sp.sys_vendor, sizeof(s_sp.sys_vendor), &s_sp.set_sys_vendor);
            } else if (c > 0) {
                str_cpy(s_sp.sys_vendor, vopts[c], sizeof(s_sp.sys_vendor));
                s_sp.set_sys_vendor = TRUE;
                if (spoof_rebuild_and_install_smbios(err, sizeof(err)))
                    show_post_spoof_temp_notice("System Vendor", s_sp.sys_vendor);
            }
            return TRUE;
        }

        case 3:
            edit_smbios_str_field("Spoof System Product / Model Name",
                "Enter Product / Model Name (SMBIOS Type 1, TEMP in RAM):",
                gHw.sys_product, s_sp.sys_product, sizeof(s_sp.sys_product), &s_sp.set_sys_product);
            return TRUE;

        case 4: {
            const CHAR8 *fopts[3] = {
                "Spoof System Version String...",
                "Spoof System SKU Number...",
                "Spoof System Family Name..."
            };
            INTN c = ui_select_modal("Spoof System Version / SKU / Family (Type 1)", fopts, 3, 0);
            if (c == 0)
                edit_smbios_str_field("Spoof System Version", "Enter System Version:",
                    gHw.sys_version, s_sp.sys_version, sizeof(s_sp.sys_version), &s_sp.set_sys_version);
            else if (c == 1)
                edit_smbios_str_field("Spoof System SKU", "Enter System SKU Number:",
                    gHw.sys_sku, s_sp.sys_sku, sizeof(s_sp.sys_sku), &s_sp.set_sys_sku);
            else if (c == 2)
                edit_smbios_str_field("Spoof System Family", "Enter System Family:",
                    gHw.sys_family, s_sp.sys_family, sizeof(s_sp.sys_family), &s_sp.set_sys_family);
            return TRUE;
        }

        case 5: {
            const CHAR8 *sopts[2] = {
                "Generate Random 12-Char Hardware Serial Number",
                "Enter Custom System Serial Number..."
            };
            INTN c = ui_select_modal("Spoof System Serial Number (Type 1)", sopts, 2, 0);
            if (c == 0) {
                gen_random_alnum(s_sp.sys_serial, 12, "SN");
                s_sp.set_sys_serial = TRUE;
                if (spoof_rebuild_and_install_smbios(err, sizeof(err)))
                    show_post_spoof_temp_notice("System Serial Number", s_sp.sys_serial);
            } else if (c == 1) {
                edit_smbios_str_field("Spoof System Serial Number", "Enter custom Serial Number:",
                    gHw.sys_serial, s_sp.sys_serial, sizeof(s_sp.sys_serial), &s_sp.set_sys_serial);
            }
            return TRUE;
        }

        case 6: {
            const CHAR8 *uopts[2] = {
                "Generate Random RFC-4122 v4 Hardware UUID",
                "Enter Custom 16-Byte UUID (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)..."
            };
            INTN c = ui_select_modal("Spoof System Hardware UUID (Type 1)", uopts, 2, 0);
            if (c == 0) {
                gen_random_uuid_wire(s_sp.sys_uuid_wire);
                s_sp.set_sys_uuid = TRUE;
                if (spoof_rebuild_and_install_smbios(err, sizeof(err)))
                    show_post_spoof_temp_notice("Hardware UUID", gHw.sys_uuid);
            } else if (c == 1) {
                CHAR8 uin[48];
                if (ui_input_modal("Custom Hardware UUID",
                                   "Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                                   gHw.sys_uuid, uin, sizeof(uin), FALSE)) {
                    if (parse_uuid_to_smbios_wire(uin, s_sp.sys_uuid_wire)) {
                        s_sp.set_sys_uuid = TRUE;
                        if (spoof_rebuild_and_install_smbios(err, sizeof(err)))
                            show_post_spoof_temp_notice("Hardware UUID", gHw.sys_uuid);
                    } else {
                        ui_message_modal("Invalid UUID", "UUID must contain exactly 32 hexadecimal digits.", TRUE);
                    }
                }
            }
            return TRUE;
        }

        case 7: {
            const CHAR8 *bopts[3] = {
                "Spoof BIOS Vendor (e.g. American Megatrends Inc., LENOVO, Dell Inc.)...",
                "Spoof BIOS Version String...",
                "Spoof BIOS Release Date (MM/DD/YYYY)..."
            };
            INTN c = ui_select_modal("Spoof BIOS Vendor / Version / Date (SMBIOS Type 0)", bopts, 3, 0);
            if (c == 0)
                edit_smbios_str_field("Spoof BIOS Vendor", "Enter BIOS Vendor name:",
                    gHw.bios_vendor, s_sp.bios_vendor, sizeof(s_sp.bios_vendor), &s_sp.set_bios_vendor);
            else if (c == 1)
                edit_smbios_str_field("Spoof BIOS Version", "Enter BIOS Version string:",
                    gHw.bios_version, s_sp.bios_version, sizeof(s_sp.bios_version), &s_sp.set_bios_version);
            else if (c == 2)
                edit_smbios_str_field("Spoof BIOS Date", "Enter BIOS Release Date (MM/DD/YYYY):",
                    gHw.bios_date, s_sp.bios_date, sizeof(s_sp.bios_date), &s_sp.set_bios_date);
            return TRUE;
        }

        case 8:
            edit_smbios_str_field("Spoof Baseboard / Motherboard Vendor",
                "Enter Baseboard Manufacturer (SMBIOS Type 2):",
                gHw.board_manufacturer[0] ? gHw.board_manufacturer : gHw.sys_manufacturer,
                s_sp.board_vendor, sizeof(s_sp.board_vendor), &s_sp.set_board_vendor);
            return TRUE;

        case 9: {
            const CHAR8 *mopts[3] = {
                "Spoof Baseboard Product / Model Name...",
                "Spoof Baseboard Serial Number (Custom)...",
                "Randomize Baseboard Serial Number"
            };
            INTN c = ui_select_modal("Spoof Baseboard Model & Serial (SMBIOS Type 2)", mopts, 3, 0);
            if (c == 0)
                edit_smbios_str_field("Spoof Baseboard Product", "Enter Baseboard Product/Model:",
                    gHw.board_product, s_sp.board_product, sizeof(s_sp.board_product), &s_sp.set_board_product);
            else if (c == 1)
                edit_smbios_str_field("Spoof Baseboard Serial", "Enter Baseboard Serial Number:",
                    gHw.board_serial, s_sp.board_serial, sizeof(s_sp.board_serial), &s_sp.set_board_serial);
            else if (c == 2) {
                gen_random_alnum(s_sp.board_serial, 14, "MB");
                s_sp.set_board_serial = TRUE;
                if (spoof_rebuild_and_install_smbios(err, sizeof(err)))
                    show_post_spoof_temp_notice("Baseboard Serial", s_sp.board_serial);
            }
            return TRUE;
        }

        case 10: {
            const CHAR8 *copts[4] = {
                "Spoof Chassis Vendor / Manufacturer...",
                "Spoof Chassis Enclosure Type (Desktop / Laptop / Server / Mini PC)...",
                "Spoof Chassis Serial Number...",
                "Spoof Chassis Asset Tag..."
            };
            INTN c = ui_select_modal("Spoof Chassis / Enclosure Identity (SMBIOS Type 3)", copts, 4, 0);
            if (c == 0) {
                edit_smbios_str_field("Spoof Chassis Vendor", "Enter Chassis Manufacturer:",
                    gHw.chassis_manufacturer[0] ? gHw.chassis_manufacturer : gHw.sys_manufacturer,
                    s_sp.chassis_vendor, sizeof(s_sp.chassis_vendor), &s_sp.set_chassis_vendor);
            } else if (c == 1) {
                static const UINT8 kCodes[7] = { 0x03, 0x07, 0x09, 0x0A, 0x0D, 0x11, 0x23 };
                const CHAR8 *topts[7] = {
                    "Desktop (0x03)",
                    "Tower Workstation (0x07)",
                    "Laptop (0x09)",
                    "Notebook (0x0A)",
                    "All-in-One / iMac (0x0D)",
                    "Main Server Chassis (0x11)",
                    "Mini PC (0x23)"
                };
                INTN tp = ui_select_modal("Select SMBIOS Type 3 Chassis Type", topts, 7, 0);
                if (tp >= 0) {
                    s_sp.chassis_type_code = kCodes[tp];
                    s_sp.set_chassis_type  = TRUE;
                    if (spoof_rebuild_and_install_smbios(err, sizeof(err)))
                        show_post_spoof_temp_notice("Chassis Type", gHw.chassis_type);
                }
            } else if (c == 2) {
                edit_smbios_str_field("Spoof Chassis Serial", "Enter Chassis Serial Number:",
                    gHw.chassis_serial, s_sp.chassis_serial, sizeof(s_sp.chassis_serial), &s_sp.set_chassis_serial);
            } else if (c == 3) {
                edit_smbios_str_field("Spoof Chassis Asset Tag", "Enter Chassis Asset Tag:",
                    gHw.chassis_asset_tag, s_sp.chassis_asset, sizeof(s_sp.chassis_asset), &s_sp.set_chassis_asset);
            }
            return TRUE;
        }

        case 11: {
            const CHAR8 *popts[2] = {
                "Spoof SMBIOS Processor Brand / Version String...",
                "Spoof SMBIOS Processor Manufacturer String..."
            };
            INTN c = ui_select_modal("Spoof Processor DMI Strings (SMBIOS Type 4)", popts, 2, 0);
            if (c == 0)
                edit_smbios_str_field("Spoof Processor Brand (SMBIOS Type 4)",
                    "Enter SMBIOS Processor Version string (Note: CPUID instruction unchanged):",
                    gHw.cpu_smbios_version[0] ? gHw.cpu_smbios_version : gHw.cpu_brand,
                    s_sp.cpu_brand, sizeof(s_sp.cpu_brand), &s_sp.set_cpu_brand);
            else if (c == 1)
                edit_smbios_str_field("Spoof Processor Vendor (SMBIOS Type 4)",
                    "Enter SMBIOS Processor Manufacturer (e.g. GenuineIntel / Advanced Micro Devices, Inc.):",
                    gHw.cpu_smbios_manufacturer[0] ? gHw.cpu_smbios_manufacturer : gHw.cpu_vendor,
                    s_sp.cpu_vendor, sizeof(s_sp.cpu_vendor), &s_sp.set_cpu_vendor);
            return TRUE;
        }

        case 12: {
            const CHAR8 *dopts[3] = {
                "Randomize All DIMM Serial Numbers (SMBIOS Type 17)",
                "Spoof DIMM Manufacturer Name (e.g. Samsung, SK Hynix, Kingston, Corsair)...",
                "Spoof DIMM Part Number..."
            };
            INTN c = ui_select_modal("Spoof RAM DIMM Identity (SMBIOS Type 17)", dopts, 3, 0);
            if (c == 0) {
                s_sp.dimm_serial_seed     = spoof_rand32();
                s_sp.set_dimm_serial_seed = TRUE;
                if (spoof_rebuild_and_install_smbios(err, sizeof(err)))
                    show_post_spoof_temp_notice("DIMM Serial Numbers", "Randomized Across All DIMMs");
            } else if (c == 1) {
                edit_smbios_str_field("Spoof DIMM Manufacturer", "Enter RAM Manufacturer:",
                    gHw.dimm_count > 0 ? gHw.dimms[0].manufacturer : "Samsung",
                    s_sp.dimm_vendor, sizeof(s_sp.dimm_vendor), &s_sp.set_dimm_vendor);
            } else if (c == 2) {
                edit_smbios_str_field("Spoof DIMM Part Number", "Enter RAM Part Number:",
                    gHw.dimm_count > 0 ? gHw.dimms[0].part_number : "DDR4-3200",
                    s_sp.dimm_part, sizeof(s_sp.dimm_part), &s_sp.set_dimm_part);
            }
            return TRUE;
        }

        case 13: {
            CHAR8 oem6[16], tbl8[16];
            if (ui_input_modal("Spoof ACPI OEM ID (6 Chars)",
                               "Enter 6-char ACPI OEM ID (e.g. ALASKA, LENOVO, DELL  , APPLE ):",
                               gHw.acpi_oem_id, oem6, 7, FALSE) &&
                ui_input_modal("Spoof ACPI OEM Table ID (8 Chars)",
                               "Enter 8-char OEM Table ID (or leave current):",
                               gHw.acpi_count > 0 ? gHw.acpi_tables[0].oem_table_id : "A M I   ",
                               tbl8, 9, FALSE)) {
                UINTN n = spoof_apply_acpi_oem(oem6, tbl8);
                if (n > 0) {
                    CHAR8 ok[64];
                    snprintf_ascii(ok, sizeof(ok), "%s (%u ACPI tables updated + CSUM fixed)", oem6, (UINT32)n);
                    show_post_spoof_temp_notice("ACPI OEM ID", ok);
                } else {
                    ui_message_modal("ACPI Read-Only", "ACPI tables are write-protected on this firmware.", TRUE);
                }
            }
            return TRUE;
        }

        case 14:
            handle_pci_subsys_spoof();
            return TRUE;

        case 15: {
            CHAR8 pw[40];
            if (ui_input_modal("Set Persistent Supervisor Password",
                               "Enter new password (leave blank to clear password):",
                               "", pw, sizeof(pw), FALSE)) {
                if (pw[0] == '\0') {
                    gSetup.cfg.has_supervisor_pw  = 0;
                    gSetup.cfg.supervisor_pw_hash = 0;
                    gSetup.cfg_dirty = TRUE;
                    ui_message_modal("Password Cleared", "Supervisor Password removed (press F10 to save to NVRAM).", FALSE);
                } else {
                    gSetup.cfg.has_supervisor_pw  = 1;
                    gSetup.cfg.supervisor_pw_hash = nvram_hash_password(pw);
                    gSetup.cfg_dirty = TRUE;
                    ui_message_modal("Password Staged", "Supervisor Password staged! Press F10 to save to NVRAM.", FALSE);
                }
            }
            return TRUE;
        }
    }

    return FALSE;
}
