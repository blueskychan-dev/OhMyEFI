#include "debug.h"
#include "hwinfo.h"
#include "nvram.h"
#include "ui.h"
#include "util.h"

/* Cached Memory Map for Debug Sub-View 1 & Address Lookup */
typedef struct {
    UINT32 Type;
    UINT64 PhysicalStart;
    UINT64 NumberOfPages;
    UINT64 Attribute;
} DBG_MEM_DESC;

#define DBG_MAX_MEM_DESCS 512

static DBG_MEM_DESC *gDbgMemMap = NULL;
static UINTN  gDbgMemCount = 0;
static UINTN  gDbgMapKey = 0;
static UINTN  gDbgDescSize = 0;
static UINT32 gDbgDescVer = 0;

static UINTN gDbgSubTab = 0; /* 0=NVRAM Vars, 1=MemMap, 2=Hex Jump, 3=Config Tables */
static UINTN gDbgCursor[4] = { 0, 0, 0, 0 };
static UINTN gDbgScroll[4] = { 0, 0, 0, 0 };
static CHAR8 gDbgVarFilter[40] = "";
static UINTN gFilteredVarIdx[NVRAM_MAX_VARS];
static UINTN gFilteredVarCount = 0;

static VOID refresh_dbg_memmap(VOID) {
    if (!gBS || !gBS->GetMemoryMap) return;
    if (!gDbgMemMap) {
        gDbgMemMap = (DBG_MEM_DESC *)alloc_zero_pool(sizeof(DBG_MEM_DESC) * DBG_MAX_MEM_DESCS);
        if (!gDbgMemMap) return;
    }
    gDbgMemCount = 0;

    UINTN msz = 0, mkey = 0, dsz = 0;
    UINT32 dver = 0;
    if (gBS->GetMemoryMap(&msz, NULL, &mkey, &dsz, &dver) != EFI_BUFFER_TOO_SMALL || msz == 0) {
        return;
    }
    msz += 8 * (dsz ? dsz : sizeof(EFI_MEMORY_DESCRIPTOR));
    UINT8 *buf = (UINT8 *)alloc_pool(msz);
    if (!buf) return;

    if (!EFI_ERROR(gBS->GetMemoryMap(&msz, (EFI_MEMORY_DESCRIPTOR *)buf, &mkey, &dsz, &dver))) {
        gDbgMapKey   = mkey;
        gDbgDescSize = dsz;
        gDbgDescVer  = dver;
        for (UINTN off = 0; off + dsz <= msz && gDbgMemCount < DBG_MAX_MEM_DESCS; off += dsz) {
            const EFI_MEMORY_DESCRIPTOR *d = (const EFI_MEMORY_DESCRIPTOR *)(buf + off);
            gDbgMemMap[gDbgMemCount].Type          = d->Type;
            gDbgMemMap[gDbgMemCount].PhysicalStart = d->PhysicalStart;
            gDbgMemMap[gDbgMemCount].NumberOfPages = d->NumberOfPages;
            gDbgMemMap[gDbgMemCount].Attribute     = d->Attribute;
            gDbgMemCount++;
        }
    }
    free_pool(buf);
    hw_refresh_memory_summary();
}

static UINT32 lookup_addr_mem_type(UINT64 addr) {
    for (UINTN i = 0; i < gDbgMemCount; i++) {
        UINT64 s = gDbgMemMap[i].PhysicalStart;
        UINT64 e = s + (gDbgMemMap[i].NumberOfPages << 12);
        if (addr >= s && addr < e) {
            return gDbgMemMap[i].Type;
        }
    }
    return 0xFFFFFFFFU;
}

static VOID rebuild_var_filter(VOID) {
    gFilteredVarCount = 0;
    for (UINTN i = 0; i < gVarCount && gFilteredVarCount < NVRAM_MAX_VARS; i++) {
        if (!gDbgVarFilter[0]) {
            gFilteredVarIdx[gFilteredVarCount++] = i;
        } else {
            const CHAR8 *fn = guid_friendly_name(&gVarList[i].guid);
            if (str_contains_icase(gVarList[i].name, gDbgVarFilter) ||
                (fn && str_contains_icase(fn, gDbgVarFilter)) ||
                str_contains_icase(gVarList[i].preview_str, gDbgVarFilter)) {
                gFilteredVarIdx[gFilteredVarCount++] = i;
            }
        }
    }
    if (gDbgCursor[0] >= gFilteredVarCount) {
        gDbgCursor[0] = (gFilteredVarCount > 0) ? (gFilteredVarCount - 1) : 0;
    }
}

VOID debug_init(VOID) {
    refresh_dbg_memmap();
    rebuild_var_filter();
}

static INT32 hex_nibble_from_char(CHAR16 uc) {
    if (uc >= L'0' && uc <= L'9') return (INT32)(uc - L'0');
    if (uc >= L'a' && uc <= L'f') return (INT32)(uc - L'a' + 10);
    if (uc >= L'A' && uc <= L'F') return (INT32)(uc - L'A' + 10);
    return -1;
}

/* =========================================================================
 * Live Physical Memory Hex Viewer & Patcher
 * ========================================================================= */
VOID debug_open_hex_editor(UINT64 initial_addr, const CHAR8 *title_hint) {
    refresh_dbg_memmap();
    cpu_invalidate_probe_cache();

    UINT64 top_addr = initial_addr & ~0xFULL;
    UINTN  cur_off  = (UINTN)(initial_addr & 0xFULL);
    BOOLEAN write_enabled = FALSE;
    BOOLEAN ascii_col = FALSE;
    INT32   pending_hi_nibble = -1;
    CHAR8   status_bar[80];
    snprintf_ascii(status_bar, sizeof(status_bar),
                   "E: Toggle Write Mode | G: GoTo Addr | Tab: Hex/ASCII | ESC: Back");

    for (;;) {
        UINTN hex_rows = (gUiRows > 9) ? (gUiRows - 9) : 12;
        UINTN win_bytes = hex_rows * 16;
        if (cur_off >= win_bytes) cur_off = win_bytes - 1;

        UINT64 cur_addr = top_addr + cur_off;
        CHAR8 hdr_title[72];
        snprintf_ascii(hdr_title, sizeof(hdr_title), "Live Memory Hex Editor - %s %s",
                       (title_hint && title_hint[0]) ? title_hint : "Physical RAM",
                       write_enabled ? "[WRITE ENABLED]" : "[READ-ONLY SAFE]");

        ui_draw_setup_frame(5, hdr_title, FALSE, NULL, NULL, status_bar);

        /* Inspector Info Row (Row 3) */
        BOOLEAN cur_mapped = FALSE, cur_rw = FALSE;
        cpu_probe_address(cur_addr, &cur_mapped, &cur_rw);
        UINT32 mtype = lookup_addr_mem_type(cur_addr);
        const CHAR8 *mt_str = (mtype == 0xFFFFFFFFU) ? "Unlisted" : efi_mem_type_short(mtype);

        UINT8 val_bytes[4] = { 0, 0, 0, 0 };
        BOOLEAN can_u32 = safe_read_mem(cur_addr, val_bytes, 4);
        UINT8 cur_b = 0;
        BOOLEAN can_u8 = safe_read_mem(cur_addr, &cur_b, 1);

        if (can_u8) {
            UINT32 u32v = (UINT32)val_bytes[0] | ((UINT32)val_bytes[1] << 8) |
                          ((UINT32)val_bytes[2] << 16) | ((UINT32)val_bytes[3] << 24);
            ui_printf(1, 3, write_enabled ? gTheme.warn_attr : gTheme.section_attr,
                      "Addr:0x%012lX [%s|%s] Byte:0x%02X(%3u) DWord:0x%08X",
                      cur_addr, mt_str, cur_rw ? "PTE:RW" : "PTE:RO",
                      cur_b, (UINT32)cur_b, can_u32 ? u32v : 0U);
        } else {
            ui_printf(1, 3, gTheme.warn_attr,
                      "Addr:0x%012lX [%s | UNMAPPED GUARD/HOLE - Page Fault Protected]",
                      cur_addr, mt_str);
        }

        /* Column Header (Row 4) */
        ui_puts_n(1, 4,
                  "Address      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  0123456789ABCDEF",
                  gUiCols - 2, gTheme.label_attr);

        /* Hex + ASCII Grid (Rows 5 .. 5 + hex_rows - 1) */
        for (UINTN r = 0; r < hex_rows; r++) {
            UINTN y = 5 + r;
            UINT64 row_addr = top_addr + r * 16;
            ui_printf(1, y, gTheme.section_attr, "%012lX", row_addr);

            for (UINTN c = 0; c < 16; c++) {
                UINTN boff = r * 16 + c;
                UINT64 baddr = row_addr + c;
                BOOLEAN is_cur = (boff == cur_off);

                BOOLEAN bm = FALSE, bw = FALSE;
                UINT8 bval = 0;
                if (cpu_probe_address(baddr, &bm, &bw) && bm) {
                    bval = *(const volatile UINT8 *)(UINTN)baddr;
                    UINT8 hex_attr = (is_cur && !ascii_col)
                                     ? gTheme.item_sel_attr
                                     : (bw ? gTheme.item_attr : gTheme.value_attr);
                    UINT8 asc_attr = (is_cur && ascii_col)
                                     ? gTheme.item_sel_attr
                                     : gTheme.label_attr;
                    if (is_cur && !ascii_col && pending_hi_nibble >= 0) {
                        ui_printf(14 + c * 3, y, gTheme.warn_attr, "%1X_", (UINT32)pending_hi_nibble);
                    } else {
                        ui_printf(14 + c * 3, y, hex_attr, "%02X", (UINT32)bval);
                    }
                    CHAR16 ach = (bval >= 0x20 && bval <= 0x7E) ? (CHAR16)bval : L'.';
                    ui_putc(62 + c, y, ach, asc_attr);
                } else {
                    UINT8 unm_attr = is_cur ? gTheme.item_sel_attr : gTheme.value_attr;
                    ui_puts(14 + c * 3, y, "--", unm_attr);
                    ui_putc(62 + c, y, L'?', unm_attr);
                }
            }
        }

        /* Bottom Hint Row inside frame */
        ui_puts_n(1, gUiRows - 3,
                  "Arrows/PgUp/PgDn:Move  G:GoTo  F:Find  Tab:Hex/ASC  E:WriteMode  ESC:Exit",
                  gUiCols - 2, gTheme.help_title_attr);

        ui_present();

        EFI_INPUT_KEY k;
        wait_key_blocking(&k);

        if (k.ScanCode == SCAN_ESC || k.UnicodeChar == 0x1B) {
            if (pending_hi_nibble >= 0) {
                pending_hi_nibble = -1;
                continue;
            }
            break;
        } else if (k.UnicodeChar == L'\t') {
            ascii_col = !ascii_col;
            pending_hi_nibble = -1;
        } else if (k.ScanCode == SCAN_LEFT) {
            pending_hi_nibble = -1;
            if (cur_off > 0) cur_off--;
            else if (top_addr >= 16) { top_addr -= 16; cur_off = 15; }
        } else if (k.ScanCode == SCAN_RIGHT) {
            pending_hi_nibble = -1;
            if (cur_off + 1 < win_bytes) cur_off++;
            else { top_addr += 16; cur_off = win_bytes - 16; }
        } else if (k.ScanCode == SCAN_UP) {
            pending_hi_nibble = -1;
            if (cur_off >= 16) cur_off -= 16;
            else if (top_addr >= 16) top_addr -= 16;
        } else if (k.ScanCode == SCAN_DOWN) {
            pending_hi_nibble = -1;
            if (cur_off + 16 < win_bytes) cur_off += 16;
            else top_addr += 16;
        } else if (k.ScanCode == SCAN_PAGE_UP || k.UnicodeChar == 0x15) {
            pending_hi_nibble = -1;
            if (top_addr >= win_bytes) top_addr -= win_bytes;
            else top_addr = 0;
        } else if (k.ScanCode == SCAN_PAGE_DOWN || k.UnicodeChar == 0x04) {
            pending_hi_nibble = -1;
            top_addr += win_bytes;
        } else if (!ascii_col && (k.UnicodeChar == L'g' || k.UnicodeChar == L'G')) {
            CHAR8 abuf[32], init_a[24];
            snprintf_ascii(init_a, sizeof(init_a), "0x%lX", cur_addr);
            if (ui_input_modal("Go To Physical Address", "Enter 64-bit Hex Address (e.g. 0x7F3E1000):",
                               init_a, abuf, sizeof(abuf), TRUE)) {
                UINT64 target = 0;
                if (parse_hex_u64(abuf, &target)) {
                    top_addr = target & ~0xFULL;
                    cur_off  = (UINTN)(target & 0xFULL);
                    pending_hi_nibble = -1;
                }
            }
        } else if (!ascii_col && (k.UnicodeChar == L'f' || k.UnicodeChar == L'F') && !write_enabled) {
            CHAR8 fbuf[48];
            if (ui_input_modal("Find ASCII String Forward", "Search mapped pages from current address (max 16 MB):",
                               "", fbuf, sizeof(fbuf), FALSE) && fbuf[0]) {
                UINTN flen = str_len(fbuf);
                BOOLEAN found = FALSE;
                for (UINT64 off_s = 1; off_s < (16ULL << 20); off_s++) {
                    UINT64 cand = cur_addr + off_s;
                    UINT8 tmp[48];
                    if (!safe_read_mem(cand, tmp, flen)) {
                        /* Skip unmapped 4KB page fast */
                        off_s = ((cand + 0x1000ULL) & ~0xFFFULL) - cur_addr - 1;
                        continue;
                    }
                    BOOLEAN eq = TRUE;
                    for (UINTN j = 0; j < flen; j++) {
                        CHAR8 a = (CHAR8)tmp[j], b = fbuf[j];
                        if (a >= 'A' && a <= 'Z') a = (CHAR8)(a + 32);
                        if (b >= 'A' && b <= 'Z') b = (CHAR8)(b + 32);
                        if (a != b) { eq = FALSE; break; }
                    }
                    if (eq) {
                        top_addr = cand & ~0xFULL;
                        cur_off  = (UINTN)(cand & 0xFULL);
                        snprintf_ascii(status_bar, sizeof(status_bar), "Found \"%s\" at 0x%lX", fbuf, cand);
                        found = TRUE;
                        break;
                    }
                }
                if (!found) {
                    snprintf_ascii(status_bar, sizeof(status_bar), "Not found within +16 MB from 0x%lX", cur_addr);
                }
            }
        } else if ((!ascii_col && (k.UnicodeChar == L'e' || k.UnicodeChar == L'E') && !write_enabled) ||
                   k.ScanCode == SCAN_F2) {
            write_enabled = !write_enabled;
            pending_hi_nibble = -1;
            snprintf_ascii(status_bar, sizeof(status_bar),
                           write_enabled
                           ? "LIVE WRITE MODE ACTIVE! Type Hex (or F2 to lock Read-Only)"
                           : "Locked to Read-Only Safe Mode (Press E or F2 to unlock writes)");
        } else if (write_enabled) {
            if (!ascii_col) {
                INT32 nib = hex_nibble_from_char(k.UnicodeChar);
                if (nib >= 0) {
                    if (pending_hi_nibble < 0) {
                        pending_hi_nibble = nib;
                    } else {
                        UINT8 new_val = (UINT8)((pending_hi_nibble << 4) | nib);
                        pending_hi_nibble = -1;
                        BOOLEAN allow = TRUE;
                        if (mtype == EfiMemoryMappedIO || mtype == EfiMemoryMappedIOPortSpace) {
                            allow = ui_confirm_modal("MMIO Write Warning",
                                "Target address is inside Hardware MMIO space! Write byte anyway?", FALSE);
                        }
                        if (allow) {
                            BOOLEAN ver = FALSE;
                            if (safe_write_byte(cur_addr, new_val, &ver)) {
                                snprintf_ascii(status_bar, sizeof(status_bar),
                                    ver ? "PATCHED 0x%lX <= 0x%02X (Verified in RAM)"
                                        : "Wrote 0x%02X to 0x%lX, readback unchanged (ROM/Locked)",
                                    cur_addr, new_val);
                                if (cur_off + 1 < win_bytes) cur_off++;
                            } else {
                                snprintf_ascii(status_bar, sizeof(status_bar),
                                    "BLOCKED: Page at 0x%lX is Read-Only or Unmapped in CR3", cur_addr);
                            }
                        }
                    }
                }
            } else if (k.UnicodeChar >= 0x20 && k.UnicodeChar <= 0x7E) {
                UINT8 new_val = (UINT8)k.UnicodeChar;
                BOOLEAN ver = FALSE;
                if (safe_write_byte(cur_addr, new_val, &ver) && ver) {
                    snprintf_ascii(status_bar, sizeof(status_bar),
                                   "PATCHED 0x%lX <= '%c' (0x%02X)", cur_addr, (CHAR8)new_val, new_val);
                    if (cur_off + 1 < win_bytes) cur_off++;
                } else {
                    snprintf_ascii(status_bar, sizeof(status_bar),
                                   "Write rejected at 0x%lX (Read-Only / ROM)", cur_addr);
                }
            }
        }
    }
}

/* =========================================================================
 * NVRAM Variable Full Hex / ASCII / Setup-Offset Editor
 * ========================================================================= */
VOID debug_open_var_editor(UINTN var_idx) {
    if (!gVarList || var_idx >= gVarCount) return;
    NVRAM_VAR_ENTRY ve = gVarList[var_idx];

    UINT32 attrs = 0;
    UINTN  data_sz = 0;
    UINT8 *orig_buf = NULL;
    EFI_STATUS st = nvram_read_var(ve.name_w, &ve.guid, &attrs, &data_sz, &orig_buf);
    if (EFI_ERROR(st) || !orig_buf || data_sz == 0) {
        ui_message_modal("Variable Empty / Unreadable",
                         "Cannot read data payload for this EFI variable.", TRUE);
        return;
    }

    UINT8 *edit_buf = (UINT8 *)alloc_pool(data_sz);
    if (!edit_buf) {
        free_pool(orig_buf);
        return;
    }
    memcpy(edit_buf, orig_buf, data_sz);

    UINTN   top_row_off = 0;
    UINTN   cur_pos     = 0;
    BOOLEAN ascii_col   = FALSE;
    BOOLEAN modified    = FALSE;
    INT32   hi_nib      = -1;
    CHAR8   guid_s[40];
    guid_to_str(&ve.guid, guid_s, sizeof(guid_s));
    const CHAR8 *fname = guid_friendly_name(&ve.guid);

    CHAR8 status_bar[80];
    str_cpy(status_bar, "Type Hex/ASCII to Edit | G:Jump Offset | F2:Write NVRAM | Del:Delete | ESC:Back",
            sizeof(status_bar));

    for (;;) {
        UINTN hex_rows = (gUiRows > 10) ? (gUiRows - 10) : 11;
        if (cur_pos >= data_sz) cur_pos = data_sz - 1;
        UINTN cur_row = cur_pos / 16;
        UINTN top_row = top_row_off / 16;
        if (cur_row < top_row) top_row = cur_row;
        if (cur_row >= top_row + hex_rows) top_row = cur_row - hex_rows + 1;
        top_row_off = top_row * 16;

        CHAR8 title[72];
        snprintf_ascii(title, sizeof(title), "NVRAM Variable Editor: %s (%u bytes)%s",
                       ve.name, (UINT32)data_sz, modified ? " [MODIFIED]" : "");
        ui_draw_setup_frame(5, title, FALSE, NULL, NULL, status_bar);

        ui_printf(1, 3, gTheme.section_attr,
                  "GUID: %s (%s)  Attr:0x%02X [%s%s%s%s]",
                  guid_s, fname ? fname : "Vendor", attrs,
                  (attrs & EFI_VARIABLE_NON_VOLATILE) ? "NV " : "",
                  (attrs & EFI_VARIABLE_BOOTSERVICE_ACCESS) ? "BS " : "",
                  (attrs & EFI_VARIABLE_RUNTIME_ACCESS) ? "RT " : "",
                  (attrs & (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
                            EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) ? "AUTH" : "RW");

        ui_printf(1, 4, modified ? gTheme.warn_attr : gTheme.label_attr,
                  "setup_var Offset: 0x%04X (%u)  Orig: 0x%02X -> Current: 0x%02X (%u)",
                  (UINT32)cur_pos, (UINT32)cur_pos,
                  orig_buf[cur_pos], edit_buf[cur_pos], (UINT32)edit_buf[cur_pos]);

        ui_puts_n(1, 5,
                  "Offset       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  0123456789ABCDEF",
                  gUiCols - 2, gTheme.label_attr);

        for (UINTN r = 0; r < hex_rows; r++) {
            UINTN roff = (top_row + r) * 16;
            if (roff >= data_sz) break;
            UINTN y = 6 + r;
            ui_printf(1, y, gTheme.section_attr, "+0x%08X ", (UINT32)roff);

            for (UINTN c = 0; c < 16; c++) {
                UINTN idx = roff + c;
                if (idx >= data_sz) break;
                BOOLEAN is_cur = (idx == cur_pos);
                BOOLEAN is_diff = (edit_buf[idx] != orig_buf[idx]);

                UINT8 ha = (is_cur && !ascii_col)
                           ? gTheme.item_sel_attr
                           : (is_diff ? gTheme.warn_attr : gTheme.item_attr);
                UINT8 aa = (is_cur && ascii_col)
                           ? gTheme.item_sel_attr
                           : (is_diff ? gTheme.warn_attr : gTheme.label_attr);

                if (is_cur && !ascii_col && hi_nib >= 0) {
                    ui_printf(14 + c * 3, y, gTheme.warn_attr, "%1X_", (UINT32)hi_nib);
                } else {
                    ui_printf(14 + c * 3, y, ha, "%02X", (UINT32)edit_buf[idx]);
                }
                CHAR16 ach = (edit_buf[idx] >= 0x20 && edit_buf[idx] <= 0x7E) ? (CHAR16)edit_buf[idx] : L'.';
                ui_putc(62 + c, y, ach, aa);
            }
        }

        ui_puts_n(1, gUiRows - 3,
                  "F2 / Ctrl+S: Write to Real NVRAM   G: GoTo Offset   Tab: Hex/ASCII   Del: Delete Var",
                  gUiCols - 2, gTheme.help_title_attr);

        ui_present();

        EFI_INPUT_KEY k;
        wait_key_blocking(&k);

        if (k.ScanCode == SCAN_ESC || k.UnicodeChar == 0x1B) {
            if (hi_nib >= 0) { hi_nib = -1; continue; }
            if (!modified || ui_confirm_modal("Discard Edits?", "Discard unsaved byte edits to this variable?", TRUE)) {
                break;
            }
        } else if (k.UnicodeChar == L'\t') {
            ascii_col = !ascii_col;
            hi_nib = -1;
        } else if (k.ScanCode == SCAN_LEFT) {
            hi_nib = -1;
            if (cur_pos > 0) cur_pos--;
        } else if (k.ScanCode == SCAN_RIGHT) {
            hi_nib = -1;
            if (cur_pos + 1 < data_sz) cur_pos++;
        } else if (k.ScanCode == SCAN_UP) {
            hi_nib = -1;
            if (cur_pos >= 16) cur_pos -= 16;
        } else if (k.ScanCode == SCAN_DOWN) {
            hi_nib = -1;
            if (cur_pos + 16 < data_sz) cur_pos += 16;
        } else if (k.ScanCode == SCAN_PAGE_UP || k.UnicodeChar == 0x15) {
            hi_nib = -1;
            UINTN step = hex_rows * 16;
            cur_pos = (cur_pos > step) ? (cur_pos - step) : 0;
        } else if (k.ScanCode == SCAN_PAGE_DOWN || k.UnicodeChar == 0x04) {
            hi_nib = -1;
            UINTN step = hex_rows * 16;
            cur_pos = (cur_pos + step < data_sz) ? (cur_pos + step) : (data_sz - 1);
        } else if (!ascii_col && (k.UnicodeChar == L'g' || k.UnicodeChar == L'G')) {
            CHAR8 obuf[24];
            if (ui_input_modal("Jump to VarStore Offset", "Enter Hex or Decimal Offset (e.g. 0x42):",
                               "0x0", obuf, sizeof(obuf), FALSE)) {
                UINT64 offv = 0;
                if (parse_dec_u64(obuf, &offv) && offv < data_sz) {
                    cur_pos = (UINTN)offv;
                }
            }
        } else if (k.ScanCode == SCAN_F2 || k.UnicodeChar == 0x13 /* Ctrl+S */) {
            if (ui_confirm_modal("Write Variable to NVRAM",
                                 "Call RT->SetVariable() to commit modified bytes to UEFI NVRAM?", TRUE)) {
                EFI_STATUS wst = nvram_write_var(ve.name_w, &ve.guid, attrs, data_sz, edit_buf);
                if (!EFI_ERROR(wst)) {
                    memcpy(orig_buf, edit_buf, data_sz);
                    modified = FALSE;
                    nvram_enumerate_all();
                    rebuild_var_filter();
                    str_cpy(status_bar, "SUCCESS: Variable written to real UEFI NVRAM!", sizeof(status_bar));
                } else {
                    snprintf_ascii(status_bar, sizeof(status_bar),
                                   "SetVariable FAILED: %s", efi_status_str(wst));
                }
            }
        } else if (k.ScanCode == SCAN_DELETE) {
            if (ui_confirm_modal("Delete NVRAM Variable",
                                 "Permanently delete this variable from UEFI NVRAM?", FALSE)) {
                EFI_STATUS dst = nvram_delete_var(ve.name_w, &ve.guid);
                if (!EFI_ERROR(dst)) {
                    nvram_enumerate_all();
                    rebuild_var_filter();
                    ui_message_modal("Variable Deleted", "Variable removed from UEFI NVRAM.", FALSE);
                    break;
                } else {
                    snprintf_ascii(status_bar, sizeof(status_bar),
                                   "Delete FAILED: %s", efi_status_str(dst));
                }
            }
        } else if (!ascii_col) {
            INT32 nib = hex_nibble_from_char(k.UnicodeChar);
            if (nib >= 0) {
                if (hi_nib < 0) {
                    hi_nib = nib;
                } else {
                    edit_buf[cur_pos] = (UINT8)((hi_nib << 4) | nib);
                    hi_nib = -1;
                    modified = TRUE;
                    if (cur_pos + 1 < data_sz) cur_pos++;
                }
            }
        } else if (k.UnicodeChar >= 0x20 && k.UnicodeChar <= 0x7E) {
            edit_buf[cur_pos] = (UINT8)k.UnicodeChar;
            modified = TRUE;
            if (cur_pos + 1 < data_sz) cur_pos++;
        }
    }

    free_pool(edit_buf);
    free_pool(orig_buf);
}

/* =========================================================================
 * 256-Byte PCI Configuration Space Viewer & Editor
 * ========================================================================= */
VOID debug_open_pci_config_editor(UINTN pci_idx) {
    if (pci_idx >= gHw.pci_count) return;
    HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];
    if (!pd->pci_io) return;

    UINT8 cfg[256];
    UINTN cur = 0;
    BOOLEAN write_en = FALSE;
    INT32 hi_nib = -1;
    CHAR8 status_bar[80];
    str_cpy(status_bar, "Arrows:Move | E:Toggle PCI Config Write | R:Reload | ESC:Back", sizeof(status_bar));

    pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint8, 0, 256, cfg);

    for (;;) {
        CHAR8 title[72];
        snprintf_ascii(title, sizeof(title), "PCI %02X:%02X.%X [%04X:%04X] %s %s",
                       pd->bus, pd->dev, pd->func, pd->vendor_id, pd->device_id,
                       pd->vendor_name, write_en ? "[WRITE]" : "[READ]");
        ui_draw_setup_frame(5, title, FALSE, NULL, NULL, status_bar);

        UINT16 cmd_reg = (UINT16)cfg[4] | ((UINT16)cfg[5] << 8);
        ui_printf(1, 3, gTheme.section_attr,
                  "Class: %s  Cmd:0x%04X [IO:%u MEM:%u BusMaster:%u]  Offset:0x%02X = 0x%02X",
                  pd->class_name, cmd_reg,
                  (cmd_reg & 1) ? 1 : 0, (cmd_reg & 2) ? 1 : 0, (cmd_reg & 4) ? 1 : 0,
                  (UINT32)cur, (UINT32)cfg[cur]);

        ui_puts_n(1, 4,
                  "Reg   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII",
                  gUiCols - 2, gTheme.label_attr);

        UINTN vis_r = (gUiRows > 8) ? (gUiRows - 8) : 16;
        if (vis_r > 16) vis_r = 16;
        UINTN top_r = 0;
        if (cur / 16 >= vis_r) top_r = (cur / 16) - vis_r + 1;

        for (UINTN r = 0; r < vis_r && (top_r + r) < 16; r++) {
            UINTN rr = top_r + r;
            UINTN y = 5 + r;
            ui_printf(1, y, gTheme.section_attr, "%02X: ", (UINT32)(rr * 16));
            for (UINTN c = 0; c < 16; c++) {
                UINTN idx = rr * 16 + c;
                BOOLEAN is_c = (idx == cur);
                UINT8 a = is_c ? gTheme.item_sel_attr : gTheme.item_attr;
                if (is_c && hi_nib >= 0) {
                    ui_printf(6 + c * 3, y, gTheme.warn_attr, "%1X_", (UINT32)hi_nib);
                } else {
                    ui_printf(6 + c * 3, y, a, "%02X", (UINT32)cfg[idx]);
                }
                CHAR16 ach = (cfg[idx] >= 0x20 && cfg[idx] <= 0x7E) ? (CHAR16)cfg[idx] : L'.';
                ui_putc(55 + c, y, ach, gTheme.label_attr);
            }
        }
        ui_present();

        EFI_INPUT_KEY k;
        wait_key_blocking(&k);
        if (k.ScanCode == SCAN_ESC || k.UnicodeChar == 0x1B) {
            break;
        } else if (k.ScanCode == SCAN_LEFT && cur > 0) {
            cur--; hi_nib = -1;
        } else if (k.ScanCode == SCAN_RIGHT && cur < 255) {
            cur++; hi_nib = -1;
        } else if (k.ScanCode == SCAN_UP && cur >= 16) {
            cur -= 16; hi_nib = -1;
        } else if (k.ScanCode == SCAN_DOWN && cur + 16 < 256) {
            cur += 16; hi_nib = -1;
        } else if (k.UnicodeChar == L'r' || k.UnicodeChar == L'R') {
            pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint8, 0, 256, cfg);
            str_cpy(status_bar, "Reloaded 256-byte PCI Configuration Space.", sizeof(status_bar));
        } else if ((k.UnicodeChar == L'e' || k.UnicodeChar == L'E') && !write_en) {
            write_en = TRUE;
            str_cpy(status_bar, "PCI WRITE UNLOCKED! Type 2 hex digits to write PCI config register.", sizeof(status_bar));
        } else if (k.ScanCode == SCAN_F2) {
            write_en = !write_en;
        } else if (write_en) {
            INT32 nib = hex_nibble_from_char(k.UnicodeChar);
            if (nib >= 0) {
                if (hi_nib < 0) hi_nib = nib;
                else {
                    UINT8 nv = (UINT8)((hi_nib << 4) | nib);
                    hi_nib = -1;
                    pd->pci_io->Pci.Write(pd->pci_io, EfiPciIoWidthUint8, (UINT32)cur, 1, &nv);
                    pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint8, 0, 256, cfg);
                    snprintf_ascii(status_bar, sizeof(status_bar),
                                   "Wrote PCI[0x%02X] <= 0x%02X (Readback: 0x%02X)",
                                   (UINT32)cur, nv, cfg[cur]);
                }
            }
        }
    }
}

/* =========================================================================
 * Create New EFI Variable Dialog
 * ========================================================================= */
static VOID create_new_nvram_var_dialog(VOID) {
    CHAR8 vname[48];
    if (!ui_input_modal("Create New EFI NVRAM Variable",
                        gHw.is_apple_mac ? "Enter Variable Name (e.g. MyCustomVar or boot-args):"
                                         : "Enter Variable Name (e.g. MyCustomVar):",
                        "", vname, sizeof(vname), FALSE) || !vname[0]) {
        return;
    }

    const CHAR8 *ns_opts_mac[4] = {
        "EfiGlobalVariable  (8BE4DF61-93CA-11D2-AA0D-00E098032B8C)",
        "AppleBoot NVRAM    (7C436110-AB2A-4BBB-A880-FE41995C9F82)",
        "SetupUtilConfig    (2011B105-EF15-4E75-A211-5E70CF602011)",
        "Custom GUID String (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)"
    };
    const CHAR8 *ns_opts_pc[3] = {
        "EfiGlobalVariable  (8BE4DF61-93CA-11D2-AA0D-00E098032B8C)",
        "SetupUtilConfig    (2011B105-EF15-4E75-A211-5E70CF602011)",
        "Custom GUID String (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)"
    };
    INTN ns = gHw.is_apple_mac
              ? ui_select_modal("Select Variable Vendor GUID", ns_opts_mac, 4, 0)
              : ui_select_modal("Select Variable Vendor GUID", ns_opts_pc, 3, 0);
    if (ns < 0) return;

    EFI_GUID target_guid = gEfiGlobalVariableGuid;
    if (gHw.is_apple_mac) {
        if (ns == 1) target_guid = gAppleBootVariableGuid;
        else if (ns == 2) target_guid = gSetupUtilityConfigGuid;
        else if (ns == 3) {
            CHAR8 gs[48];
            if (!ui_input_modal("Custom Vendor GUID", "Format: 12345678-1234-1234-1234-123456789ABC",
                                "", gs, sizeof(gs), FALSE) || !parse_guid_str(gs, &target_guid)) {
                ui_message_modal("Invalid GUID", "Could not parse GUID string.", TRUE);
                return;
            }
        }
    } else {
        if (ns == 1) target_guid = gSetupUtilityConfigGuid;
        else if (ns == 2) {
            CHAR8 gs[48];
            if (!ui_input_modal("Custom Vendor GUID", "Format: 12345678-1234-1234-1234-123456789ABC",
                                "", gs, sizeof(gs), FALSE) || !parse_guid_str(gs, &target_guid)) {
                ui_message_modal("Invalid GUID", "Could not parse GUID string.", TRUE);
                return;
            }
        }
    }

    const CHAR8 *fmt_opts[2] = {
        "Hex Bytes (e.g. 01 00 00 00)",
        "ASCII String (NUL-terminated)"
    };
    INTN vfmt = ui_select_modal("Select Payload Format", fmt_opts, 2, 0);
    if (vfmt < 0) return;

    CHAR8 val_in[96];
    if (!ui_input_modal("Variable Data Payload",
                        (vfmt == 0) ? "Enter Hex Bytes:" : "Enter ASCII String:",
                        "", val_in, sizeof(val_in), vfmt == 0)) {
        return;
    }

    UINT8 payload[96];
    UINTN plen = 0;
    if (vfmt == 0) {
        plen = parse_hex_bytes(val_in, payload, sizeof(payload));
    } else {
        plen = str_len(val_in) + 1;
        memcpy(payload, val_in, plen);
    }
    if (plen == 0) {
        ui_message_modal("Empty Payload", "No bytes provided.", TRUE);
        return;
    }

    CHAR16 wname[64];
    ascii_to_wstr(wname, vname, 64);
    UINT32 attr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
    EFI_STATUS st = nvram_write_var(wname, &target_guid, attr, plen, payload);
    if (!EFI_ERROR(st)) {
        nvram_enumerate_all();
        rebuild_var_filter();
        ui_message_modal("Variable Created", "New EFI variable written to NVRAM successfully!", FALSE);
    } else {
        CHAR8 err[80];
        snprintf_ascii(err, sizeof(err), "RT->SetVariable returned: %s", efi_status_str(st));
        ui_message_modal("SetVariable Error", err, TRUE);
    }
}

/* =========================================================================
 * Debug Main Tab Rendering & Input
 * ========================================================================= */
VOID debug_draw_tab(VOID) {
    if (gFilteredVarCount == 0 && !gDbgVarFilter[0] && gVarCount > 0) {
        rebuild_var_filter();
    }
    if (gDbgMemCount == 0) {
        refresh_dbg_memmap();
    }

    const CHAR8 *footer = "Tab or 1-4: Switch Debug View | Enter: Inspect/Edit | /: Filter | N: New Var | R: Refresh";
    ui_draw_setup_frame(5, "EFI Debug Inspector (All Variables, Memory Map & Live Hex)", FALSE, NULL, NULL, footer);

    /* Sub-Tab Bar at Row 3 */
    CHAR8 sub0[28], sub1[28];
    snprintf_ascii(sub0, sizeof(sub0), " 1:Vars(%u) ",   (UINT32)gFilteredVarCount);
    snprintf_ascii(sub1, sizeof(sub1), " 2:MemMap(%u) ", (UINT32)gDbgMemCount);
    const CHAR8 *subs[4] = { sub0, sub1, " 3:Hex Patcher ", " 4:Config Tables " };

    UINTN sx = 2;
    for (UINTN i = 0; i < 4; i++) {
        UINT8 a = (i == gDbgSubTab) ? gTheme.item_sel_attr : gTheme.section_attr;
        ui_puts(sx, 3, subs[i], a);
        sx += str_len(subs[i]) + 1;
    }

    UINTN x = 2;
    UINTN w = gUiCols - 4;
    UINTN vis_rows = (gUiRows > 9) ? (gUiRows - 9) : 12;

    if (gDbgSubTab == 0) {
        /* Sub-View 0: All EFI NVRAM Variables */
        if (gSetup.storage_info_valid) {
            ui_printf(x, 4, gTheme.label_attr,
                      "Max:%luKB Free:%luKB MaxVar:%luKB Flt:\"%s\" (/=Find C=Clr N=New)",
                      gSetup.max_storage_bytes >> 10, gSetup.rem_storage_bytes >> 10,
                      gSetup.max_var_bytes >> 10, gDbgVarFilter[0] ? gDbgVarFilter : "*");
        } else {
            ui_printf(x, 4, gTheme.label_attr,
                      "Total EFI Vars:%u  Filter:\"%s\"  (/=Find, C=Clear, N=New Var)",
                      (UINT32)gVarCount, gDbgVarFilter[0] ? gDbgVarFilter : "*");
        }

        ui_puts_n(x, 5, "Variable Name            Namespace      Attr    Size   Value / Preview", w, gTheme.section_attr);

        if (gDbgCursor[0] < gDbgScroll[0]) gDbgScroll[0] = gDbgCursor[0];
        if (gDbgCursor[0] >= gDbgScroll[0] + vis_rows) gDbgScroll[0] = gDbgCursor[0] - vis_rows + 1;

        for (UINTN r = 0; r < vis_rows && (gDbgScroll[0] + r) < gFilteredVarCount; r++) {
            UINTN fidx = gDbgScroll[0] + r;
            const NVRAM_VAR_ENTRY *v = &gVarList[gFilteredVarIdx[fidx]];
            BOOLEAN sel = (fidx == gDbgCursor[0]);
            UINT8 a = sel ? gTheme.item_sel_attr : gTheme.item_attr;
            ui_hline(x, 6 + r, w, L' ', sel ? a : gTheme.body_attr);

            const CHAR8 *gn = guid_friendly_name(&v->guid);
            CHAR8 gshort[15];
            if (gn) str_cpy(gshort, gn, sizeof(gshort));
            else snprintf_ascii(gshort, sizeof(gshort), "%08X..", v->guid.Data1);

            CHAR8 attr_s[8];
            snprintf_ascii(attr_s, sizeof(attr_s), "%c%c%c%c",
                           (v->attributes & EFI_VARIABLE_NON_VOLATILE) ? 'N' : '-',
                           (v->attributes & EFI_VARIABLE_BOOTSERVICE_ACCESS) ? 'B' : '-',
                           (v->attributes & EFI_VARIABLE_RUNTIME_ACCESS) ? 'R' : '-',
                           v->is_writable_hint ? 'W' : 'L');

            CHAR8 row_txt[160];
            snprintf_ascii(row_txt, sizeof(row_txt), "%-24.24s %-14.14s %-5s %6uB  %s",
                           v->name, gshort, attr_s, (UINT32)v->data_size, v->preview_str);
            ui_puts_n(x, 6 + r, row_txt, w, a);
        }
    } else if (gDbgSubTab == 1) {
        /* Sub-View 1: Full EFI Memory Map */
        ui_printf(x, 4, gTheme.label_attr,
                  "RAM:%luMB Usable:%luMB ACPI:%luKB RT:%luKB BS:%luMB MMIO:%luMB (MapKey:0x%X)",
                  gHw.total_ram_bytes >> 20, gHw.usable_ram_bytes >> 20,
                  gHw.acpi_ram_bytes >> 10, gHw.runtime_ram_bytes >> 10,
                  gHw.boot_svcs_bytes >> 20, gHw.mmio_bytes >> 20, (UINT32)gDbgMapKey);

        ui_puts_n(x, 5, "Idx  Type      Physical Start      Pages     Size       Attr / PTE", w, gTheme.section_attr);

        if (gDbgCursor[1] >= gDbgMemCount && gDbgMemCount > 0) gDbgCursor[1] = gDbgMemCount - 1;
        if (gDbgCursor[1] < gDbgScroll[1]) gDbgScroll[1] = gDbgCursor[1];
        if (gDbgCursor[1] >= gDbgScroll[1] + vis_rows) gDbgScroll[1] = gDbgCursor[1] - vis_rows + 1;

        for (UINTN r = 0; r < vis_rows && (gDbgScroll[1] + r) < gDbgMemCount; r++) {
            UINTN idx = gDbgScroll[1] + r;
            const DBG_MEM_DESC *d = &gDbgMemMap[idx];
            BOOLEAN sel = (idx == gDbgCursor[1]);
            UINT8 a = sel ? gTheme.item_sel_attr : gTheme.item_attr;
            ui_hline(x, 6 + r, w, L' ', sel ? a : gTheme.body_attr);

            UINT64 kb = (d->NumberOfPages << 12) >> 10;
            CHAR8 sz_s[16];
            if (kb >= 10240ULL) snprintf_ascii(sz_s, sizeof(sz_s), "%6lu MB", kb >> 10);
            else snprintf_ascii(sz_s, sizeof(sz_s), "%6lu KB", kb);

            BOOLEAN mp = FALSE, rw = FALSE;
            cpu_probe_address(d->PhysicalStart, &mp, &rw);

            CHAR8 row_txt[160];
            snprintf_ascii(row_txt, sizeof(row_txt),
                           "%3u  %-8s  0x%016lX  %7lu  %s  %s%s [%s]",
                           (UINT32)idx, efi_mem_type_short(d->Type), d->PhysicalStart,
                           d->NumberOfPages, sz_s,
                           (d->Attribute & EFI_MEMORY_WB) ? "WB " : "UC ",
                           (d->Attribute & EFI_MEMORY_RT) ? "RT" : "  ",
                           mp ? (rw ? "PTE:RW" : "PTE:RO") : "UNMAP");
            ui_puts_n(x, 6 + r, row_txt, w, a);
        }
    } else if (gDbgSubTab == 2) {
        /* Sub-View 2: Quick Jump Targets into Live Memory Hex Editor */
        ui_puts_n(x, 4, "Select a Live Physical Memory Landmark or Enter Any Custom 64-bit Address:", w, gTheme.label_attr);
        const CHAR8 *labels[7] = {
            "Enter Custom 64-bit Physical Memory Address...",
            "Inspect EFI_SYSTEM_TABLE (gST) in RAM",
            "Inspect EFI_RUNTIME_SERVICES (gRT) in RAM",
            "Inspect EFI_BOOT_SERVICES (gBS) in RAM",
            "Inspect SMBIOS Structure Table in RAM",
            "Inspect ACPI RSDP / Root Pointer in RAM",
            "Inspect GOP Video Framebuffer Base (MMIO)"
        };
        UINT64 addrs[7] = {
            0x100000ULL,
            (UINT64)(UINTN)gST,
            (UINT64)(UINTN)gRT,
            (UINT64)(UINTN)gBS,
            gHw.smbios_table_addr,
            gHw.acpi_rsdp_addr,
            gHw.gop_fb_base
        };
        if (gDbgCursor[2] >= 7) gDbgCursor[2] = 6;
        for (UINTN i = 0; i < 7; i++) {
            BOOLEAN sel = (i == gDbgCursor[2]);
            UINT8 a = sel ? gTheme.item_sel_attr : gTheme.item_attr;
            ui_hline(x, 6 + i, w, L' ', sel ? a : gTheme.body_attr);
            ui_putc(x, 6 + i, gBox.arrow_r, a);
            if (i == 0) {
                ui_puts_n(x + 2, 6 + i, labels[i], w - 2, a);
            } else {
                ui_printf(x + 2, 6 + i, a, "%-46s [0x%016lX]", labels[i], addrs[i]);
            }
        }
    } else {
        /* Sub-View 3: EFI System Table & Configuration Tables */
        ui_printf(x, 4, gTheme.label_attr,
                  "ST:0x%lX  BS:0x%lX  RT:0x%lX  SelfImg:0x%lX (%luKB)",
                  (UINT64)(UINTN)gST, (UINT64)(UINTN)gBS, (UINT64)(UINTN)gRT,
                  gHw.image_base, gHw.image_size >> 10);

        ui_puts_n(x, 5, "Idx Table Name      Vendor GUID                          Phys Address", w, gTheme.section_attr);

        UINTN ct_cnt = gST ? gST->NumberOfTableEntries : 0;
        if (gDbgCursor[3] >= ct_cnt && ct_cnt > 0) gDbgCursor[3] = ct_cnt - 1;
        if (gDbgCursor[3] < gDbgScroll[3]) gDbgScroll[3] = gDbgCursor[3];
        if (gDbgCursor[3] >= gDbgScroll[3] + vis_rows) gDbgScroll[3] = gDbgCursor[3] - vis_rows + 1;

        for (UINTN r = 0; r < vis_rows && (gDbgScroll[3] + r) < ct_cnt; r++) {
            UINTN idx = gDbgScroll[3] + r;
            const EFI_CONFIGURATION_TABLE *ct = &gST->ConfigurationTable[idx];
            BOOLEAN sel = (idx == gDbgCursor[3]);
            UINT8 a = sel ? gTheme.item_sel_attr : gTheme.item_attr;
            ui_hline(x, 6 + r, w, L' ', sel ? a : gTheme.body_attr);

            CHAR8 gs[40];
            guid_to_str(&ct->VendorGuid, gs, sizeof(gs));
            const CHAR8 *fn = guid_friendly_name(&ct->VendorGuid);

            CHAR8 row_txt[160];
            snprintf_ascii(row_txt, sizeof(row_txt), "%2u  %-15.15s %s 0x%012lX",
                           (UINT32)idx, fn ? fn : "OEM_ConfigTable", gs,
                           (UINT64)(UINTN)ct->VendorTable);
            ui_puts_n(x, 6 + r, row_txt, w, a);
        }
    }
}

BOOLEAN debug_handle_key(const EFI_INPUT_KEY *k) {
    UINTN vis_rows = (gUiRows > 9) ? (gUiRows - 9) : 12;

    /* Sub-tab switchers: Tab or 1..4 */
    if (k->UnicodeChar == L'\t') {
        gDbgSubTab = (gDbgSubTab + 1) % 4;
        return TRUE;
    } else if (k->UnicodeChar >= L'1' && k->UnicodeChar <= L'4') {
        gDbgSubTab = (UINTN)(k->UnicodeChar - L'1');
        return TRUE;
    } else if (k->UnicodeChar == L'r' || k->UnicodeChar == L'R') {
        nvram_enumerate_all();
        rebuild_var_filter();
        refresh_dbg_memmap();
        return TRUE;
    }

    UINTN count = 0;
    if (gDbgSubTab == 0) count = gFilteredVarCount;
    else if (gDbgSubTab == 1) count = gDbgMemCount;
    else if (gDbgSubTab == 2) count = 7;
    else count = gST ? gST->NumberOfTableEntries : 0;

    if (k->ScanCode == SCAN_UP && count > 0) {
        gDbgCursor[gDbgSubTab] = (gDbgCursor[gDbgSubTab] > 0) ? (gDbgCursor[gDbgSubTab] - 1) : (count - 1);
        return TRUE;
    } else if (k->ScanCode == SCAN_DOWN && count > 0) {
        gDbgCursor[gDbgSubTab] = (gDbgCursor[gDbgSubTab] + 1 < count) ? (gDbgCursor[gDbgSubTab] + 1) : 0;
        return TRUE;
    } else if ((k->ScanCode == SCAN_PAGE_UP || k->UnicodeChar == 0x15) && count > 0) {
        gDbgCursor[gDbgSubTab] = (gDbgCursor[gDbgSubTab] > vis_rows) ? (gDbgCursor[gDbgSubTab] - vis_rows) : 0;
        return TRUE;
    } else if ((k->ScanCode == SCAN_PAGE_DOWN || k->UnicodeChar == 0x04) && count > 0) {
        gDbgCursor[gDbgSubTab] = (gDbgCursor[gDbgSubTab] + vis_rows < count) ? (gDbgCursor[gDbgSubTab] + vis_rows) : (count - 1);
        return TRUE;
    } else if (k->ScanCode == SCAN_HOME && count > 0) {
        gDbgCursor[gDbgSubTab] = 0;
        return TRUE;
    } else if (k->ScanCode == SCAN_END && count > 0) {
        gDbgCursor[gDbgSubTab] = count - 1;
        return TRUE;
    }

    if (gDbgSubTab == 0) {
        if (k->UnicodeChar == L'/') {
            CHAR8 flt[40];
            if (ui_input_modal("Filter EFI NVRAM Variables",
                               "Enter name, GUID alias, or value substring (empty = show all):",
                               gDbgVarFilter, flt, sizeof(flt), FALSE)) {
                str_cpy(gDbgVarFilter, flt, sizeof(gDbgVarFilter));
                rebuild_var_filter();
                gDbgCursor[0] = 0;
                gDbgScroll[0] = 0;
            }
            return TRUE;
        } else if (k->UnicodeChar == L'c' || k->UnicodeChar == L'C') {
            gDbgVarFilter[0] = '\0';
            rebuild_var_filter();
            return TRUE;
        } else if (k->UnicodeChar == L'n' || k->UnicodeChar == L'N' || k->ScanCode == SCAN_INSERT) {
            create_new_nvram_var_dialog();
            return TRUE;
        } else if ((k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') && gFilteredVarCount > 0) {
            debug_open_var_editor(gFilteredVarIdx[gDbgCursor[0]]);
            return TRUE;
        }
    } else if (gDbgSubTab == 1) {
        if ((k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') && gDbgMemCount > 0) {
            const DBG_MEM_DESC *d = &gDbgMemMap[gDbgCursor[1]];
            debug_open_hex_editor(d->PhysicalStart, efi_mem_type_full(d->Type));
            return TRUE;
        }
    } else if (gDbgSubTab == 2) {
        if (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') {
            UINTN c = gDbgCursor[2];
            if (c == 0) {
                CHAR8 abuf[32];
                if (ui_input_modal("Open Physical Address", "Enter 64-bit Hex Address (e.g. 0x100000):",
                                   "0x100000", abuf, sizeof(abuf), TRUE)) {
                    UINT64 target = 0;
                    if (parse_hex_u64(abuf, &target)) {
                        debug_open_hex_editor(target, "Custom Physical Address");
                    }
                }
            } else {
                UINT64 addrs[7] = {
                    0, (UINT64)(UINTN)gST, (UINT64)(UINTN)gRT, (UINT64)(UINTN)gBS,
                    gHw.smbios_table_addr, gHw.acpi_rsdp_addr, gHw.gop_fb_base
                };
                if (addrs[c] != 0) {
                    debug_open_hex_editor(addrs[c], "UEFI Landmark");
                } else {
                    ui_message_modal("Not Present", "This firmware table pointer is NULL on this platform.", TRUE);
                }
            }
            return TRUE;
        }
    } else if (gDbgSubTab == 3) {
        UINTN ct_cnt = gST ? gST->NumberOfTableEntries : 0;
        if ((k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') && ct_cnt > 0) {
            const EFI_CONFIGURATION_TABLE *ct = &gST->ConfigurationTable[gDbgCursor[3]];
            const CHAR8 *fn = guid_friendly_name(&ct->VendorGuid);
            debug_open_hex_editor((UINT64)(UINTN)ct->VendorTable, fn ? fn : "EFI Configuration Table");
            return TRUE;
        }
    }

    return FALSE;
}
