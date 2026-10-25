#include "efi.h"
#include "util.h"
#include "ui.h"
#include "hwinfo.h"
#include "nvram.h"
#include "memscan.h"
#include "debug.h"
#include "dump.h"
#include "unlock.h"
#include "spoof.h"

/* Top-Level Tabs */
enum {
    TAB_MAIN     = 0,
    TAB_ADVANCED = 1,
    TAB_MEMSCAN  = 2,
    TAB_SECURITY = 3,
    TAB_BOOT     = 4,
    TAB_DEBUG    = 5,
    TAB_EXIT     = 6,
    TAB_COUNT    = 7
};

/* Submenus inside Advanced Tab */
enum {
    ADV_SUB_NONE     = 0,
    ADV_SUB_UNLOCK   = 1,
    ADV_SUB_CPU      = 2,
    ADV_SUB_GPU_VRAM = 3,
    ADV_SUB_PCIE     = 4,
    ADV_SUB_MEMORY   = 5,
    ADV_SUB_STORAGE  = 6,
    ADV_SUB_ACPI     = 7,
    ADV_SUB_APPLE    = 8,
    ADV_SUB_HII      = 9,
    ADV_SUB_DUMP_ACT = 99
};

static UINTN gActiveTab    = TAB_MAIN;
static UINTN gAdvSub       = ADV_SUB_NONE;

static UINTN gMainCur      = 0; /* 0..4 items on Main */
static UINTN gAdvCur       = 0;
static UINTN gAdvSubCur    = 0;
static UINTN gAdvSubScroll = 0;
static UINTN gSecCur       = 0;
static UINTN gSecScroll    = 0;
static UINTN gBootCur      = 0;
static UINTN gBootScroll   = 0;
static UINTN gExitCur      = 0;

static CHAR8 gHiiFilter[40] = "";
static UINT8 gHiiCatMode    = 0; /* 0=All, 1=Hidden Only, 2=CPU/OC/Lock, 3=GPU/ReBAR/PCIe, 4=Mem/XMP */
static UINTN gHiiFilteredIdx[HW_MAX_HII_QUESTIONS]; /* Static BSS array — avoids 32KB stack frame! */

static BOOLEAN gShouldExitSetup = FALSE;

static BOOLEAN parse_any_u64(const CHAR8 *s, UINT64 *out) {
    if (!s || !out) return FALSE;
    while (*s == ' ' || *s == '\t') s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return parse_hex_u64(s, out);
    }
    return parse_dec_u64(s, out);
}

static VOID build_footer_status(CHAR8 *out, UINTN max_len) {
    UINTN pend = nvram_pending_changes_count();
    const CHAR8 *live_tag = gSpoofActive ? " [SPOOF]" :
                            (gVolatileHwTweakActive ? " [LIVE]" : "");
    CHAR8 prod[18];
    str_cpy(prod, gHw.sys_product, live_tag[0] ? 14U : sizeof(prod));
    snprintf_ascii(out, max_len,
                   "%s | %s | %uC/%uT | Pend:%u%s",
                   gHw.is_apple_mac ? "Mac EFI" : "UEFI",
                   prod,
                   gHw.cpu_cores,
                   gHw.cpu_threads,
                   (UINT32)pend,
                   live_tag);
}

/* Helper to render a static label + value row in left panel */
static VOID draw_kv_row(UINTN lx, UINTN y, UINTN lw, const CHAR8 *label, const CHAR8 *val) {
    if (y >= gUiRows - 2) return;
    ui_puts_n(lx, y, label, 22, gTheme.label_attr);
    if (lw > 23) {
        ui_puts_n(lx + 23, y, val, lw - 23, gTheme.value_attr);
    }
}

/* Helper to render an editable (or greyed-out/locked) option row in left panel */
static VOID draw_opt_row_ex(
    UINTN lx, UINTN y, UINTN lw,
    BOOLEAN selected, BOOLEAN dimmed,
    const CHAR8 *label, const CHAR8 *bracket_val
) {
    if (y >= gUiRows - 2) return;
    UINT8 a;
    if (dimmed) {
        a = selected ? gTheme.dim_sel_attr : gTheme.dim_attr;
    } else {
        a = selected ? gTheme.item_sel_attr : gTheme.item_attr;
    }
    if (selected) {
        ui_hline(lx, y, lw, L' ', a);
    }
    ui_puts_n(lx, y, label, 22, a);
    if (lw > 23) {
        CHAR8 tmp[64];
        snprintf_ascii(tmp, sizeof(tmp), "[%s]", bracket_val);
        ui_puts_n(lx + 23, y, tmp, lw - 23, a);
    }
}

static VOID draw_opt_row(UINTN lx, UINTN y, UINTN lw, BOOLEAN selected, const CHAR8 *label, const CHAR8 *bracket_val) {
    draw_opt_row_ex(lx, y, lw, selected, FALSE, label, bracket_val);
}

static UINTN left_panel_width(VOID) {
    UINTN split_x = (gUiCols * 2) / 3;
    if (split_x < 50 && gUiCols >= 80) split_x = 52;
    if (gUiCols - split_x < 27 && gUiCols >= 80) split_x = gUiCols - 28;
    return split_x - 3;
}

/*
 * Universal Option Picker Helper:
 * Always displays all available options and marks the current value so the user
 * sees every available option and picks what they want to change.
 */
static BOOLEAN pick_u8_option(
    const CHAR8 *setting_name,
    const CHAR8 *const *options,
    UINTN count,
    UINT8 *io_val,
    BOOLEAN plus_hint,
    BOOLEAN minus_hint
) {
    if (!options || count == 0 || !io_val) return FALSE;
    UINTN cur = (*io_val < count) ? (UINTN)(*io_val) : 0;
    UINTN init_sel = cur;
    if (plus_hint) init_sel = (cur + 1) % count;
    else if (minus_hint) init_sel = (cur + count - 1) % count;

    INTN picked = ui_pick_option_modal(setting_name, options, count, cur, init_sel);
    if (picked >= 0 && (UINTN)picked < count && (UINT8)picked != *io_val) {
        *io_val = (UINT8)picked;
        return TRUE;
    }
    return FALSE;
}

static const CHAR8 * const kDisEnOpts[2] = { "Disabled (False)", "Enabled (True)" };
static const CHAR8 * const kOffOnOpts[2] = { "Off (Disabled)",   "On (Enabled)"   };

/* =========================================================================
 * Interactive HII / IFR Question Option Picker & Live NVRAM Writer
 * ========================================================================= */
static VOID format_hii_question_cur_val(UINTN q_idx, CHAR8 *out, UINTN max_len) {
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
    snprintf_ascii(out, max_len, "0x%lX (%lu)", val, val);
}

static VOID edit_hii_question_interactive(UINTN q_idx, BOOLEAN plus_hint, BOOLEAN minus_hint) {
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

    CHAR8 err[128];
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
        UINTN init_s = cur_i;
        if (plus_hint) init_s = (cur_i + 1) % q->opt_count;
        else if (minus_hint) init_s = (cur_i + q->opt_count - 1) % q->opt_count;

        INTN picked = ui_pick_option_modal(q->prompt, optrs, q->opt_count, cur_i, init_s);
        if (picked >= 0 && (UINTN)picked < q->opt_count) {
            if (!hw_hii_write_question_val(q_idx, q->opts[picked].value, err, sizeof(err))) {
                ui_message_modal("HII Write Failed", err, TRUE);
            }
        }
    } else {
        CHAR8 init_s[32], out_s[32], pr[96];
        snprintf_ascii(init_s, sizeof(init_s), "%lu", cur_val);
        snprintf_ascii(pr, sizeof(pr), "VarOffset 0x%04X (%uB) | Range: %lu .. %lu (dec or 0x hex):",
                       (UINT32)q->var_offset, (UINT32)q->width, q->min_val, q->max_val);
        if (ui_input_modal(q->prompt, pr, init_s, out_s, sizeof(out_s), FALSE)) {
            UINT64 nv = 0;
            if (parse_any_u64(out_s, &nv)) {
                if (!hw_hii_write_question_val(q_idx, nv, err, sizeof(err))) {
                    ui_message_modal("HII Write Failed", err, TRUE);
                }
            }
        }
    }
}

static INTN find_motherboard_hii_q(const CHAR8 *kw1, const CHAR8 *kw2) {
    INTN q = hw_hii_find_question_icase(kw1, NULL);
    if (q < 0 && kw2) q = hw_hii_find_question_icase(kw2, NULL);
    if (q >= 0) {
        UINT64 v = 0;
        BOOLEAN in_nv = FALSE;
        hw_hii_read_question_val((UINTN)q, &v, &in_nv);
        if (!in_nv) return -1;
    }
    return q;
}

static VOID sync_motherboard_hii_bool(const CHAR8 *kw1, const CHAR8 *kw2, BOOLEAN enable) {
    INTN q_idx = find_motherboard_hii_q(kw1, kw2);
    if (q_idx < 0 || !gHw.hii_questions) return;
    const HW_HII_QUESTION *q = &gHw.hii_questions[q_idx];
    UINT64 target_v = enable ? 1ULL : 0ULL;
    for (UINT8 oi = 0; oi < q->opt_count; oi++) {
        if (enable && (str_contains_icase(q->opts[oi].label, "Enable") ||
                       str_icmp(q->opts[oi].label, "On") == 0)) {
            target_v = q->opts[oi].value;
            break;
        }
        if (!enable && (str_contains_icase(q->opts[oi].label, "Disable") ||
                        str_icmp(q->opts[oi].label, "Off") == 0)) {
            target_v = q->opts[oi].value;
            break;
        }
    }
    CHAR8 err[64];
    hw_hii_write_question_val((UINTN)q_idx, target_v, err, sizeof(err));
}

/* =========================================================================
 * TAB 0: MAIN (Hardware Specs, Accurate CPU Cores, RTC, Dump)
 * ========================================================================= */
static VOID draw_main_tab(VOID) {
    const CHAR8 *help_titles[5] = {
        "System Date (RTC)",
        "System Time (RTC)",
        "Console Resolution",
        "Setup Color Theme",
        "EFI Dump (F12)"
    };
    const CHAR8 *help_bodies[5] = {
        "Set the hardware Real-Time Clock (CMOS/RTC) calendar date [MM/DD/YYYY].\nSaved via RT->SetTime() on F10 Save.",
        "Set the hardware Real-Time Clock time [HH:MM:SS].\nLive clock ticks automatically.",
        "Show all available UEFI SimpleTextOut resolutions (80x25, 100x31, high-DPI) and switch live.",
        "Show available color themes (Classic Aptio Blue/Gray, Classic Phoenix Blue, High-Contrast Dark).",
        "Export full hardware specs, raw HII/IFR packages, decoded VarOffsets, ACPI .aml, SMBIOS & NVRAM to boot folder!"
    };
    CHAR8 status[80];
    build_footer_status(status, sizeof(status));

    ui_draw_setup_frame(TAB_MAIN, NULL, TRUE,
                        help_titles[gMainCur % 5], help_bodies[gMainCur % 5], status);

    UINTN lx = 2;
    UINTN lw = left_panel_width();
    UINTN y = 3;

    CHAR8 buf[80];
    snprintf_ascii(buf, sizeof(buf), "%s (UEFI %u.%02u)", gHw.fw_vendor, gHw.uefi_major, gHw.uefi_minor);
    draw_kv_row(lx, y++, lw, "EFI Firmware Vendor", buf);

    snprintf_ascii(buf, sizeof(buf), "%s (%s)", gHw.bios_version, gHw.bios_date);
    draw_kv_row(lx, y++, lw, "BIOS / ROM Version", buf);

    draw_kv_row(lx, y++, lw, "Manufacturer", gHw.sys_manufacturer);
    draw_kv_row(lx, y++, lw, "Product / Model", gHw.sys_product);
    draw_kv_row(lx, y++, lw, "System Serial No.", gHw.sys_serial);

    snprintf_ascii(buf, sizeof(buf), "%s / %s", gHw.board_product, gHw.board_serial);
    draw_kv_row(lx, y++, lw, gHw.is_apple_mac ? "Board ID / MLB" : "Baseboard / Serial", buf);

    draw_kv_row(lx, y++, lw, "Hardware UUID", gHw.sys_uuid);
    draw_kv_row(lx, y++, lw, "Platform / Hyperv.", gHw.hypervisor_name);

    y++;
    draw_kv_row(lx, y++, lw, "Processor", gHw.cpu_brand);

    if (gHw.cpu_max_mhz > 0) {
        snprintf_ascii(buf, sizeof(buf), "%uC / %uT @ %u MHz (Sig %06X)",
                       gHw.cpu_cores, gHw.cpu_threads, gHw.cpu_max_mhz, gHw.cpu_signature);
    } else {
        snprintf_ascii(buf, sizeof(buf), "%uC / %uT (Sig %06X)",
                       gHw.cpu_cores, gHw.cpu_threads, gHw.cpu_signature);
    }
    draw_kv_row(lx, y++, lw, "CPU Cores / Threads", buf);

    snprintf_ascii(buf, sizeof(buf), "%lu MB Total (%lu MB Usable)",
                   gHw.total_ram_bytes >> 20, gHw.usable_ram_bytes >> 20);
    draw_kv_row(lx, y++, lw, "Installed Memory", buf);

    if (gHw.gpu_count > 0) {
        const HW_PCI_DEV_INFO *g0 = &gHw.pci_devs[gHw.gpu_pci_indices[0]];
        if (gHw.igd_ggc_present) {
            snprintf_ascii(buf, sizeof(buf), "%s [%04X:%04X] (%u GPU, Stolen:%uMB)",
                           g0->vendor_name, g0->vendor_id, g0->device_id,
                           (UINT32)gHw.gpu_count, gHw.igd_stolen_mb);
        } else if (g0->vram_bar_size > 0) {
            snprintf_ascii(buf, sizeof(buf), "%s [%04X:%04X] (%lu MB BAR%s)",
                           g0->vendor_name, g0->vendor_id, g0->device_id,
                           g0->vram_bar_size >> 20, g0->rebar_supported ? ", ReBAR" : "");
        } else {
            snprintf_ascii(buf, sizeof(buf), "%s [%04X:%04X] (%u GPU)",
                           g0->vendor_name, g0->vendor_id, g0->device_id, (UINT32)gHw.gpu_count);
        }
    } else if (gHw.gop_present) {
        snprintf_ascii(buf, sizeof(buf), "UEFI GOP %ux%u", gHw.gop_width, gHw.gop_height);
    } else {
        str_cpy(buf, "Standard Text Console", sizeof(buf));
    }
    draw_kv_row(lx, y++, lw, "Graphics / VRAM", buf);

    y++;
    EFI_TIME tm = gSetup.staged_rtc;
    if (!gSetup.rtc_dirty && gRT && gRT->GetTime) {
        gRT->GetTime(&tm, NULL);
        gSetup.staged_rtc = tm;
    }

    snprintf_ascii(buf, sizeof(buf), "%02u/%02u/%04u%s",
                   tm.Month, tm.Day, tm.Year, gSetup.rtc_dirty ? " *" : "");
    draw_opt_row(lx, y++, lw, gMainCur == 0, "System Date", buf);

    snprintf_ascii(buf, sizeof(buf), "%02u:%02u:%02u%s",
                   tm.Hour, tm.Minute, tm.Second, gSetup.rtc_dirty ? " *" : "");
    draw_opt_row(lx, y++, lw, gMainCur == 1, "System Time", buf);

    snprintf_ascii(buf, sizeof(buf), "%ux%u (Mode %d)",
                   (UINT32)gUiCols, (UINT32)gUiRows, gCurrentConsoleMode);
    draw_opt_row(lx, y++, lw, gMainCur == 2, "Console Text Mode", buf);

    const CHAR8 *tnames[UI_THEME_COUNT] = {
        "Classic Aptio Blue/Gray",
        "Classic Phoenix Blue",
        "High-Contrast Dark"
    };
    draw_opt_row(lx, y++, lw, gMainCur == 3, "Setup Color Theme", tnames[gCurrentThemeIdx % UI_THEME_COUNT]);

    if (y < gUiRows - 2) {
        UINT8 da = (gMainCur == 4) ? gTheme.item_sel_attr : gTheme.item_attr;
        if (gMainCur == 4) ui_hline(lx, y, lw, L' ', da);
        ui_putc(lx, y, gBox.arrow_r, da);
        ui_puts_n(lx + 2, y, "EFI Dump (F12)", lw - 2, da);
    }
}

static BOOLEAN handle_main_key(const EFI_INPUT_KEY *k) {
    if (k->ScanCode == SCAN_UP) {
        gMainCur = (gMainCur > 0) ? (gMainCur - 1) : 4;
        return TRUE;
    } else if (k->ScanCode == SCAN_DOWN) {
        gMainCur = (gMainCur + 1) % 5;
        return TRUE;
    }

    BOOLEAN plus  = (k->UnicodeChar == L'+' || k->UnicodeChar == L'=' || k->ScanCode == SCAN_F6);
    BOOLEAN minus = (k->UnicodeChar == L'-' || k->ScanCode == SCAN_F5);
    BOOLEAN enter = (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n' || k->UnicodeChar == L' ');

    if (gMainCur == 0 && (enter || plus || minus)) {
        if (plus || minus) {
            INT32 d = (INT32)gSetup.staged_rtc.Day + (plus ? 1 : -1);
            if (d < 1) d = 28;
            if (d > 31) d = 1;
            gSetup.staged_rtc.Day = (UINT8)d;
            gSetup.rtc_dirty = TRUE;
        } else {
            CHAR8 init_s[20], out_s[20];
            snprintf_ascii(init_s, sizeof(init_s), "%02u/%02u/%04u",
                           gSetup.staged_rtc.Month, gSetup.staged_rtc.Day, gSetup.staged_rtc.Year);
            if (ui_input_modal("Set Hardware System Date", "Format: MM/DD/YYYY (e.g. 10/25/2026)",
                               init_s, out_s, sizeof(out_s), FALSE)) {
                UINT64 mm = 0, dd = 0, yy = 0;
                if (out_s[2] == '/' && out_s[5] == '/') {
                    out_s[2] = '\0'; out_s[5] = '\0';
                    if (parse_dec_u64(out_s, &mm) && parse_dec_u64(out_s + 3, &dd) && parse_dec_u64(out_s + 6, &yy)) {
                        if (mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31 && yy >= 1998 && yy <= 2099) {
                            gSetup.staged_rtc.Month = (UINT8)mm;
                            gSetup.staged_rtc.Day   = (UINT8)dd;
                            gSetup.staged_rtc.Year  = (UINT16)yy;
                            gSetup.rtc_dirty = TRUE;
                        }
                    }
                }
            }
        }
        return TRUE;
    } else if (gMainCur == 1 && (enter || plus || minus)) {
        if (plus || minus) {
            INT32 m = (INT32)gSetup.staged_rtc.Minute + (plus ? 1 : -1);
            if (m < 0) m = 59;
            if (m > 59) m = 0;
            gSetup.staged_rtc.Minute = (UINT8)m;
            gSetup.rtc_dirty = TRUE;
        } else {
            CHAR8 init_s[20], out_s[20];
            snprintf_ascii(init_s, sizeof(init_s), "%02u:%02u:%02u",
                           gSetup.staged_rtc.Hour, gSetup.staged_rtc.Minute, gSetup.staged_rtc.Second);
            if (ui_input_modal("Set Hardware System Time", "Format: HH:MM:SS (24-hour)",
                               init_s, out_s, sizeof(out_s), FALSE)) {
                UINT64 hh = 0, mm = 0, ss = 0;
                if (out_s[2] == ':' && out_s[5] == ':') {
                    out_s[2] = '\0'; out_s[5] = '\0';
                    if (parse_dec_u64(out_s, &hh) && parse_dec_u64(out_s + 3, &mm) && parse_dec_u64(out_s + 6, &ss)) {
                        if (hh <= 23 && mm <= 59 && ss <= 59) {
                            gSetup.staged_rtc.Hour   = (UINT8)hh;
                            gSetup.staged_rtc.Minute = (UINT8)mm;
                            gSetup.staged_rtc.Second = (UINT8)ss;
                            gSetup.rtc_dirty = TRUE;
                        }
                    }
                }
            }
        }
        return TRUE;
    } else if (gMainCur == 2 && (enter || plus || minus) && gConsoleModeCount > 0) {
        CHAR8 mbufs[UI_MAX_CONSOLE_MODES][36];
        const CHAR8 *mptrs[UI_MAX_CONSOLE_MODES];
        UINTN cur_i = 0;
        for (UINTN i = 0; i < gConsoleModeCount; i++) {
            snprintf_ascii(mbufs[i], sizeof(mbufs[i]), "Mode %d: %ux%u Columns/Rows",
                           gConsoleModes[i].mode_num, (UINT32)gConsoleModes[i].cols, (UINT32)gConsoleModes[i].rows);
            mptrs[i] = mbufs[i];
            if (gConsoleModes[i].mode_num == gCurrentConsoleMode) cur_i = i;
        }
        UINTN init_s = plus ? ((cur_i + 1) % gConsoleModeCount) :
                       (minus ? ((cur_i + gConsoleModeCount - 1) % gConsoleModeCount) : cur_i);
        INTN picked = ui_pick_option_modal("Console Text Resolution", mptrs, gConsoleModeCount, cur_i, init_s);
        if (picked >= 0 && (UINTN)picked < gConsoleModeCount) {
            if (ui_set_console_mode(gConsoleModes[picked].mode_num)) {
                gSetup.cfg.preferred_con_mode = (INT16)gCurrentConsoleMode;
                gSetup.cfg_dirty = TRUE;
            }
        }
        return TRUE;
    } else if (gMainCur == 3 && (enter || plus || minus)) {
        const CHAR8 *opts[UI_THEME_COUNT] = {
            "Classic AMI Aptio (Blue / Gray)",
            "Classic Award / Phoenix BIOS (Deep Blue)",
            "High-Contrast Dark Terminal (Black / Cyan)"
        };
        UINT8 tidx = gCurrentThemeIdx;
        if (pick_u8_option("Setup Color Theme", opts, UI_THEME_COUNT, &tidx, plus, minus)) {
            ui_set_theme(tidx);
            gSetup.cfg.theme_idx = tidx;
            gSetup.cfg_dirty = TRUE;
        }
        return TRUE;
    } else if (gMainCur == 4 && (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n')) {
        dump_run_interactive_modal();
        return TRUE;
    }
    return FALSE;
}

/* =========================================================================
 * Helpers: Auto-Match Motherboard HII Questions (CPU/OC/Lock, GPU/ReBAR, Mem)
 * ========================================================================= */
static BOOLEAN is_cpu_oc_hii_q(const HW_HII_QUESTION *q) {
    const CHAR8 *p = q->prompt;
    return str_contains_icase(p, "CFG Lock") ||
           str_contains_icase(p, "Overclock") ||
           str_contains_icase(p, "OC Lock") ||
           str_contains_icase(p, "Ratio") ||
           str_contains_icase(p, "Turbo") ||
           str_contains_icase(p, "Precision Boost") ||
           str_contains_icase(p, "PBO") ||
           str_contains_icase(p, "Core Performance") ||
           str_contains_icase(p, "Curve Optimizer") ||
           str_contains_icase(p, "Undervolt") ||
           str_contains_icase(p, "Power Limit") ||
           str_contains_icase(p, "cTDP") ||
           str_contains_icase(p, "BCLK") ||
           str_contains_icase(p, "CPU Clock") ||
           str_contains_icase(p, "Vcore") ||
           str_contains_icase(p, "Core Voltage") ||
           str_contains_icase(p, "C-State") ||
           str_contains_icase(p, "Global C") ||
           str_contains_icase(p, "SVM") ||
           str_contains_icase(p, "VMX") ||
           str_contains_icase(p, "Virtualization") ||
           str_contains_icase(p, "Hyper-Threading") ||
           str_contains_icase(p, "SMT Mode") ||
           str_contains_icase(p, "Downcore");
}

static BOOLEAN is_gpu_vram_hii_q(const HW_HII_QUESTION *q) {
    const CHAR8 *p = q->prompt;
    return str_contains_icase(p, "DVMT") ||
           str_contains_icase(p, "VRAM") ||
           str_contains_icase(p, "UMA") ||
           str_contains_icase(p, "Aperture") ||
           str_contains_icase(p, "Resizable BAR") ||
           str_contains_icase(p, "Re-Size BAR") ||
           str_contains_icase(p, "ReBAR") ||
           str_contains_icase(p, "Above 4G") ||
           str_contains_icase(p, "Primary Display") ||
           str_contains_icase(p, "Primary Video") ||
           str_contains_icase(p, "Integrated Graphics") ||
           str_contains_icase(p, "Hybrid Graphics") ||
           str_contains_icase(p, "IGD");
}

static BOOLEAN is_mem_oc_hii_q(const HW_HII_QUESTION *q) {
    const CHAR8 *p = q->prompt;
    return str_contains_icase(p, "XMP") ||
           str_contains_icase(p, "EXPO") ||
           str_contains_icase(p, "DOCP") ||
           str_contains_icase(p, "Memory Frequency") ||
           str_contains_icase(p, "DRAM Frequency") ||
           str_contains_icase(p, "Memory Clock") ||
           str_contains_icase(p, "FCLK") ||
           str_contains_icase(p, "UCLK") ||
           str_contains_icase(p, "Memory Profile");
}

static UINTN get_cpu_hii_questions(UINTN *out_indices, UINTN max_out) {
    UINTN cnt = 0;
    if (!gHw.hii_questions) return 0;
    for (UINTN i = 0; i < gHw.hii_question_count && cnt < max_out; i++) {
        if (is_cpu_oc_hii_q(&gHw.hii_questions[i])) out_indices[cnt++] = i;
    }
    return cnt;
}

static UINTN get_gpu_hii_questions(UINTN *out_indices, UINTN max_out) {
    UINTN cnt = 0;
    if (!gHw.hii_questions) return 0;
    for (UINTN i = 0; i < gHw.hii_question_count && cnt < max_out; i++) {
        if (is_gpu_vram_hii_q(&gHw.hii_questions[i])) out_indices[cnt++] = i;
    }
    return cnt;
}

static UINTN get_mem_hii_questions(UINTN *out_indices, UINTN max_out) {
    UINTN cnt = 0;
    if (!gHw.hii_questions) return 0;
    for (UINTN i = 0; i < gHw.hii_question_count && cnt < max_out; i++) {
        if (is_mem_oc_hii_q(&gHw.hii_questions[i])) out_indices[cnt++] = i;
    }
    return cnt;
}

static BOOLEAN is_sec_me_spi_hii_q(const HW_HII_QUESTION *q) {
    const CHAR8 *p = q->prompt;
    return str_contains_icase(p, "ME ") ||
           str_contains_icase(p, "ME State") ||
           str_contains_icase(p, "MeFw") ||
           str_contains_icase(p, "CSME") ||
           str_contains_icase(p, "HAP") ||
           str_contains_icase(p, "High Assurance") ||
           str_contains_icase(p, "AltMeDisable") ||
           str_contains_icase(p, "End of Post") ||
           str_contains_icase(p, "AMT") ||
           str_contains_icase(p, "PSP") ||
           str_contains_icase(p, "fTPM") ||
           str_contains_icase(p, "TSME") ||
           str_contains_icase(p, "IOMMU") ||
           str_contains_icase(p, "BIOS Lock") ||
           str_contains_icase(p, "BIOS Guard") ||
           str_contains_icase(p, "Flash") ||
           str_contains_icase(p, "FPRR") ||
           str_contains_icase(p, "SPI") ||
           str_contains_icase(p, "SGX") ||
           str_contains_icase(p, "Undervolt") ||
           str_contains_icase(p, "Lock");
}

static UINTN get_filtered_hii_questions(UINTN *out_indices, UINTN max_out) {
    UINTN cnt = 0;
    if (!gHw.hii_questions) return 0;
    for (UINTN i = 0; i < gHw.hii_question_count && cnt < max_out; i++) {
        const HW_HII_QUESTION *q = &gHw.hii_questions[i];
        if (gHiiCatMode == 1 && !q->is_suppressed && !q->is_grayout) continue;
        if (gHiiCatMode == 2 && !is_cpu_oc_hii_q(q)) continue;
        if (gHiiCatMode == 3 && !is_gpu_vram_hii_q(q) && !str_contains_icase(q->prompt, "PCIe") && !str_contains_icase(q->prompt, "ASPM")) continue;
        if (gHiiCatMode == 4 && !is_mem_oc_hii_q(q)) continue;
        if (gHiiCatMode == 5 && !is_sec_me_spi_hii_q(q)) continue;

        if (!gHiiFilter[0] ||
            str_contains_icase(q->prompt, gHiiFilter) ||
            str_contains_icase(q->formset_title, gHiiFilter) ||
            str_contains_icase(q->help, gHiiFilter)) {
            out_indices[cnt++] = i;
        }
    }
    return cnt;
}

static INTN find_first_rebar_gpu_pci_idx(VOID) {
    for (UINTN g = 0; g < gHw.gpu_count; g++) {
        UINTN pidx = gHw.gpu_pci_indices[g];
        if (gHw.pci_devs[pidx].rebar_supported && gHw.pci_devs[pidx].rebar_ext_off != 0) {
            return (INTN)pidx;
        }
    }
    return -1;
}

static VOID edit_rebar_size_interactive(UINTN pci_idx) {
    hw_refresh_pci_dev(pci_idx);
    const HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];
    if (!pd->rebar_supported || pd->rebar_ext_off == 0) {
        INTN hq = hw_hii_find_question_icase("Resizable BAR", NULL);
        if (hq < 0) hq = hw_hii_find_question_icase("Re-Size BAR", NULL);
        if (hq >= 0) {
            edit_hii_question_interactive((UINTN)hq, FALSE, FALSE);
        } else {
            ui_message_modal("Resizable BAR Unavailable",
                             "No PCIe Extended Capability 0x0015 (ReBAR) or ECAM aperture detected on this GPU.",
                             TRUE);
        }
        return;
    }

    UINT8 exps[20];
    CHAR8 obufs[20][44];
    const CHAR8 *optrs[20];
    UINTN cnt = 0;
    UINTN cur_i = 0;

    for (UINT8 exp = 0; exp <= 20 && cnt < 20; exp++) {
        BOOLEAN sup = (exp == pd->rebar_cur_size_exp);
        if ((UINT32)(exp + 4) < 32 && (pd->rebar_cap_mask & (1U << (exp + 4))) != 0) {
            sup = TRUE;
        }
        if (!sup) continue;

        exps[cnt] = exp;
        UINT64 mb = 1ULL << exp;
        if (mb >= 1024ULL) {
            snprintf_ascii(obufs[cnt], sizeof(obufs[cnt]), "%lu GB Aperture (2^%u MB)%s",
                           mb >> 10, exp, (exp == pd->rebar_max_size_exp) ? " [Full VRAM]" : "");
        } else {
            snprintf_ascii(obufs[cnt], sizeof(obufs[cnt]), "%lu MB Aperture (2^%u MB)", mb, exp);
        }
        optrs[cnt] = obufs[cnt];
        if (exp == pd->rebar_cur_size_exp) cur_i = cnt;
        cnt++;
    }

    if (cnt == 0) return;
    INTN p = ui_pick_option_modal("PCIe Resizable BAR (ReBAR / SAM) Size", optrs, cnt, cur_i, cur_i);
    if (p >= 0 && (UINTN)p < cnt) {
        if (!hw_pci_set_rebar_size_exp(pci_idx, exps[p])) {
            ui_message_modal("ReBAR Register Locked",
                             "GPU rejected Resizable BAR Control update (ensure Above 4G Decoding is enabled).",
                             TRUE);
        }
    }
}

static VOID edit_active_threads_interactive(VOID) {
    if (gHw.cpu_mp_total_threads <= 1) {
        ui_message_modal("Single-Thread / No MP Protocol",
                         "Firmware exposes only 1 logical processor or does not publish EFI_MP_SERVICES_PROTOCOL.",
                         TRUE);
        return;
    }

    UINT32 tot = gHw.cpu_mp_total_threads;
    UINT32 presets[7];
    CHAR8 obufs[8][48];
    const CHAR8 *optrs[8];
    UINTN cnt = 0;
    UINTN cur_i = 0;

    UINT32 cands[6] = { tot, (tot >= 4) ? (tot / 2) : 0, 16, 8, 4, 2 };
    for (UINTN i = 0; i < 6; i++) {
        UINT32 c = cands[i];
        if (c < 1 || c > tot) continue;
        BOOLEAN dup = FALSE;
        for (UINTN j = 0; j < cnt; j++) if (presets[j] == c) dup = TRUE;
        if (dup) continue;
        presets[cnt] = c;
        snprintf_ascii(obufs[cnt], sizeof(obufs[cnt]), "%u Active Logical Threads%s",
                       c, (c == tot) ? " (All Enabled)" : "");
        optrs[cnt] = obufs[cnt];
        if (c == gHw.cpu_mp_threads) cur_i = cnt;
        cnt++;
    }
    presets[cnt] = 1;
    str_cpy(obufs[cnt], "1 Thread Only (BSP Single-Core Mode)", sizeof(obufs[cnt]));
    optrs[cnt] = obufs[cnt];
    if (gHw.cpu_mp_threads == 1) cur_i = cnt;
    cnt++;

    str_cpy(obufs[cnt], "Enter Custom Active Thread Count...", sizeof(obufs[cnt]));
    optrs[cnt] = obufs[cnt];
    UINTN custom_idx = cnt++;

    INTN p = ui_pick_option_modal("Active CPU Logical Threads (MP Services)", optrs, cnt, cur_i, cur_i);
    if (p < 0) return;

    UINTN target = 0;
    if ((UINTN)p == custom_idx) {
        CHAR8 init_s[16], out_s[16], pr[64];
        snprintf_ascii(init_s, sizeof(init_s), "%u", gHw.cpu_mp_threads);
        snprintf_ascii(pr, sizeof(pr), "Enter active logical CPUs (1 .. %u):", tot);
        if (!ui_input_modal("Custom Active Threads", pr, init_s, out_s, sizeof(out_s), FALSE)) return;
        UINT64 v = 0;
        if (!parse_dec_u64(out_s, &v) || v < 1 || v > tot) return;
        target = (UINTN)v;
    } else {
        target = presets[p];
    }

    CHAR8 err[128];
    if (!hw_mp_set_enabled_threads(target, err, sizeof(err))) {
        ui_message_modal("MP Thread Control Error", err, TRUE);
    }
}

/* =========================================================================
 * PCIe Per-Device Hardware Controller Dialog (ASPM, Gen1-Gen5, ReBAR, DMA)
 * ========================================================================= */
static VOID open_pcie_device_controller(UINTN pci_idx) {
    if (pci_idx >= gHw.pci_count) return;

    for (;;) {
        hw_refresh_pci_dev(pci_idx);
        const HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];

        CHAR8 title[64];
        snprintf_ascii(title, sizeof(title), "PCI %02X:%02X.%X [%04X:%04X] %s",
                       pd->bus, pd->dev, pd->func, pd->vendor_id, pd->device_id, pd->vendor_name);

        if (pd->pcie_cap_off != 0) {
            const CHAR8 *aspm_names[4] = { "Disabled", "L0s Only", "L1 Only", "L0s + L1" };
            const CHAR8 *mr_names[6]   = { "128B", "256B", "512B", "1024B", "2048B", "4096B" };
            CHAR8 o0[64], o1[64], o2[64], o3[64], o4[64], o5[64];
            snprintf_ascii(o0, sizeof(o0), "PCIe ASPM Power Control    [%s]",
                           aspm_names[pd->pcie_aspm_cur & 3U]);
            snprintf_ascii(o1, sizeof(o1), "Target Link Speed          [Cur:Gen%u x%u / Tgt:Gen%u / Max:Gen%u]",
                           pd->pcie_cur_speed, pd->pcie_cur_width,
                           pd->pcie_target_speed ? pd->pcie_target_speed : pd->pcie_cur_speed,
                           pd->pcie_max_speed);
            snprintf_ascii(o2, sizeof(o2), "PCIe Relaxed Ordering      [%s]",
                           pd->pcie_relaxed_ord ? "Enabled" : "Disabled");
            snprintf_ascii(o3, sizeof(o3), "Max Read Request Size      [%s]",
                           mr_names[(pd->pcie_max_read_req <= 5) ? pd->pcie_max_read_req : 2]);
            snprintf_ascii(o4, sizeof(o4), "PCI Bus Master DMA         [%s]",
                           (pd->command & 0x0004U) ? "Enabled" : "Disabled");

            const CHAR8 *menu[7];
            UINTN mcnt = 0;
            menu[mcnt++] = o0;
            menu[mcnt++] = o1;
            menu[mcnt++] = o2;
            menu[mcnt++] = o3;
            menu[mcnt++] = o4;
            INTN rebar_act = -1;
            if (pd->rebar_supported && pd->rebar_ext_off != 0) {
                snprintf_ascii(o5, sizeof(o5), "Resizable BAR (ReBAR)      [Active:%luMB / Max:%luMB]",
                               1ULL << pd->rebar_cur_size_exp, 1ULL << pd->rebar_max_size_exp);
                rebar_act = (INTN)mcnt;
                menu[mcnt++] = o5;
            }
            INTN hex_act = (INTN)mcnt;
            menu[mcnt++] = "Open 256-Byte Raw PCI Config Space Hex Editor...";

            INTN act = ui_select_modal(title, menu, mcnt, 0);
            if (act < 0) break;

            if (act == 0) {
                INTN p = ui_pick_option_modal("PCIe ASPM Control", aspm_names, 4,
                                              pd->pcie_aspm_cur & 3U, pd->pcie_aspm_cur & 3U);
                if (p >= 0) {
                    if (!hw_pci_set_aspm(pci_idx, (UINT8)p)) {
                        ui_message_modal("ASPM Locked", "Device rejected ASPM register modification.", TRUE);
                    }
                }
            } else if (act == 1) {
                const CHAR8 *gens[5] = {
                    "Gen 1 (2.5 GT/s)",
                    "Gen 2 (5.0 GT/s)",
                    "Gen 3 (8.0 GT/s)",
                    "Gen 4 (16.0 GT/s)",
                    "Gen 5 (32.0 GT/s)"
                };
                UINTN max_g = (pd->pcie_max_speed >= 1 && pd->pcie_max_speed <= 5) ? pd->pcie_max_speed : 5;
                UINTN cur_g = (pd->pcie_target_speed >= 1 && pd->pcie_target_speed <= max_g)
                              ? (pd->pcie_target_speed - 1) : 0;
                INTN p = ui_pick_option_modal("PCIe Target Link Speed", gens, max_g, cur_g, cur_g);
                if (p >= 0) {
                    if (!hw_pci_set_target_speed(pci_idx, (UINT8)(p + 1))) {
                        ui_message_modal("Link Control 2",
                                         "PCIe Cap v2 Link Control 2 not writable on this device.", TRUE);
                    }
                }
            } else if (act == 2) {
                UINT8 v = pd->pcie_relaxed_ord ? 1 : 0;
                if (pick_u8_option("PCIe Relaxed Ordering", kDisEnOpts, 2, &v, FALSE, FALSE)) {
                    hw_pci_set_relaxed_ordering(pci_idx, v != 0);
                }
            } else if (act == 3) {
                const CHAR8 *mropts[6] = {
                    "128 Bytes", "256 Bytes", "512 Bytes", "1024 Bytes", "2048 Bytes", "4096 Bytes"
                };
                UINTN cur_m = (pd->pcie_max_read_req <= 5) ? pd->pcie_max_read_req : 2;
                INTN p = ui_pick_option_modal("PCIe Max Read Request Size", mropts, 6, cur_m, cur_m);
                if (p >= 0) hw_pci_set_max_read_req(pci_idx, (UINT8)p);
            } else if (act == 4) {
                UINT8 bm = (pd->command & 0x0004U) ? 1 : 0;
                if (pick_u8_option("PCI Bus Master DMA", kDisEnOpts, 2, &bm, FALSE, FALSE)) {
                    hw_pci_set_command_bit(pci_idx, 0x0004U, bm != 0);
                }
            } else if (act == rebar_act) {
                edit_rebar_size_interactive(pci_idx);
            } else if (act == hex_act) {
                debug_open_pci_config_editor(pci_idx);
            }
        } else {
            CHAR8 o0[64], o1[64];
            snprintf_ascii(o0, sizeof(o0), "PCI Bus Master DMA         [%s]",
                           (pd->command & 0x0004U) ? "Enabled" : "Disabled");
            snprintf_ascii(o1, sizeof(o1), "PCI Memory Space Decode    [%s]",
                           (pd->command & 0x0002U) ? "Enabled" : "Disabled");
            const CHAR8 *menu[3] = {
                o0, o1,
                "Open 256-Byte Raw PCI Config Space Hex Editor..."
            };
            INTN act = ui_select_modal(title, menu, 3, 0);
            if (act < 0) break;
            if (act == 0) {
                UINT8 bm = (pd->command & 0x0004U) ? 1 : 0;
                if (pick_u8_option("PCI Bus Master DMA", kDisEnOpts, 2, &bm, FALSE, FALSE)) {
                    hw_pci_set_command_bit(pci_idx, 0x0004U, bm != 0);
                }
            } else if (act == 1) {
                UINT8 ms = (pd->command & 0x0002U) ? 1 : 0;
                if (pick_u8_option("PCI Memory Space Decode", kDisEnOpts, 2, &ms, FALSE, FALSE)) {
                    hw_pci_set_command_bit(pci_idx, 0x0002U, ms != 0);
                }
            } else if (act == 2) {
                debug_open_pci_config_editor(pci_idx);
            }
        }
    }
}

/* =========================================================================
 * TAB 1: ADVANCED (Unlock Hub, CPU OC/Locks, GPU/VRAM/ReBAR, PCIe, Memory, HII)
 * ========================================================================= */
static UINTN get_adv_menu_items(UINTN *out_ids, const CHAR8 **out_names, const CHAR8 **out_help) {
    UINTN n = 0;

    out_ids[n]   = ADV_SUB_UNLOCK;
    out_names[n] = gHw.cpu_msr.is_amd
        ? "Unlock Hub: PSP, SVI2, SPI & setup_var"
        : "Unlock Hub: Undervolt, ME, SPI & setup_var";
    out_help[n]  = gHw.cpu_msr.is_amd
        ? "Universal Unlock Hub: Built-in setup_var_3 direct hex offset patcher (with live IFR cross-check), AMD PSP/fTPM/TSME/IOMMU controls, SVI2 undervolting, and SPI Flash write-protection inspector."
        : "Universal Unlock Hub: One-click Undervolt & CFG Lock unlocker, live Intel FIVR Voltage Offsets (MSR 0x150 Core/Cache/iGPU/SA), Intel ME / CSME (HAP, HMRFPO, Re-Flash), PCH SPI Flash locks & built-in setup_var_3!";
    n++;

    out_ids[n]   = ADV_SUB_CPU;
    out_names[n] = "CPU Frequency, Overclock & Lock Control";
    out_help[n]  = gHw.cpu_msr.is_amd
        ? "Live AMD Ryzen/Zen Hardware P-State P0 Frequency (MHz) & Core Voltage (VID) overclock/undervolt, Core Performance Boost (CPB), SVM, Active Threads, and motherboard HII PBO/CBS settings."
        : "Live Intel CPU Target Multiplier, All-Core Turbo Ratio, CFG Lock (0xE2) & Overclocking Lock (0x194) unlockers, RAPL PL1/PL2 Power Limits, BD PROCHOT, Active Threads, and HII OC settings.";
    n++;

    out_ids[n]   = ADV_SUB_GPU_VRAM;
    out_names[n] = gHw.is_apple_mac
        ? "GPU, VRAM, ReBAR & Mac GPU Mux"
        : "GPU, VRAM, ReBAR & Display Control";
    out_help[n]  = gHw.is_apple_mac
        ? "Configure Dual-GPU Mux (gpu-power-prefs), Primary Display, PCIe Resizable BAR, Intel GMCH Stolen VRAM (GGC), GOP resolution & HII GPU options."
        : "Configure Primary Display Adapter, live PCIe Resizable BAR (ReBAR / SAM) aperture size, Above 4G MMIO Decoding, iGPU UMA/DVMT VRAM size, GOP mode & HII GPU options.";
    n++;

    out_ids[n]   = ADV_SUB_PCIE;
    out_names[n] = "PCIe Gen1-Gen5 Speed, ASPM & ReBAR";
    out_help[n]  = "Inspect negotiated PCIe Gen1-Gen5 link width/speed and live-edit ASPM (L0s/L1), Target Link Speed (2.5-32 GT/s), Resizable BAR, Relaxed Ordering, Max Read Req & 256B Config.";
    n++;

    out_ids[n]   = ADV_SUB_MEMORY;
    out_names[n] = "Memory Profiles (XMP/EXPO) & DIMM Slots";
    out_help[n]  = "Configure ACPI S3 Sleep, edit discovered motherboard HII Memory Overclock / XMP / EXPO / DOCP / FCLK settings, and inspect SMBIOS Type 17 DIMM slots.";
    n++;

    out_ids[n]   = ADV_SUB_STORAGE;
    out_names[n] = "SATA, NVMe & Block Storage Devices";
    out_help[n]  = "Configure SATA controller mode & USB legacy options, and inspect all connected SATA/NVMe/USB/VirtIO block devices.";
    n++;

    out_ids[n]   = ADV_SUB_ACPI;
    out_names[n] = "ACPI Table Inspector & Live Patcher";
    out_help[n]  = "Inspect live ACPI tables (DSDT, FACP, SSDT, MCFG, APIC), patch bytes in RAM, and fix SDT checksums before chainloading an OS.";
    n++;

    if (gHw.is_apple_mac) {
        out_ids[n]   = ADV_SUB_APPLE;
        out_names[n] = "Apple / Intel Mac EFI NVRAM Settings";
        out_help[n]  = "Edit Apple Mac NVRAM variables: macOS boot-args, SIP csr-active-config, Startup Chime, and Dual-GPU Power Prefs.";
        n++;
    }

    out_ids[n]   = ADV_SUB_HII;
    out_names[n] = "Firmware HII / IFR Settings Browser";
    out_help[n]  = "Browse & live-edit up to 4,096 motherboard IFR BIOS settings (including [H] Suppressed/Hidden options!) directly in their backing NVRAM VarStores.";
    n++;

    out_ids[n]   = ADV_SUB_DUMP_ACT;
    out_names[n] = "EFI Dump (F12)";
    out_help[n]  = "Save full EFI dump (system report, raw HII/IFR binary packages, decoded VarOffsets, ACPI .aml, SMBIOS & NVRAM) to boot folder.";
    n++;

    return n;
}

static VOID format_hii_prompt_label(const HW_HII_QUESTION *q, const CHAR8 *prefix, CHAR8 *out, UINTN max_len) {
    if (q->is_suppressed) {
        snprintf_ascii(out, max_len, "%s[H] %s", prefix ? prefix : "", q->prompt);
    } else if (prefix && prefix[0]) {
        snprintf_ascii(out, max_len, "%s%s", prefix, q->prompt);
    } else {
        str_cpy(out, q->prompt, max_len);
    }
}

static VOID draw_advanced_tab(VOID) {
    CHAR8 status[80];
    build_footer_status(status, sizeof(status));
    UINTN lx = 2;
    UINTN lw = left_panel_width();

    if (gAdvSub == ADV_SUB_NONE) {
        UINTN sub_ids[12];
        const CHAR8 *sub_names[12];
        const CHAR8 *sub_help[12];
        UINTN mcnt = get_adv_menu_items(sub_ids, sub_names, sub_help);
        if (gAdvCur >= mcnt) gAdvCur = mcnt - 1;

        ui_draw_setup_frame(TAB_ADVANCED, NULL, TRUE,
                            sub_names[gAdvCur], sub_help[gAdvCur], status);

        UINTN step = (mcnt > 0 && (4 + (mcnt - 1) * 2 < gUiRows - 2)) ? 2 : 1;
        for (UINTN i = 0; i < mcnt; i++) {
            BOOLEAN sel = (i == gAdvCur);
            UINT8 a = sel ? gTheme.item_sel_attr : gTheme.item_attr;
            UINTN ry = 4 + i * step;
            if (ry >= gUiRows - 2) break;
            ui_hline(lx, ry, lw, L' ', sel ? a : gTheme.body_attr);
            ui_putc(lx, ry, gBox.arrow_r, a);
            ui_puts_n(lx + 2, ry, sub_names[i], lw - 2, a);
        }
        return;
    }

    if (gAdvSub == ADV_SUB_UNLOCK) {
        unlock_draw_submenu(TAB_ADVANCED, status, &gAdvSubCur, &gAdvSubScroll);
        return;
    }

    if (gAdvSub == ADV_SUB_CPU) {
        hw_refresh_cpu_msrs();
        UINTN cpu_q_idx[48];
        UINTN cpu_q_cnt = get_cpu_hii_questions(cpu_q_idx, 48);

        const CHAR8 *cpu_help = gHw.cpu_msr.is_amd
            ? "AMD Zen/Ryzen All-Core Ring-0 Control:\nAdjust Hardware P0 Frequency (MHz), Core Voltage (SVI2 VID mV), Core Performance Boost (CPB), Active P-State, SVM, Active Threads, and HII PBO/CBS options!\nGreyed items are locked/unavailable on current platform."
            : "Intel All-Core Ring-0 & Lock Control:\nAdjust Target Multiplier, All-Core Turbo Ratio, unlock CFG Lock (0xE2) & OC Lock (0x194) in MSR + HII NVRAM, set PL1/PL2 Power Limits, BD PROCHOT, Active Threads & HII OC!\nGreyed items are hardware-locked.";

        ui_draw_setup_frame(TAB_ADVANCED, "CPU Frequency, Overclock & Locks", TRUE,
                            "CPU & Overclock", cpu_help, status);

        UINTN y = 3;
        CHAR8 b[84];
        draw_kv_row(lx, y++, lw, "CPU Brand", gHw.cpu_brand);

        if (gHw.cpu_mp_total_threads > 0) {
            snprintf_ascii(b, sizeof(b), "%uC / %uT (Active Threads: %u / %u)",
                           gHw.cpu_cores, gHw.cpu_threads,
                           gHw.cpu_mp_threads, gHw.cpu_mp_total_threads);
        } else {
            snprintf_ascii(b, sizeof(b), "%uC / %uT (SMT:%u MADT:%u)",
                           gHw.cpu_cores, gHw.cpu_threads,
                           gHw.cpu_smt_per_core, gHw.cpu_madt_threads);
        }
        draw_kv_row(lx, y++, lw, "Topology / Active", b);

        if (gHw.cpu_msr.is_amd) {
            if (gHw.cpu_msr.amd_pstate_valid && gHw.cpu_msr.amd_p0_mhz > 0) {
                snprintf_ascii(b, sizeof(b), "P0:%uMHz @%umV (VID 0x%02X) P1:%uMHz Cur:P%u",
                               gHw.cpu_msr.amd_p0_mhz, gHw.cpu_msr.amd_p0_mv,
                               gHw.cpu_msr.amd_p0_vid, gHw.cpu_msr.amd_p1_mhz,
                               gHw.cpu_msr.amd_cur_pstate);
            } else if (gHw.cpu_max_mhz > 0) {
                snprintf_ascii(b, sizeof(b), "Base %u MHz / Max %u MHz (P-State MSR Restricted)",
                               gHw.cpu_cur_mhz, gHw.cpu_max_mhz);
            } else {
                str_cpy(b, "Hardware P-State MSR Restricted (Hypervisor/VM)", sizeof(b));
            }
            draw_kv_row(lx, y++, lw, "AMD Clocks & SVI2", b);

            snprintf_ascii(b, sizeof(b), "CPB:%s | SVM:%s%s",
                           gHw.cpu_msr.amd_hwcr_valid
                               ? (!gHw.cpu_msr.amd_cpb_disabled ? "Enabled" : "Disabled") : "N/A",
                           gHw.cpu_msr.amd_vmcr_valid
                               ? (!gHw.cpu_msr.amd_svm_disabled ? "Enabled" : "Disabled")
                               : (gHw.feat_svm ? "Supported" : "N/A"),
                           (gHw.cpu_msr.amd_vmcr_valid && gHw.cpu_msr.amd_svm_locked) ? " (Locked)" : "");
            draw_kv_row(lx, y++, lw, "Boost & SVM Status", b);
            y++;

            UINTN fixed_cnt = 7;
            UINTN total_opts = fixed_cnt + cpu_q_cnt;
            if (gAdvSubCur >= total_opts) gAdvSubCur = total_opts - 1;
            UINTN vis = (gUiRows - 2 > y) ? (gUiRows - 2 - y) : 1;
            if (gAdvSubCur < gAdvSubScroll) gAdvSubScroll = gAdvSubCur;
            if (gAdvSubCur >= gAdvSubScroll + vis) gAdvSubScroll = gAdvSubCur - vis + 1;

            const CHAR8 *cst[3] = { "Disabled", "Auto", "Enabled" };
            for (UINTN r = 0; r < vis && (gAdvSubScroll + r) < total_opts; r++) {
                UINTN idx = gAdvSubScroll + r;
                BOOLEAN sel = (idx == gAdvSubCur);
                if (idx == 0) {
                    if (gHw.cpu_msr.amd_pstate_valid && gHw.cpu_msr.amd_p0_mhz > 0) {
                        snprintf_ascii(b, sizeof(b), "%u MHz [All-Core HW P0]", gHw.cpu_msr.amd_p0_mhz);
                        draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "CPU P0 Target Freq", b);
                    } else {
                        draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "CPU P0 Target Freq", "Locked / VM Restricted");
                    }
                } else if (idx == 1) {
                    if (gHw.cpu_msr.amd_hwcr_valid) {
                        draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "Core Perf Boost (CPB)",
                                        !gHw.cpu_msr.amd_cpb_disabled ? "Enabled [HW MSR]" : "Disabled [HW MSR]");
                    } else {
                        draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "Core Perf Boost (CPB)",
                                        gSetup.cfg.cpu_turbo ? "Enabled [Staged]" : "Disabled [Staged]");
                    }
                } else if (idx == 2) {
                    if (gHw.cpu_msr.amd_pstate_valid) {
                        snprintf_ascii(b, sizeof(b), "P%u Active (Max P%u)",
                                       gHw.cpu_msr.amd_cur_pstate, gHw.cpu_msr.amd_max_pstate);
                        draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "Active HW P-State", b);
                    } else {
                        draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "Active HW P-State", "Unavailable");
                    }
                } else if (idx == 3) {
                    if (gHw.cpu_msr.amd_pstate_valid && gHw.cpu_msr.amd_p0_mv > 0) {
                        snprintf_ascii(b, sizeof(b), "%u mV (VID 0x%02X)", gHw.cpu_msr.amd_p0_mv, gHw.cpu_msr.amd_p0_vid);
                        draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "P0 Core Voltage (VID)", b);
                    } else {
                        draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "P0 Core Voltage (VID)", "Locked / VM Restricted");
                    }
                } else if (idx == 4) {
                    BOOLEAN dim = (gHw.cpu_msr.amd_vmcr_valid && gHw.cpu_msr.amd_svm_locked);
                    if (gHw.cpu_msr.amd_vmcr_valid) {
                        snprintf_ascii(b, sizeof(b), "%s%s",
                                       !gHw.cpu_msr.amd_svm_disabled ? "Enabled" : "Disabled",
                                       gHw.cpu_msr.amd_svm_locked ? " [SVMLock=1]" : " [Unlocked]");
                    } else {
                        str_cpy(b, gSetup.cfg.cpu_virtualization ? "Enabled [Staged]" : "Disabled [Staged]", sizeof(b));
                        dim = !gHw.feat_svm;
                    }
                    draw_opt_row_ex(lx, y + r, lw, sel, dim, "AMD-V (SVM) Virt", b);
                } else if (idx == 5) {
                    BOOLEAN dim = (gHw.cpu_mp_total_threads <= 1);
                    if (gHw.cpu_mp_total_threads > 0) {
                        snprintf_ascii(b, sizeof(b), "%u / %u Threads Active",
                                       gHw.cpu_mp_threads, gHw.cpu_mp_total_threads);
                    } else {
                        snprintf_ascii(b, sizeof(b), "%u Threads (No MP Svc)", gHw.cpu_threads);
                    }
                    draw_opt_row_ex(lx, y + r, lw, sel, dim, "Active CPU Threads", b);
                } else if (idx == 6) {
                    draw_opt_row(lx, y + r, lw, sel, "CPU C-States Policy", cst[gSetup.cfg.cpu_cstates % 3]);
                } else {
                    UINTN qi = cpu_q_idx[idx - fixed_cnt];
                    const HW_HII_QUESTION *hq = &gHw.hii_questions[qi];
                    CHAR8 lbl[32], vstr[32];
                    format_hii_prompt_label(hq, "", lbl, sizeof(lbl));
                    format_hii_question_cur_val(qi, vstr, sizeof(vstr));
                    draw_opt_row_ex(lx, y + r, lw, sel, hq->read_only, lbl, vstr);
                }
            }
        } else {
            /* Intel / Generic x86 CPU View */
            if (gHw.cpu_msr.perf_valid || gHw.cpu_msr.plat_info_valid) {
                snprintf_ascii(b, sizeof(b), "Cur:%ux (%uMHz) Base:%ux Turbo1C:%ux%s",
                               gHw.cpu_msr.intel_cur_ratio, (UINT32)gHw.cpu_msr.intel_cur_ratio * 100U,
                               gHw.cpu_msr.intel_base_ratio, gHw.cpu_msr.intel_turbo_1c,
                               gHw.cpu_msr.pkg_pwr_valid ? "" : "");
                if (gHw.cpu_msr.pkg_pwr_valid && gHw.cpu_msr.pl1_watts > 0) {
                    snprintf_ascii(b, sizeof(b), "Cur:%ux (%uMHz) T1C:%ux | PL1:%uW PL2:%uW",
                                   gHw.cpu_msr.intel_cur_ratio, (UINT32)gHw.cpu_msr.intel_cur_ratio * 100U,
                                   gHw.cpu_msr.intel_turbo_1c,
                                   gHw.cpu_msr.pl1_watts, gHw.cpu_msr.pl2_watts);
                }
            } else {
                snprintf_ascii(b, sizeof(b), "Fam %u Mod 0x%02X Step %u | %s %s",
                               gHw.cpu_family, gHw.cpu_model, gHw.cpu_stepping,
                               gHw.feat_vmx ? "VT-x" : "NoVMX",
                               gHw.feat_avx2 ? "AVX2" : (gHw.feat_avx ? "AVX" : "SSE"));
            }
            draw_kv_row(lx, y++, lw, "Clocks & Power (MSR)", b);

            snprintf_ascii(b, sizeof(b), "CFG(0xE2):%s | OC(0x194):%s",
                           gHw.cpu_msr.cst_cfg_valid ? (gHw.cpu_msr.cfg_locked ? "LOCKED" : "UNLOCKED") : "Restricted",
                           gHw.cpu_msr.flex_oc_valid ? (gHw.cpu_msr.oc_locked ? "LOCKED" : "UNLOCKED") : "Restricted");
            draw_kv_row(lx, y++, lw, "Hardware Lock Bits", b);
            y++;

            UINTN fixed_cnt = 12;
            UINTN total_opts = fixed_cnt + cpu_q_cnt;
            if (gAdvSubCur >= total_opts) gAdvSubCur = total_opts - 1;
            UINTN vis = (gUiRows - 2 > y) ? (gUiRows - 2 - y) : 1;
            if (gAdvSubCur < gAdvSubScroll) gAdvSubScroll = gAdvSubCur;
            if (gAdvSubCur >= gAdvSubScroll + vis) gAdvSubScroll = gAdvSubCur - vis + 1;

            INTN hii_cfg_q = hw_hii_find_question_icase("CFG Lock", NULL);
            INTN hii_oc_q  = hw_hii_find_question_icase("Overclock", "Lock");

            for (UINTN r = 0; r < vis && (gAdvSubScroll + r) < total_opts; r++) {
                UINTN idx = gAdvSubScroll + r;
                BOOLEAN sel = (idx == gAdvSubCur);
                if (idx == 0) {
                    if (gHw.cpu_msr.perf_valid &&
                        (gHw.cpu_msr.intel_target_ratio > 0 || gHw.cpu_msr.intel_base_ratio > 0)) {
                        UINT8 dr = gHw.cpu_msr.intel_target_ratio ? gHw.cpu_msr.intel_target_ratio : gHw.cpu_msr.intel_cur_ratio;
                        snprintf_ascii(b, sizeof(b), "%ux (%u MHz) [MSR 0x199]", dr, (UINT32)dr * 100U);
                        draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "CPU Target Multiplier", b);
                    } else {
                        draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "CPU Target Multiplier", "Unavailable in VM");
                    }
                } else if (idx == 1) {
                    BOOLEAN dim = !gHw.cpu_msr.turbo_limit_valid ||
                                  (gHw.cpu_msr.flex_oc_valid && gHw.cpu_msr.oc_locked && !gHw.cpu_msr.intel_tdp_ratio_unl);
                    if (gHw.cpu_msr.turbo_limit_valid && gHw.cpu_msr.intel_turbo_allc > 0) {
                        snprintf_ascii(b, sizeof(b), "All:%ux / 1C:%ux%s",
                                       gHw.cpu_msr.intel_turbo_allc, gHw.cpu_msr.intel_turbo_1c,
                                       dim ? " [Locked]" : " [RW]");
                    } else {
                        str_cpy(b, "Unavailable / Locked", sizeof(b));
                        dim = TRUE;
                    }
                    draw_opt_row_ex(lx, y + r, lw, sel, dim, "All-Core Turbo Ratio", b);
                } else if (idx == 2) {
                    BOOLEAN dim = (!gHw.cpu_msr.cst_cfg_valid && hii_cfg_q < 0);
                    if (gHw.cpu_msr.cst_cfg_valid) {
                        snprintf_ascii(b, sizeof(b), "%s%s",
                                       gHw.cpu_msr.cfg_locked ? "LOCKED" : "UNLOCKED",
                                       (gHw.cpu_msr.cfg_locked && hii_cfg_q >= 0) ? " [Unlock via HII!]" : "");
                    } else if (hii_cfg_q >= 0) {
                        format_hii_question_cur_val((UINTN)hii_cfg_q, b, sizeof(b));
                    } else {
                        str_cpy(b, "Unavailable", sizeof(b));
                    }
                    draw_opt_row_ex(lx, y + r, lw, sel, dim, "CFG Lock (MSR 0xE2)", b);
                } else if (idx == 3) {
                    BOOLEAN dim = (!gHw.cpu_msr.flex_oc_valid && hii_oc_q < 0);
                    if (gHw.cpu_msr.flex_oc_valid) {
                        snprintf_ascii(b, sizeof(b), "%s (Flex:%ux)",
                                       gHw.cpu_msr.oc_locked ? "OC Locked" : "Unlocked",
                                       gHw.cpu_msr.flex_ratio);
                    } else if (hii_oc_q >= 0) {
                        format_hii_question_cur_val((UINTN)hii_oc_q, b, sizeof(b));
                    } else {
                        str_cpy(b, "Unavailable", sizeof(b));
                    }
                    draw_opt_row_ex(lx, y + r, lw, sel, dim, "OC Lock / Flex Ratio", b);
                } else if (idx == 4) {
                    BOOLEAN dim = (!gHw.cpu_msr.pkg_pwr_valid || gHw.cpu_msr.pkg_pwr_locked ||
                                   (gHw.cpu_msr.pl1_watts == 0 && gHw.cpu_msr.pl2_watts == 0));
                    if (gHw.cpu_msr.pkg_pwr_valid && (gHw.cpu_msr.pl1_watts > 0 || gHw.cpu_msr.pl2_watts > 0)) {
                        snprintf_ascii(b, sizeof(b), "PL1:%uW / PL2:%uW%s",
                                       gHw.cpu_msr.pl1_watts, gHw.cpu_msr.pl2_watts,
                                       gHw.cpu_msr.pkg_pwr_locked ? " [Locked]" : "");
                    } else {
                        str_cpy(b, "Unavailable in VM", sizeof(b));
                    }
                    draw_opt_row_ex(lx, y + r, lw, sel, dim, "Package Power PL1/PL2", b);
                } else if (idx == 5) {
                    draw_opt_row_ex(lx, y + r, lw, sel, !gHw.cpu_msr.misc_valid, "SpeedStep (MSR 0x1A0)",
                        gHw.cpu_msr.misc_valid ? (gHw.cpu_msr.eist_enabled ? "Enabled [HW]" : "Disabled [HW]")
                                               : "Unavailable");
                } else if (idx == 6) {
                    draw_opt_row_ex(lx, y + r, lw, sel, !gHw.cpu_msr.misc_valid && !gHw.cpu_msr.turbo_hw_avail,
                        "Turbo Boost (0x1A0)",
                        gHw.cpu_msr.misc_valid ? (!gHw.cpu_msr.turbo_disabled ? "Enabled [HW]" : "Disabled [HW]")
                                               : (gSetup.cfg.cpu_turbo ? "Enabled [Staged]" : "Disabled [Staged]"));
                } else if (idx == 7) {
                    draw_opt_row_ex(lx, y + r, lw, sel, !gHw.cpu_msr.power_ctl_valid, "BD PROCHOT (MSR 0x1FC)",
                        gHw.cpu_msr.power_ctl_valid ? (gHw.cpu_msr.bd_prochot ? "Enabled [HW]" : "Disabled [HW]")
                                                    : "Unavailable");
                } else if (idx == 8) {
                    draw_opt_row_ex(lx, y + r, lw, sel, !gHw.cpu_msr.power_ctl_valid, "C1E Halt (MSR 0x1FC)",
                        gHw.cpu_msr.power_ctl_valid ? (gHw.cpu_msr.c1e_enable ? "Enabled [HW]" : "Disabled [HW]")
                                                    : "Unavailable");
                } else if (idx == 9) {
                    BOOLEAN dim = (gHw.cpu_msr.feat_ctl_valid && gHw.cpu_msr.vmx_locked);
                    if (gHw.cpu_msr.feat_ctl_valid) {
                        snprintf_ascii(b, sizeof(b), "%s%s",
                                       gHw.cpu_msr.vmx_outside_smx ? "Enabled" : "Disabled",
                                       gHw.cpu_msr.vmx_locked ? " [Locked]" : " [Unlocked]");
                    } else {
                        str_cpy(b, gSetup.cfg.cpu_virtualization ? "Enabled [Staged]" : "Disabled [Staged]", sizeof(b));
                        dim = !gHw.feat_vmx;
                    }
                    draw_opt_row_ex(lx, y + r, lw, sel, dim, "Virtualization (VT-x)", b);
                } else if (idx == 10) {
                    BOOLEAN dim = (gHw.cpu_mp_total_threads <= 1);
                    if (gHw.cpu_mp_total_threads > 0) {
                        snprintf_ascii(b, sizeof(b), "%u / %u Threads Active",
                                       gHw.cpu_mp_threads, gHw.cpu_mp_total_threads);
                    } else {
                        snprintf_ascii(b, sizeof(b), "%u Threads (No MP Svc)", gHw.cpu_threads);
                    }
                    draw_opt_row_ex(lx, y + r, lw, sel, dim, "Active CPU Threads", b);
                } else if (idx == 11) {
                    if (gUnlockFivr.supported) {
                        snprintf_ascii(b, sizeof(b), "Core:%dmV / Cache:%dmV",
                                       gUnlockFivr.plane_mv[0], gUnlockFivr.plane_mv[2]);
                        draw_opt_row_ex(lx, y + r, lw, sel, gUnlockFivr.plundervolt_locked,
                                        "FIVR Undervolt (0x150)", b);
                    } else {
                        draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "FIVR Undervolt (0x150)",
                                        gHw.feat_hypervisor ? "Unavailable in VM" : "Unavailable");
                    }
                } else {
                    UINTN qi = cpu_q_idx[idx - fixed_cnt];
                    const HW_HII_QUESTION *hq = &gHw.hii_questions[qi];
                    CHAR8 lbl[32], vstr[32];
                    format_hii_prompt_label(hq, "", lbl, sizeof(lbl));
                    format_hii_question_cur_val(qi, vstr, sizeof(vstr));
                    draw_opt_row_ex(lx, y + r, lw, sel, hq->read_only, lbl, vstr);
                }
            }
        }
    } else if (gAdvSub == ADV_SUB_GPU_VRAM) {
        hw_refresh_igd_ggc();
        UINTN gpu_q_idx[48];
        UINTN gpu_q_cnt = get_gpu_hii_questions(gpu_q_idx, 48);
        INTN  rebar_gpu = find_first_rebar_gpu_pci_idx();

        const CHAR8 *gpu_sub_hdr = gHw.is_apple_mac
            ? "GPU, VRAM, ReBAR & Mac Mux"
            : "GPU, VRAM, ReBAR & Display";
        const CHAR8 *gpu_help = gHw.is_apple_mac
            ? "Switch Default GPU on dual-GPU Macs (gpu-power-prefs), adjust PCIe Resizable BAR aperture, Intel GMCH Stolen VRAM (GGC), GOP mode, or HII GPU settings."
            : "Configure Primary Display Adapter, live PCIe Resizable BAR (ReBAR / SAM) aperture size via ECAM, Above 4G MMIO Decoding, iGPU UMA/DVMT VRAM size, GOP mode, and motherboard HII GPU settings.\nGreyed options are locked or unsupported on current GPU.";

        ui_draw_setup_frame(TAB_ADVANCED, gpu_sub_hdr, TRUE,
                            "GPU, VRAM & ReBAR", gpu_help, status);

        UINTN y = 3;
        CHAR8 b[84];
        BOOLEAN has_intel_igpu = gHw.igd_ggc_present;
        BOOLEAN has_amd_apu_igpu = FALSE;
        for (UINTN g = 0; g < gHw.gpu_count && y < 6; g++) {
            UINTN pidx = gHw.gpu_pci_indices[g];
            hw_refresh_pci_dev(pidx);
            const HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pidx];
            if (pd->vendor_id == 0x8086 && pd->bus == 0) has_intel_igpu = TRUE;
            if (pd->vendor_id == 0x1002 && pd->vram_bar_size > 0 && (pd->vram_bar_size >> 20) <= 2048 && gHw.cpu_msr.is_amd)
                has_amd_apu_igpu = TRUE;

            CHAR8 glbl[24];
            snprintf_ascii(glbl, sizeof(glbl), "Detected GPU #%u", (UINT32)g);
            if (pd->rebar_supported && pd->rebar_ext_off != 0) {
                snprintf_ascii(b, sizeof(b), "%02X:%02X.%X %s [%04X:%04X] BAR:%luMB ReBAR:%lu/%luMB",
                               pd->bus, pd->dev, pd->func, pd->vendor_name,
                               pd->vendor_id, pd->device_id, pd->vram_bar_size >> 20,
                               1ULL << pd->rebar_cur_size_exp, 1ULL << pd->rebar_max_size_exp);
            } else if (pd->vram_bar_size > 0) {
                snprintf_ascii(b, sizeof(b), "%02X:%02X.%X %s [%04X:%04X] %lu MB BAR",
                               pd->bus, pd->dev, pd->func, pd->vendor_name,
                               pd->vendor_id, pd->device_id, pd->vram_bar_size >> 20);
            } else {
                snprintf_ascii(b, sizeof(b), "%02X:%02X.%X %s [%04X:%04X] %s",
                               pd->bus, pd->dev, pd->func, pd->vendor_name,
                               pd->vendor_id, pd->device_id, pd->class_name);
            }
            draw_kv_row(lx, y++, lw, glbl, b);
        }
        if (gHw.igd_ggc_present) {
            snprintf_ascii(b, sizeof(b), "%u MB Stolen / %u MB GTT (%s)",
                           gHw.igd_stolen_mb, gHw.igd_gtt_mb,
                           gHw.igd_ggc_locked ? "MRC Locked" : "Unlocked RW!");
            draw_kv_row(lx, y++, lw, "Intel GMCH GGC (0x50)", b);
        }
        y++;

        UINTN mac_extra = gHw.is_apple_mac ? 1 : 0;
        UINTN fixed_cnt = mac_extra + 5;
        UINTN total_items = fixed_cnt + gpu_q_cnt;
        if (gAdvSubCur >= total_items) gAdvSubCur = total_items - 1;
        UINTN vis = (gUiRows - 2 > y) ? (gUiRows - 2 - y) : 1;
        if (gAdvSubCur < gAdvSubScroll) gAdvSubScroll = gAdvSubCur;
        if (gAdvSubCur >= gAdvSubScroll + vis) gAdvSubScroll = gAdvSubCur - vis + 1;

        const CHAR8 *mac_gpu_s[3]  = { "Auto (Default)", "Force Intel iGPU (01)", "Discrete / Dynamic (00)" };
        const CHAR8 *pri_disp_s[3] = { "Auto", "Integrated iGPU", "Discrete PCIe GPU" };
        const CHAR8 *dvmt_s[6]     = { "32 MB", "64 MB", "96 MB", "128 MB", "256 MB", "512 MB" };
        INTN rebar_hii = hw_hii_find_question_icase("Resizable BAR", NULL);
        if (rebar_hii < 0) rebar_hii = hw_hii_find_question_icase("Re-Size BAR", NULL);

        for (UINTN r = 0; r < vis && (gAdvSubScroll + r) < total_items; r++) {
            UINTN idx = gAdvSubScroll + r;
            BOOLEAN sel = (idx == gAdvSubCur);
            if (gHw.is_apple_mac && idx == 0) {
                draw_opt_row(lx, y + r, lw, sel, "Mac Default GPU Mux",
                             mac_gpu_s[gSetup.apple_gpu_mode % 3]);
                continue;
            }
            UINTN rel = idx - mac_extra;
            if (rel == 0) {
                draw_opt_row(lx, y + r, lw, sel, "Primary Display Pref",
                             pri_disp_s[gSetup.cfg.primary_display % 3]);
            } else if (rel == 1) {
                if (rebar_gpu >= 0) {
                    const HW_PCI_DEV_INFO *rg = &gHw.pci_devs[rebar_gpu];
                    snprintf_ascii(b, sizeof(b), "%lu MB Active (Max %lu MB)",
                                   1ULL << rg->rebar_cur_size_exp, 1ULL << rg->rebar_max_size_exp);
                    draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "Resizable BAR (ReBAR)", b);
                } else if (rebar_hii >= 0) {
                    format_hii_question_cur_val((UINTN)rebar_hii, b, sizeof(b));
                    draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "Resizable BAR (HII)", b);
                } else {
                    draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "Resizable BAR (ReBAR)", "Not Supported on GPU");
                }
            } else if (rel == 2) {
                draw_opt_row(lx, y + r, lw, sel, "Above 4G MMIO Decode",
                             gSetup.cfg.above_4g_decode ? "Enabled" : "Disabled");
            } else if (rel == 3) {
                if (gHw.igd_ggc_present && !gHw.igd_ggc_locked) {
                    snprintf_ascii(b, sizeof(b), "%u MB [HW Live RW]", gHw.igd_stolen_mb);
                    draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "iGPU UMA / DVMT VRAM", b);
                } else if (gHw.igd_ggc_present && gHw.igd_ggc_locked) {
                    snprintf_ascii(b, sizeof(b), "%u MB [MRC Locked]", gHw.igd_stolen_mb);
                    draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "iGPU UMA / DVMT VRAM", b);
                } else if (has_intel_igpu || has_amd_apu_igpu) {
                    draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "iGPU UMA / VRAM Size",
                                    dvmt_s[gSetup.cfg.igd_dvmt_prealloc % 6]);
                } else {
                    draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "iGPU UMA / VRAM Size", "No iGPU Detected");
                }
            } else if (rel == 4) {
                if (gHw.gop_present) {
                    snprintf_ascii(b, sizeof(b), "Mode %u (%ux%u)", gHw.gop_cur_mode, gHw.gop_width, gHw.gop_height);
                    draw_opt_row_ex(lx, y + r, lw, sel, FALSE, "UEFI GOP Resolution", b);
                } else {
                    draw_opt_row_ex(lx, y + r, lw, sel, TRUE, "UEFI GOP Resolution", "Not Present");
                }
            } else {
                UINTN qi = gpu_q_idx[rel - 5];
                const HW_HII_QUESTION *hq = &gHw.hii_questions[qi];
                CHAR8 lbl[32], vstr[32];
                format_hii_prompt_label(hq, "", lbl, sizeof(lbl));
                format_hii_question_cur_val(qi, vstr, sizeof(vstr));
                draw_opt_row_ex(lx, y + r, lw, sel, hq->read_only, lbl, vstr);
            }
        }
    } else if (gAdvSub == ADV_SUB_PCIE) {
        ui_draw_setup_frame(TAB_ADVANCED, "PCIe Gen1-Gen5, ASPM & ReBAR", TRUE,
                            "PCIe Hardware Control",
                            "Press Enter on Global ASPM to apply across all PCIe links, or press Enter on any PCI/PCIe device below to edit ASPM, Gen1-Gen5 (2.5-32 GT/s) Link Speed, Resizable BAR, Relaxed Ordering, Max Read Req, or 256B Config!",
                            status);
        UINTN y = 3;
        const CHAR8 *aspm_pol[5] = { "Disabled", "L0s Only", "L1 Only", "L0s + L1", "OS Controlled" };
        draw_opt_row(lx, y++, lw, gAdvSubCur == 0, "Global PCIe ASPM Mode",
                     aspm_pol[gSetup.cfg.pcie_aspm_policy % 5]);
        y++;

        UINTN total_sel = 1 + gHw.pci_count;
        if (gAdvSubCur >= total_sel) gAdvSubCur = total_sel - 1;
        UINTN vis = (gUiRows - 2 > y) ? (gUiRows - 2 - y) : 1;
        UINTN pci_sel = (gAdvSubCur > 0) ? (gAdvSubCur - 1) : 0;
        if (pci_sel < gAdvSubScroll) gAdvSubScroll = pci_sel;
        if (pci_sel >= gAdvSubScroll + vis) gAdvSubScroll = pci_sel - vis + 1;

        const CHAR8 *aspm_short[4] = { "Off", "L0s", "L1", "L0sL1" };
        for (UINTN r = 0; r < vis && (gAdvSubScroll + r) < gHw.pci_count; r++) {
            UINTN pidx = gAdvSubScroll + r;
            const HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pidx];
            BOOLEAN sel = (gAdvSubCur == 1 + pidx);
            UINT8 a = sel ? gTheme.item_sel_attr : gTheme.item_attr;
            ui_hline(lx, y + r, lw, L' ', sel ? a : gTheme.body_attr);
            CHAR8 b[96];
            if (pd->pcie_cap_off != 0 && pd->pcie_cur_width > 0) {
                snprintf_ascii(b, sizeof(b), "%02X:%02X.%X [%04X:%04X] Gen%ux%-2u ASPM:%-5s %s",
                               pd->bus, pd->dev, pd->func, pd->vendor_id, pd->device_id,
                               pd->pcie_cur_speed, pd->pcie_cur_width,
                               aspm_short[pd->pcie_aspm_cur & 3U], pd->class_name);
            } else {
                snprintf_ascii(b, sizeof(b), "%02X:%02X.%X [%04X:%04X] %-10s %s",
                               pd->bus, pd->dev, pd->func, pd->vendor_id, pd->device_id,
                               pd->vendor_name, pd->class_name);
            }
            ui_puts_n(lx, y + r, b, lw, a);
        }
    } else if (gAdvSub == ADV_SUB_MEMORY) {
        UINTN mem_q_idx[24];
        UINTN mem_q_cnt = get_mem_hii_questions(mem_q_idx, 24);
        UINTN total_opts = 1 + mem_q_cnt;
        if (gAdvSubCur >= total_opts) gAdvSubCur = total_opts - 1;

        ui_draw_setup_frame(TAB_ADVANCED, "Memory (XMP/EXPO) & DIMM Slots", TRUE,
                            "Memory & Profiles",
                            "Displays UEFI GetMemoryMap() allocation totals, discovered motherboard HII Memory Overclock / XMP / EXPO / DOCP / FCLK settings, and SMBIOS Type 17 DIMM inventory.",
                            status);
        UINTN y = 3;
        CHAR8 b[84];
        snprintf_ascii(b, sizeof(b), "%lu MB (%u Descriptors)",
                       gHw.total_ram_bytes >> 20, (UINT32)gHw.mem_desc_count);
        draw_kv_row(lx, y++, lw, "Total Physical RAM", b);
        snprintf_ascii(b, sizeof(b), "%lu MB", gHw.usable_ram_bytes >> 20);
        draw_kv_row(lx, y++, lw, "Conventional Free", b);
        snprintf_ascii(b, sizeof(b), "ACPI:%luKB  RT:%luKB  BS:%luMB",
                       gHw.acpi_ram_bytes >> 10, gHw.runtime_ram_bytes >> 10, gHw.boot_svcs_bytes >> 20);
        draw_kv_row(lx, y++, lw, "Firmware Memory", b);

        draw_opt_row(lx, y++, lw, gAdvSubCur == 0, "ACPI Sleep State",
                     gSetup.cfg.acpi_s3_sleep ? "S3 (Suspend to RAM)" : "Suspend Disabled");

        for (UINTN mq = 0; mq < mem_q_cnt && y < gUiRows - 6; mq++) {
            UINTN qi = mem_q_idx[mq];
            const HW_HII_QUESTION *hq = &gHw.hii_questions[qi];
            CHAR8 lbl[32], vstr[32];
            format_hii_prompt_label(hq, "", lbl, sizeof(lbl));
            format_hii_question_cur_val(qi, vstr, sizeof(vstr));
            draw_opt_row_ex(lx, y++, lw, gAdvSubCur == (1 + mq), hq->read_only, lbl, vstr);
        }

        y++;
        if (y < gUiRows - 2) {
            ui_puts_n(lx, y++, "-- SMBIOS Type 17 DIMM Slots --", lw, gTheme.section_attr);
        }
        if (gHw.dimm_count == 0 && y < gUiRows - 2) {
            ui_puts_n(lx, y++, "No SMBIOS Type 17 DIMM records reported by firmware.", lw, gTheme.value_attr);
        } else {
            for (UINTN i = 0; i < gHw.dimm_count && y < gUiRows - 2; i++) {
                const HW_DIMM_INFO *dm = &gHw.dimms[i];
                if (dm->populated) {
                    snprintf_ascii(b, sizeof(b), "%-10s %5uMB %s %uMHz %s %s",
                                   dm->locator, dm->size_mb, dm->mem_type, dm->speed_mhz,
                                   dm->manufacturer, dm->part_number);
                } else {
                    snprintf_ascii(b, sizeof(b), "%-10s [Empty Slot]", dm->locator);
                }
                ui_puts_n(lx, y++, b, lw, gTheme.label_attr);
            }
        }
    } else if (gAdvSub == ADV_SUB_STORAGE) {
        ui_draw_setup_frame(TAB_ADVANCED, "SATA & Block Storage Configuration", TRUE,
                            "Storage Subsystem",
                            "Configure SATA & USB storage options and inspect real EFI_BLOCK_IO_PROTOCOL drives.\nESC: Back.",
                            status);
        UINTN y = 3;
        const CHAR8 *smode[3] = { "IDE Compatibility", "AHCI Mode", "RAID Mode" };
        draw_opt_row(lx, y++, lw, gAdvSubCur == 0, "SATA Mode Selection", smode[gSetup.cfg.sata_mode % 3]);
        const CHAR8 *uleg[3] = { "Disabled", "Enabled", "Auto" };
        draw_opt_row(lx, y++, lw, gAdvSubCur == 1, "Legacy USB Support", uleg[gSetup.cfg.usb_legacy % 3]);

        y++;
        ui_puts_n(lx, y++, "-- Detected Block Devices --", lw, gTheme.section_attr);
        if (gHw.disk_count == 0) {
            ui_puts_n(lx, y++, "No BlockIO media detected.", lw, gTheme.value_attr);
        } else {
            for (UINTN i = 0; i < gHw.disk_count && y < gUiRows - 2; i++) {
                const HW_DISK_INFO *dk = &gHw.disks[i];
                CHAR8 line[96];
                snprintf_ascii(line, sizeof(line), "[%s] %6luMB (%uB blk) %s",
                               dk->is_partition ? "Part" : (dk->removable ? "Remv" : "Disk"),
                               dk->size_mb, dk->block_size, dk->label);
                ui_puts_n(lx, y++, line, lw, gTheme.label_attr);
            }
        }
    } else if (gAdvSub == ADV_SUB_ACPI) {
        ui_draw_setup_frame(TAB_ADVANCED, "ACPI Table Inspector & Live Patcher", TRUE,
                            "ACPI Firmware Tables",
                            "Press Enter on any ACPI table to view/patch bytes in RAM or recalculate its SDT checksum before chainloading an OS.",
                            status);
        UINTN y = 3;
        CHAR8 b[80];
        snprintf_ascii(b, sizeof(b), "0x%lX (Rev %u, OEM: %s)",
                       gHw.acpi_rsdp_addr, gHw.acpi_revision, gHw.acpi_oem_id);
        draw_kv_row(lx, y++, lw, "ACPI RSDP Pointer", b);
        y++;

        UINTN vis = (gUiRows - 2 > y) ? (gUiRows - 2 - y) : 1;
        if (gHw.acpi_count == 0) {
            ui_puts_n(lx, y, "No ACPI tables found in EFI ConfigurationTable.", lw, gTheme.value_attr);
        } else {
            if (gAdvSubCur >= gHw.acpi_count) gAdvSubCur = gHw.acpi_count - 1;
            if (gAdvSubCur < gAdvSubScroll) gAdvSubScroll = gAdvSubCur;
            if (gAdvSubCur >= gAdvSubScroll + vis) gAdvSubScroll = gAdvSubCur - vis + 1;
            for (UINTN r = 0; r < vis && (gAdvSubScroll + r) < gHw.acpi_count; r++) {
                UINTN idx = gAdvSubScroll + r;
                const HW_ACPI_TABLE_INFO *ti = &gHw.acpi_tables[idx];
                BOOLEAN sel = (idx == gAdvSubCur);
                UINT8 a = sel ? gTheme.item_sel_attr : gTheme.item_attr;
                ui_hline(lx, y + r, lw, L' ', sel ? a : gTheme.body_attr);
                snprintf_ascii(b, sizeof(b), "%-4s @0x%08lX %6uB %-8s %s %s",
                               ti->signature, ti->phys_addr, ti->length, ti->oem_table_id,
                               ti->checksum_ok ? "CS:OK" : "CS:BAD",
                               ti->writable ? "[RW]" : "[RO]");
                ui_puts_n(lx, y + r, b, lw, a);
            }
        }
    } else if (gAdvSub == ADV_SUB_APPLE) {
        ui_draw_setup_frame(TAB_ADVANCED, "Apple / Intel Mac EFI Settings", TRUE,
                            "Apple Mac NVRAM",
                            "Configure Apple Mac NVRAM variables: boot-args, SIP csr-active-config, Startup Chime, and Dual-GPU Mux (gpu-power-prefs).\nPress F10 to commit to NVRAM.",
                            status);
        UINTN y = 3;
        draw_kv_row(lx, y++, lw, "Apple Mac Detected", gHw.is_apple_mac ? "Yes (Apple EFI)" : "No");
        draw_kv_row(lx, y++, lw, "Board-ID / MLB", gHw.board_product);
        y++;

        draw_opt_row(lx, y++, lw, gAdvSubCur == 0, "macOS boot-args",
                     gSetup.apple_boot_args[0] ? gSetup.apple_boot_args : "<none / normal>");

        CHAR8 csr_s[32];
        if (!gSetup.apple_csr_present && !gSetup.apple_csr_dirty) {
            str_cpy(csr_s, "Default (Not Set)", sizeof(csr_s));
        } else if (gSetup.apple_csr_config == 0) {
            str_cpy(csr_s, "SIP Enabled (0x0)", sizeof(csr_s));
        } else if (gSetup.apple_csr_config == 0x67000000U || gSetup.apple_csr_config == 0x00000067U) {
            str_cpy(csr_s, "SIP Disabled (0x67)", sizeof(csr_s));
        } else {
            snprintf_ascii(csr_s, sizeof(csr_s), "0x%08X", gSetup.apple_csr_config);
        }
        draw_opt_row(lx, y++, lw, gAdvSubCur == 1, "SIP csr-active-config", csr_s);

        CHAR8 vol_s[28];
        if (gSetup.apple_audio_vol & 0x80U) str_cpy(vol_s, "Muted (0x80)", sizeof(vol_s));
        else snprintf_ascii(vol_s, sizeof(vol_s), "Level 0x%02X", gSetup.apple_audio_vol);
        draw_opt_row(lx, y++, lw, gAdvSubCur == 2, "Startup Chime Volume", vol_s);

        const CHAR8 *mgpu[3] = { "Auto (Default)", "Force Intel iGPU (01)", "Discrete / Dynamic (00)" };
        draw_opt_row(lx, y++, lw, gAdvSubCur == 3, "GPU Power Prefs (Mux)", mgpu[gSetup.apple_gpu_mode % 3]);
    } else if (gAdvSub == ADV_SUB_HII) {
        UINTN q_cnt = get_filtered_hii_questions(gHiiFilteredIdx, HW_MAX_HII_QUESTIONS);
        UINTN total_items = 3 + q_cnt + gHw.hii_varstore_count;
        if (gAdvSubCur >= total_items) gAdvSubCur = total_items - 1;

        const CHAR8 *htitle = "HII / IFR Settings";
        CHAR8 hbody[320];
        if (gAdvSubCur >= 3 && gAdvSubCur < 3 + q_cnt) {
            const HW_HII_QUESTION *hq = &gHw.hii_questions[gHiiFilteredIdx[gAdvSubCur - 3]];
            const CHAR8 *vsn = (hq->varstore_idx >= 0 && (UINTN)hq->varstore_idx < gHw.hii_varstore_count)
                               ? gHw.hii_varstores[hq->varstore_idx].name : "?";
            htitle = hq->formset_title;
            snprintf_ascii(hbody, sizeof(hbody),
                "%s%s\nStore: %s | Off: 0x%04X (%uB)\n%s",
                hq->is_suppressed ? "[HIDDEN IN BIOS] " : "",
                hq->prompt, vsn, (UINT32)hq->var_offset, (UINT32)hq->width,
                hq->help[0] ? hq->help : "Press Enter to view all options & write NVRAM VarStore.");
        } else {
            snprintf_ascii(hbody, sizeof(hbody),
                "Decodes live EFI_HII_DATABASE_PROTOCOL IFR FormSets (%u Questions, %u Hidden [H], %u VarStores).\n"
                "Filter by Category (Hidden, CPU/OC, GPU/ReBAR, Memory/XMP) or press '/' to search!",
                (UINT32)gHw.hii_question_count, (UINT32)gHw.hii_hidden_count, (UINT32)gHw.hii_varstore_count);
        }

        ui_draw_setup_frame(TAB_ADVANCED, "HII / IFR Settings Browser", TRUE, htitle, hbody, status);

        UINTN y = 3;
        UINTN vis = (gUiRows - 2 > y) ? (gUiRows - 2 - y) : 1;
        if (gAdvSubCur < gAdvSubScroll) gAdvSubScroll = gAdvSubCur;
        if (gAdvSubCur >= gAdvSubScroll + vis) gAdvSubScroll = gAdvSubCur - vis + 1;

        const CHAR8 *cat_names[6] = {
            "All Decoded Settings",
            "Hidden / Suppressed [H]",
            "CPU / Overclock / Locks",
            "GPU / VRAM / ReBAR / PCIe",
            "Memory / XMP / EXPO",
            "ME / PSP / SPI / Security"
        };

        for (UINTN r = 0; r < vis && (gAdvSubScroll + r) < total_items; r++) {
            UINTN idx = gAdvSubScroll + r;
            BOOLEAN sel = (idx == gAdvSubCur);
            UINT8 a = sel ? gTheme.item_sel_attr : gTheme.item_attr;
            ui_hline(lx, y + r, lw, L' ', sel ? a : gTheme.body_attr);

            if (idx == 0) {
                draw_opt_row(lx, y + r, lw, sel, "Category / View Mode", cat_names[gHiiCatMode % 6]);
            } else if (idx == 1) {
                draw_opt_row(lx, y + r, lw, sel, "Search / Filter ('/')",
                             gHiiFilter[0] ? gHiiFilter : "<All Matching>");
            } else if (idx == 2) {
                ui_putc(lx, y + r, gBox.arrow_r, a);
                ui_puts_n(lx + 2, y + r, "EFI Dump (F12)...", lw - 2, a);
            } else if (idx < 3 + q_cnt) {
                UINTN qi = gHiiFilteredIdx[idx - 3];
                const HW_HII_QUESTION *hq = &gHw.hii_questions[qi];
                CHAR8 lbl[32], vstr[32];
                format_hii_prompt_label(hq, "", lbl, sizeof(lbl));
                format_hii_question_cur_val(qi, vstr, sizeof(vstr));
                draw_opt_row_ex(lx, y + r, lw, sel, hq->read_only, lbl, vstr);
            } else {
                UINTN vi = idx - 3 - q_cnt;
                const HW_HII_VARSTORE_INFO *vs = &gHw.hii_varstores[vi];
                CHAR8 b[80];
                snprintf_ascii(b, sizeof(b), "[Raw VarStore] %-18s (%uB, ID 0x%04X)",
                               vs->name, vs->size, vs->varstore_id);
                ui_puts_n(lx, y + r, b, lw, a);
            }
        }
    }
}

static BOOLEAN handle_advanced_key(const EFI_INPUT_KEY *k) {
    if (gAdvSub == ADV_SUB_NONE) {
        UINTN sub_ids[12];
        const CHAR8 *sub_names[12];
        const CHAR8 *sub_help[12];
        UINTN mcnt = get_adv_menu_items(sub_ids, sub_names, sub_help);
        if (gAdvCur >= mcnt) gAdvCur = mcnt - 1;

        if (k->ScanCode == SCAN_UP) {
            gAdvCur = (gAdvCur > 0) ? (gAdvCur - 1) : (mcnt - 1);
            return TRUE;
        } else if (k->ScanCode == SCAN_DOWN) {
            gAdvCur = (gAdvCur + 1) % mcnt;
            return TRUE;
        } else if (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') {
            if (sub_ids[gAdvCur] == ADV_SUB_DUMP_ACT) {
                dump_run_interactive_modal();
                return TRUE;
            }
            gAdvSub = sub_ids[gAdvCur];
            gAdvSubCur = 0;
            gAdvSubScroll = 0;
            return TRUE;
        }
        return FALSE;
    }

    if (k->ScanCode == SCAN_ESC || k->UnicodeChar == 0x1B) {
        gAdvSub = ADV_SUB_NONE;
        return TRUE;
    }

    if (gAdvSub == ADV_SUB_UNLOCK) {
        return unlock_handle_submenu_key(k, &gAdvSubCur, &gAdvSubScroll);
    }

    BOOLEAN plus  = (k->UnicodeChar == L'+' || k->UnicodeChar == L'=' || k->ScanCode == SCAN_F6);
    BOOLEAN minus = (k->UnicodeChar == L'-' || k->ScanCode == SCAN_F5);
    BOOLEAN enter = (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n' || k->UnicodeChar == L' ');

    if (gAdvSub == ADV_SUB_CPU) {
        hw_refresh_cpu_msrs();
        UINTN cpu_q_idx[48];
        UINTN cpu_q_cnt = get_cpu_hii_questions(cpu_q_idx, 48);
        UINTN fixed_cnt = gHw.cpu_msr.is_amd ? 7 : 12;
        UINTN total_opts = fixed_cnt + cpu_q_cnt;
        UINTN vis = (gUiRows > 9) ? (gUiRows - 9) : 8;

        if (k->ScanCode == SCAN_UP) { gAdvSubCur = (gAdvSubCur > 0) ? (gAdvSubCur - 1) : (total_opts - 1); return TRUE; }
        if (k->ScanCode == SCAN_DOWN) { gAdvSubCur = (gAdvSubCur + 1) % total_opts; return TRUE; }
        if (k->ScanCode == SCAN_PAGE_UP) { gAdvSubCur = (gAdvSubCur > vis) ? (gAdvSubCur - vis) : 0; return TRUE; }
        if (k->ScanCode == SCAN_PAGE_DOWN) { gAdvSubCur = (gAdvSubCur + vis < total_opts) ? (gAdvSubCur + vis) : (total_opts - 1); return TRUE; }

        if (!(plus || minus || enter)) return FALSE;

        if (gAdvSubCur >= fixed_cnt) {
            edit_hii_question_interactive(cpu_q_idx[gAdvSubCur - fixed_cnt], plus, minus);
            return TRUE;
        }

        if (gHw.cpu_msr.is_amd) {
            if (gAdvSubCur == 0) {
                /* AMD Hardware P0 Frequency Overclock / Underclock (MHz) */
                if (!gHw.cpu_msr.amd_pstate_valid) {
                    INTN hq = hw_hii_find_question_icase("CPU Clock", NULL);
                    if (hq < 0) hq = hw_hii_find_question_icase("Core Ratio", NULL);
                    if (hq >= 0) edit_hii_question_interactive((UINTN)hq, plus, minus);
                    else ui_message_modal("AMD P-State MSR Restricted",
                                          "MSR 0xC0010064 is restricted by hypervisor or platform.", TRUE);
                } else {
                    const UINT32 f_mhz[9] = { 2200, 2800, 3200, 3400, 3800, 4200, 4500, 4700, 5000 };
                    const CHAR8 *f_opts[10] = {
                        "2200 MHz (Eco / Low Power)",
                        "2800 MHz (Quiet Efficiency)",
                        "3200 MHz",
                        "3400 MHz (Standard Base)",
                        "3800 MHz",
                        "4200 MHz (All-Core Boost)",
                        "4500 MHz (Performance OC)",
                        "4700 MHz (High All-Core OC)",
                        "5000 MHz (Extreme OC)",
                        "Enter Custom Target Frequency in MHz..."
                    };
                    UINTN cur_i = 9;
                    for (UINTN i = 0; i < 9; i++) {
                        if (gHw.cpu_msr.amd_p0_mhz == f_mhz[i]) { cur_i = i; break; }
                    }
                    INTN p = ui_pick_option_modal("AMD All-Core Hardware P0 Frequency (MSR 0xC0010064)",
                                                  f_opts, 10, cur_i, cur_i);
                    if (p >= 0 && p < 9) {
                        if (!hw_amd_set_p0_freq_mhz(f_mhz[p])) {
                            ui_message_modal("P0 Frequency Locked", "CPU rejected MSR 0xC0010064 update.", TRUE);
                        }
                    } else if (p == 9) {
                        CHAR8 init_s[16], out_s[16];
                        snprintf_ascii(init_s, sizeof(init_s), "%u", gHw.cpu_msr.amd_p0_mhz);
                        if (ui_input_modal("Custom AMD P0 Frequency",
                                           "Enter target all-core MHz (1200 .. 6000):",
                                           init_s, out_s, sizeof(out_s), FALSE)) {
                            UINT64 mhz = 0;
                            if (parse_dec_u64(out_s, &mhz) && mhz >= 1200 && mhz <= 6000) {
                                if (!hw_amd_set_p0_freq_mhz((UINT32)mhz)) {
                                    ui_message_modal("P0 Frequency Locked", "CPU rejected MSR 0xC0010064 update.", TRUE);
                                }
                            }
                        }
                    }
                }
            } else if (gAdvSubCur == 1) {
                /* AMD Core Performance Boost (CPB - MSR 0xC0010015[25]) */
                UINT8 v = gHw.cpu_msr.amd_hwcr_valid ? (!gHw.cpu_msr.amd_cpb_disabled ? 1 : 0) : gSetup.cfg.cpu_turbo;
                if (pick_u8_option("AMD Core Performance Boost / Turbo (MSR 0xC0010015[25])",
                                   kDisEnOpts, 2, &v, plus, minus)) {
                    gSetup.cfg.cpu_turbo = v;
                    gSetup.cfg_dirty = TRUE;
                    if (gHw.cpu_msr.amd_hwcr_valid) {
                        /* Bit 25 = CpbDis (0=Boost Enabled, 1=Boost Disabled) */
                        hw_write_cpu_msr_bit(0xC0010015U, 25, v == 0);
                    }
                }
            } else if (gAdvSubCur == 2) {
                /* Active Hardware P-State */
                if (!gHw.cpu_msr.amd_pstate_valid) {
                    ui_message_modal("P-State Control Unavailable", "MSR 0xC0010062 not exposed.", TRUE);
                } else {
                    const CHAR8 *ps_opts[3] = {
                        "P0 (Maximum Performance / OC Clock)",
                        "P1 (Balanced Intermediate Clock)",
                        "P2 (Minimum Power / Efficiency Clock)"
                    };
                    UINTN cnt = (gHw.cpu_msr.amd_max_pstate >= 2) ? 3 : (gHw.cpu_msr.amd_max_pstate + 1U);
                    UINTN cur = (gHw.cpu_msr.amd_cur_pstate < cnt) ? gHw.cpu_msr.amd_cur_pstate : 0;
                    INTN p = ui_pick_option_modal("AMD Active Hardware P-State (All Cores)", ps_opts, cnt, cur, cur);
                    if (p >= 0) hw_amd_set_active_pstate((UINT8)p);
                }
            } else if (gAdvSubCur == 3) {
                /* AMD Core Voltage SVI2 VID */
                if (!gHw.cpu_msr.amd_pstate_valid) {
                    ui_message_modal("SVI2 Voltage MSR Restricted", "MSR 0xC0010064 not exposed.", TRUE);
                } else {
                    const UINT32 mv_p[7] = { 950, 1025, 1100, 1175, 1250, 1325, 1375 };
                    const CHAR8 *v_opts[8] = {
                        "950 mV  (Undervolt / Eco)",
                        "1025 mV (Undervolt)",
                        "1100 mV (Balanced Stock)",
                        "1175 mV",
                        "1250 mV (Boost Stock)",
                        "1325 mV (All-Core OC)",
                        "1375 mV (High OC)",
                        "Enter Custom Core Voltage in mV (700 .. 1450)..."
                    };
                    INTN p = ui_pick_option_modal("AMD SVI2 P0 Core Voltage (MSR 0xC0010064)", v_opts, 8, 2, 2);
                    UINT32 target_mv = 0;
                    if (p >= 0 && p < 7) {
                        target_mv = mv_p[p];
                    } else if (p == 7) {
                        CHAR8 init_s[16], out_s[16];
                        snprintf_ascii(init_s, sizeof(init_s), "%u", gHw.cpu_msr.amd_p0_mv);
                        if (ui_input_modal("Custom AMD P0 Core Voltage",
                                           "Enter SVI2 voltage in mV (700 .. 1450):",
                                           init_s, out_s, sizeof(out_s), FALSE)) {
                            UINT64 v64 = 0;
                            if (parse_dec_u64(out_s, &v64) && v64 >= 700 && v64 <= 1450) {
                                target_mv = (UINT32)v64;
                            }
                        }
                    }
                    if (target_mv >= 700 && target_mv <= 1450) {
                        UINT32 vid = (155000U - target_mv * 100U) / 625U;
                        if (vid <= 0xF8U) {
                            if (!hw_amd_set_p0_vid((UINT8)vid)) {
                                ui_message_modal("VID Locked", "CPU rejected SVI2 VID update in MSR 0xC0010064.", TRUE);
                            }
                        }
                    }
                }
            } else if (gAdvSubCur == 4) {
                /* AMD-V SVM */
                UINT8 v = gHw.cpu_msr.amd_vmcr_valid ? (!gHw.cpu_msr.amd_svm_disabled ? 1 : 0) : gSetup.cfg.cpu_virtualization;
                if (pick_u8_option("AMD-V (SVM) Virtualization (MSR 0xC0010114)", kDisEnOpts, 2, &v, plus, minus)) {
                    gSetup.cfg.cpu_virtualization = v;
                    gSetup.cfg_dirty = TRUE;
                    if (gHw.cpu_msr.amd_vmcr_valid && !gHw.cpu_msr.amd_svm_locked) {
                        hw_write_cpu_msr_bit(0xC0010114U, 4, v == 0);
                    } else {
                        INTN hq = hw_hii_find_question_icase("SVM", NULL);
                        if (hq >= 0) edit_hii_question_interactive((UINTN)hq, FALSE, FALSE);
                        else ui_message_modal("SVMLock Active",
                                              "MSR 0xC0010114 SVMLock=1 is set for this boot; staged in config.", FALSE);
                    }
                }
            } else if (gAdvSubCur == 5) {
                edit_active_threads_interactive();
            } else if (gAdvSubCur == 6) {
                const CHAR8 *cst_opts[3] = { "Disabled (C0/C1 Only)", "Auto (Firmware Default)", "Enabled (Deep C-States)" };
                if (pick_u8_option("CPU C-States Power Saving", cst_opts, 3, &gSetup.cfg.cpu_cstates, plus, minus)) {
                    gSetup.cfg_dirty = TRUE;
                }
            }
            return TRUE;
        }

        /* Intel / Generic CPU Key Handlers (0..10) */
        if (gAdvSubCur == 0) {
            if (!gHw.cpu_msr.perf_valid) {
                INTN hq = hw_hii_find_question_icase("CPU Ratio", NULL);
                if (hq < 0) hq = hw_hii_find_question_icase("Core Ratio", NULL);
                if (hq >= 0) edit_hii_question_interactive((UINTN)hq, plus, minus);
                else ui_message_modal("MSR 0x199 Unavailable", "IA32_PERF_CTL is not exposed on this CPU/VM.", TRUE);
            } else {
                CHAR8 init_s[16], out_s[16], pr[80];
                snprintf_ascii(init_s, sizeof(init_s), "%u", gHw.cpu_msr.intel_target_ratio);
                snprintf_ascii(pr, sizeof(pr), "Enter multiplier x100MHz (Min:%u Base:%u Turbo:%u):",
                               gHw.cpu_msr.intel_min_ratio ? gHw.cpu_msr.intel_min_ratio : 8,
                               gHw.cpu_msr.intel_base_ratio,
                               gHw.cpu_msr.intel_turbo_1c ? gHw.cpu_msr.intel_turbo_1c : 60);
                if (ui_input_modal("Set Intel All-Core Target Multiplier (MSR 0x199)",
                                   pr, init_s, out_s, sizeof(out_s), FALSE)) {
                    UINT64 r = 0;
                    if (parse_dec_u64(out_s, &r) && r >= 8 && r <= 85) {
                        if (!hw_intel_set_target_ratio((UINT8)r)) {
                            ui_message_modal("Multiplier Rejected", "CPU rejected IA32_PERF_CTL ratio request.", TRUE);
                        }
                    }
                }
            }
        } else if (gAdvSubCur == 1) {
            if (!gHw.cpu_msr.turbo_limit_valid) {
                ui_message_modal("MSR 0x1AD Unavailable", "MSR_TURBO_RATIO_LIMIT is not exposed on this CPU/VM.", TRUE);
            } else {
                CHAR8 init_s[16], out_s[16];
                snprintf_ascii(init_s, sizeof(init_s), "%u", gHw.cpu_msr.intel_turbo_allc);
                if (ui_input_modal("Set Intel All-Core Turbo Ratio Overclock (MSR 0x1AD)",
                                   "Enter all-core Turbo multiplier (e.g. 42 = 4200 MHz):",
                                   init_s, out_s, sizeof(out_s), FALSE)) {
                    UINT64 r = 0;
                    if (parse_dec_u64(out_s, &r) && r >= 8 && r <= 90) {
                        if (!hw_intel_set_turbo_allcore_ratio((UINT8)r)) {
                            ui_message_modal("Turbo Ratio Locked",
                                             "MSR 0x1AD is locked (OC_LOCK=1 or non-K SKU). Try Unlock OC / HII below!",
                                             TRUE);
                        }
                    }
                }
            }
        } else if (gAdvSubCur == 2) {
            /* Unlock CFG Lock (MSR 0xE2[15] + HII NVRAM Auto-Unlock!) */
            INTN hii_cfg_q = hw_hii_find_question_icase("CFG Lock", NULL);
            if (gHw.cpu_msr.cst_cfg_valid && !gHw.cpu_msr.cfg_locked) {
                if (hii_cfg_q >= 0) edit_hii_question_interactive((UINTN)hii_cfg_q, plus, minus);
                else ui_message_modal("CFG Lock Already Unlocked!",
                                      "MSR 0xE2 Bit 15 is 0 (UNLOCKED) across CPU cores!", FALSE);
            } else if (gHw.cpu_msr.cst_cfg_valid && hw_intel_unlock_cfg_lock_msr()) {
                ui_message_modal("CFG Lock Unlocked", "Cleared MSR 0xE2 Bit 15 across all CPU cores!", FALSE);
            } else if (hii_cfg_q >= 0) {
                if (ui_confirm_modal("Unlock CFG Lock in Motherboard NVRAM?",
                                     "MSR 0xE2 Bit 15 is write-once locked for this boot, BUT Oh my EFI! found \"CFG Lock\" in your motherboard HII database!\n\nOpen CFG Lock NVRAM option now (set to Disabled & reboot to unlock)?",
                                     TRUE)) {
                    edit_hii_question_interactive((UINTN)hii_cfg_q, FALSE, FALSE);
                }
            } else {
                ui_message_modal("CFG Lock Status",
                                 gHw.cpu_msr.cst_cfg_valid
                                     ? "MSR 0xE2 Bit 15 is hardware write-once locked for this boot.\nUse F12 Dump -> HII_Decoded_Options.txt to check VarStore offsets."
                                     : "MSR 0xE2 (PMG_CST_CONFIG_CONTROL) is not exposed on this CPU/VM.",
                                 TRUE);
            }
        } else if (gAdvSubCur == 3) {
            /* Unlock Overclocking Lock / Flex Ratio (MSR 0x194 + HII Auto-Unlock) */
            INTN hii_oc_q = hw_hii_find_question_icase("Overclock", "Lock");
            if (hii_oc_q < 0) hii_oc_q = hw_hii_find_question_icase("OC Lock", NULL);

            if (gHw.cpu_msr.flex_oc_valid && !gHw.cpu_msr.oc_locked) {
                CHAR8 init_s[16], out_s[16];
                snprintf_ascii(init_s, sizeof(init_s), "%u", gHw.cpu_msr.flex_ratio);
                if (ui_input_modal("Configure MSR 0x194 Flex Ratio (OC Unlocked)",
                                   "Enter Flex Ratio multiplier (0 to disable Flex override):",
                                   init_s, out_s, sizeof(out_s), FALSE)) {
                    UINT64 r = 0;
                    if (parse_dec_u64(out_s, &r) && r <= 80) {
                        hw_intel_set_flex_ratio((UINT8)r, r > 0);
                    }
                }
            } else if (hii_oc_q >= 0) {
                if (ui_confirm_modal("Unlock Overclocking Lock in NVRAM?",
                                     "Found Overclocking Lock in motherboard HII IFR!\nOpen NVRAM option now (set to Disabled & reboot)?",
                                     TRUE)) {
                    edit_hii_question_interactive((UINTN)hii_oc_q, FALSE, FALSE);
                }
            } else {
                ui_message_modal("Overclocking Lock (MSR 0x194)",
                                 gHw.cpu_msr.flex_oc_valid
                                     ? "MSR 0x194 Bit 20 (OC_LOCK) is write-once locked by BIOS for this boot.\nCheck HII / IFR Settings Browser for Overclocking / XTU options!"
                                     : "MSR 0x194 (MSR_FLEX_RATIO) is not exposed on this CPU/VM.",
                                 TRUE);
            }
        } else if (gAdvSubCur == 4) {
            /* Intel RAPL Package Power Limits PL1 / PL2 */
            if (!gHw.cpu_msr.pkg_pwr_valid || gHw.cpu_msr.pkg_pwr_locked) {
                ui_message_modal("RAPL Power Limit (MSR 0x610)",
                                 gHw.cpu_msr.pkg_pwr_locked
                                     ? "MSR 0x610 Bit 63 (PKG_PWR_LIMIT_LOCK) is set by BIOS."
                                     : "MSR 0x610 RAPL Package Power Limit not exposed on this CPU/VM.",
                                 TRUE);
            } else {
                const UINT16 p1_p[5] = { 35, 65, 95, 125, 253 };
                const UINT16 p2_p[5] = { 45, 90, 125, 180, 253 };
                const CHAR8 *p_opts[6] = {
                    "PL1 = 35W  / PL2 = 45W   (Cool Laptop / Eco)",
                    "PL1 = 65W  / PL2 = 90W   (Standard Desktop)",
                    "PL1 = 95W  / PL2 = 125W  (Performance)",
                    "PL1 = 125W / PL2 = 180W  (K-SKU Unlocked)",
                    "PL1 = 253W / PL2 = 253W  (Remove Power Limits!)",
                    "Enter Custom PL1 / PL2 Watts..."
                };
                INTN p = ui_pick_option_modal("Intel RAPL Package Power Limits (MSR 0x610)", p_opts, 6, 3, 3);
                if (p >= 0 && p < 5) {
                    hw_intel_set_pkg_power_limits_watts(p1_p[p], p2_p[p]);
                } else if (p == 5) {
                    CHAR8 s1[16], s2[16], o1[16], o2[16];
                    snprintf_ascii(s1, sizeof(s1), "%u", gHw.cpu_msr.pl1_watts);
                    snprintf_ascii(s2, sizeof(s2), "%u", gHw.cpu_msr.pl2_watts);
                    if (ui_input_modal("Custom Sustained PL1 (Watts)", "Enter PL1 Watts (10 .. 400):", s1, o1, sizeof(o1), FALSE) &&
                        ui_input_modal("Custom Boost PL2 (Watts)", "Enter PL2 Watts (10 .. 400):", s2, o2, sizeof(o2), FALSE)) {
                        UINT64 w1 = 0, w2 = 0;
                        if (parse_dec_u64(o1, &w1) && parse_dec_u64(o2, &w2) && w1 >= 5 && w2 >= 5) {
                            hw_intel_set_pkg_power_limits_watts((UINT16)w1, (UINT16)w2);
                        }
                    }
                }
            }
        } else if (gAdvSubCur == 5) {
            if (!gHw.cpu_msr.misc_valid) {
                ui_message_modal("MSR 0x1A0 Unavailable", "IA32_MISC_ENABLE not exposed on this CPU/VM.", TRUE);
            } else {
                UINT8 v = gHw.cpu_msr.eist_enabled ? 1 : 0;
                if (pick_u8_option("Intel SpeedStep (EIST - MSR 0x1A0[16])", kDisEnOpts, 2, &v, plus, minus)) {
                    hw_write_cpu_msr_bit(0x1A0U, 16, v != 0);
                }
            }
        } else if (gAdvSubCur == 6) {
            UINT8 v = gHw.cpu_msr.misc_valid ? (!gHw.cpu_msr.turbo_disabled ? 1 : 0) : gSetup.cfg.cpu_turbo;
            if (pick_u8_option("CPU Turbo Boost Mode (MSR 0x1A0[38])", kDisEnOpts, 2, &v, plus, minus)) {
                gSetup.cfg.cpu_turbo = v;
                gSetup.cfg_dirty = TRUE;
                if (gHw.cpu_msr.misc_valid) hw_write_cpu_msr_bit(0x1A0U, 38, v == 0);
            }
        } else if (gAdvSubCur == 7) {
            if (!gHw.cpu_msr.power_ctl_valid) {
                ui_message_modal("MSR 0x1FC Unavailable", "MSR_POWER_CTL (0x1FC) not exposed on this CPU/VM.", TRUE);
            } else {
                const CHAR8 *bd_opts[2] = {
                    "Disabled (Bypass External BD PROCHOT Throttle!)",
                    "Enabled (Allow Bi-Directional PROCHOT)"
                };
                UINT8 v = gHw.cpu_msr.bd_prochot ? 1 : 0;
                if (pick_u8_option("BD PROCHOT Throttle (MSR 0x1FC[0])", bd_opts, 2, &v, plus, minus)) {
                    hw_write_cpu_msr_bit(0x1FCU, 0, v != 0);
                }
            }
        } else if (gAdvSubCur == 8) {
            if (!gHw.cpu_msr.power_ctl_valid) {
                ui_message_modal("MSR 0x1FC Unavailable", "MSR_POWER_CTL (0x1FC) not exposed on this CPU/VM.", TRUE);
            } else {
                UINT8 v = gHw.cpu_msr.c1e_enable ? 1 : 0;
                if (pick_u8_option("C1E Enhanced Halt (MSR 0x1FC[1])", kDisEnOpts, 2, &v, plus, minus)) {
                    hw_write_cpu_msr_bit(0x1FCU, 1, v != 0);
                }
            }
        } else if (gAdvSubCur == 9) {
            UINT8 v = gHw.cpu_msr.feat_ctl_valid ? (gHw.cpu_msr.vmx_outside_smx ? 1 : 0) : gSetup.cfg.cpu_virtualization;
            if (pick_u8_option("Hardware Virtualization (VT-x - MSR 0x3A)", kDisEnOpts, 2, &v, plus, minus)) {
                gSetup.cfg.cpu_virtualization = v;
                gSetup.cfg_dirty = TRUE;
                if (gHw.cpu_msr.feat_ctl_valid && !gHw.cpu_msr.vmx_locked) {
                    hw_write_cpu_msr_bit(0x3AU, 2, v != 0);
                } else if (gHw.cpu_msr.feat_ctl_valid && gHw.cpu_msr.vmx_locked) {
                    INTN hq = hw_hii_find_question_icase("Virtualization", NULL);
                    if (hq < 0) hq = hw_hii_find_question_icase("VMX", NULL);
                    if (hq >= 0) edit_hii_question_interactive((UINTN)hq, FALSE, FALSE);
                    else ui_message_modal("MSR 0x3A Locked", "IA32_FEATURE_CONTROL Bit 0 is locked for this boot; staged in config.", FALSE);
                }
            }
        } else if (gAdvSubCur == 10) {
            edit_active_threads_interactive();
        } else if (gAdvSubCur == 11) {
            unlock_edit_fivr_core_cache_sync_interactive();
        }
        return TRUE;
    } else if (gAdvSub == ADV_SUB_GPU_VRAM) {
        UINTN gpu_q_idx[48];
        UINTN gpu_q_cnt = get_gpu_hii_questions(gpu_q_idx, 48);
        UINTN mac_extra = gHw.is_apple_mac ? 1 : 0;
        UINTN fixed_cnt = mac_extra + 5;
        UINTN total_items = fixed_cnt + gpu_q_cnt;
        UINTN vis = (gUiRows > 8) ? (gUiRows - 8) : 8;

        if (k->ScanCode == SCAN_UP) { gAdvSubCur = (gAdvSubCur > 0) ? (gAdvSubCur - 1) : (total_items - 1); return TRUE; }
        if (k->ScanCode == SCAN_DOWN) { gAdvSubCur = (gAdvSubCur + 1) % total_items; return TRUE; }
        if (k->ScanCode == SCAN_PAGE_UP) { gAdvSubCur = (gAdvSubCur > vis) ? (gAdvSubCur - vis) : 0; return TRUE; }
        if (k->ScanCode == SCAN_PAGE_DOWN) { gAdvSubCur = (gAdvSubCur + vis < total_items) ? (gAdvSubCur + vis) : (total_items - 1); return TRUE; }

        if (plus || minus || enter) {
            if (gHw.is_apple_mac && gAdvSubCur == 0) {
                const CHAR8 *mgpu_opts[3] = {
                    "Auto / Default (Remove gpu-power-prefs)",
                    "Force Integrated Intel iGPU Only (01 00 00 00)",
                    "Dynamic / Discrete GPU Preferred (00 00 00 00)"
                };
                UINT8 m = gSetup.apple_gpu_mode;
                if (pick_u8_option("Apple Dual-GPU Power Prefs (FA4CE28D..)", mgpu_opts, 3, &m, plus, minus)) {
                    gSetup.apple_gpu_mode  = m;
                    gSetup.apple_gpu_dirty = TRUE;
                }
                return TRUE;
            }

            UINTN rel = gAdvSubCur - mac_extra;
            if (rel == 0) {
                INTN hq_pd = find_motherboard_hii_q("Primary Display", "Initial Display Output");
                if (hq_pd >= 0) {
                    edit_hii_question_interactive((UINTN)hq_pd, plus, minus);
                } else {
                    const CHAR8 *pdisp_opts[3] = {
                        "Auto (Firmware Default)",
                        "Integrated Graphics (iGPU / IGFX)",
                        "Discrete PCIe Graphics (dGPU / PEG)"
                    };
                    if (pick_u8_option("Primary Display Adapter", pdisp_opts, 3, &gSetup.cfg.primary_display, plus, minus)) {
                        gSetup.cfg_dirty = TRUE;
                    }
                }
            } else if (rel == 1) {
                INTN rebar_gpu = find_first_rebar_gpu_pci_idx();
                if (rebar_gpu >= 0) {
                    edit_rebar_size_interactive((UINTN)rebar_gpu);
                } else {
                    INTN hq = hw_hii_find_question_icase("Resizable BAR", NULL);
                    if (hq < 0) hq = hw_hii_find_question_icase("Re-Size BAR", NULL);
                    if (hq >= 0) edit_hii_question_interactive((UINTN)hq, plus, minus);
                    else ui_message_modal("Resizable BAR Unavailable",
                                          "Current GPU does not advertise PCIe Extended Cap 0x0015 (ReBAR) or Above 4G / ECAM is disabled.",
                                          TRUE);
                }
            } else if (rel == 2) {
                if (pick_u8_option("Above 4G MMIO / Large BAR Decoding",
                                   kDisEnOpts, 2, &gSetup.cfg.above_4g_decode, plus, minus)) {
                    gSetup.cfg_dirty = TRUE;
                    INTN hq = hw_hii_find_question_icase("Above 4G", NULL);
                    if (hq >= 0) {
                        CHAR8 err[64];
                        hw_hii_write_question_val((UINTN)hq, gSetup.cfg.above_4g_decode ? 1 : 0, err, sizeof(err));
                    }
                }
            } else if (rel == 3) {
                const CHAR8 *dvmt_opts[6] = {
                    "32 MB Pre-Allocated",
                    "64 MB Pre-Allocated",
                    "96 MB Pre-Allocated",
                    "128 MB Pre-Allocated",
                    "256 MB Pre-Allocated",
                    "512 MB Pre-Allocated"
                };
                const UINT32 dvmt_mb[6] = { 32, 64, 96, 128, 256, 512 };
                UINT8 cur_d = gSetup.cfg.igd_dvmt_prealloc % 6;
                if (gHw.igd_ggc_present) {
                    for (UINT8 i = 0; i < 6; i++) {
                        if (gHw.igd_stolen_mb == dvmt_mb[i]) { cur_d = i; break; }
                    }
                }
                if (gHw.igd_ggc_present && !gHw.igd_ggc_locked) {
                    if (pick_u8_option("iGPU Stolen VRAM Size (Live GMCH GGC)", dvmt_opts, 6, &cur_d, plus, minus)) {
                        gSetup.cfg.igd_dvmt_prealloc = cur_d;
                        gSetup.cfg_dirty = TRUE;
                        hw_igd_set_stolen_vram_mb(dvmt_mb[cur_d]);
                    }
                } else {
                    INTN hq = hw_hii_find_question_icase("DVMT", NULL);
                    if (hq < 0) hq = hw_hii_find_question_icase("UMA Frame Buffer", NULL);
                    if (hq < 0) hq = hw_hii_find_question_icase("UMA", "Size");
                    if (hq >= 0) {
                        edit_hii_question_interactive((UINTN)hq, plus, minus);
                    } else if (pick_u8_option("iGPU UMA / Pre-Allocated VRAM", dvmt_opts, 6, &cur_d, plus, minus)) {
                        gSetup.cfg.igd_dvmt_prealloc = cur_d;
                        gSetup.cfg_dirty = TRUE;
                        if (gHw.igd_ggc_present && gHw.igd_ggc_locked) {
                            ui_message_modal("GMCH GGC Locked by MRC",
                                "00:00.0 GGC (0x50) has GGCLCK=1 after RAM init; staged in Setup Config.",
                                FALSE);
                        }
                    }
                }
            } else if (rel == 4) {
                if (gHw.gop_mode_count > 0) {
                    const CHAR8 *mopts[HW_MAX_GOP_MODES];
                    CHAR8 mbufs[HW_MAX_GOP_MODES][36];
                    UINTN cur_i = 0;
                    for (UINTN i = 0; i < gHw.gop_mode_count; i++) {
                        snprintf_ascii(mbufs[i], sizeof(mbufs[i]), "Mode %u: %ux%u Pixels",
                                       gHw.gop_modes[i].mode_num, gHw.gop_modes[i].width, gHw.gop_modes[i].height);
                        mopts[i] = mbufs[i];
                        if (gHw.gop_modes[i].mode_num == gHw.gop_cur_mode) cur_i = i;
                    }
                    UINTN init_s = plus ? ((cur_i + 1) % gHw.gop_mode_count) :
                                   (minus ? ((cur_i + gHw.gop_mode_count - 1) % gHw.gop_mode_count) : cur_i);
                    INTN pick = ui_pick_option_modal("UEFI GOP Video Mode", mopts, gHw.gop_mode_count, cur_i, init_s);
                    if (pick >= 0 && (UINTN)pick < gHw.gop_mode_count) {
                        hw_set_gop_mode(gHw.gop_modes[pick].mode_num);
                        ui_init();
                    }
                }
            } else if ((rel - 5) < gpu_q_cnt) {
                edit_hii_question_interactive(gpu_q_idx[rel - 5], plus, minus);
            }
            return TRUE;
        }
    } else if (gAdvSub == ADV_SUB_PCIE) {
        UINTN total = 1 + gHw.pci_count;
        UINTN vis = (gUiRows > 7) ? (gUiRows - 7) : 10;
        if (k->ScanCode == SCAN_UP) { gAdvSubCur = (gAdvSubCur > 0) ? (gAdvSubCur - 1) : (total - 1); return TRUE; }
        if (k->ScanCode == SCAN_DOWN) { gAdvSubCur = (gAdvSubCur + 1) % total; return TRUE; }
        if (k->ScanCode == SCAN_PAGE_UP) { gAdvSubCur = (gAdvSubCur > vis) ? (gAdvSubCur - vis) : 0; return TRUE; }
        if (k->ScanCode == SCAN_PAGE_DOWN) { gAdvSubCur = (gAdvSubCur + vis < total) ? (gAdvSubCur + vis) : (total - 1); return TRUE; }

        if (gAdvSubCur == 0 && (enter || plus || minus)) {
            const CHAR8 *aspm_opts[5] = {
                "Disabled (Force L0 Performance on All Links)",
                "L0s Entry Only",
                "L1 Entry Only",
                "L0s + L1 Maximum Power Saving",
                "OS / Firmware Default"
            };
            if (pick_u8_option("Global PCIe ASPM Power Policy", aspm_opts, 5, &gSetup.cfg.pcie_aspm_policy, plus, minus)) {
                gSetup.cfg_dirty = TRUE;
                if (gSetup.cfg.pcie_aspm_policy <= 3) {
                    for (UINTN i = 0; i < gHw.pci_count; i++) {
                        if (gHw.pci_devs[i].pcie_cap_off != 0) {
                            hw_pci_set_aspm(i, gSetup.cfg.pcie_aspm_policy);
                        }
                    }
                }
            }
            return TRUE;
        } else if (gAdvSubCur >= 1 && (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n')) {
            open_pcie_device_controller(gAdvSubCur - 1);
            return TRUE;
        }
    } else if (gAdvSub == ADV_SUB_MEMORY) {
        UINTN mem_q_idx[24];
        UINTN mem_q_cnt = get_mem_hii_questions(mem_q_idx, 24);
        UINTN total_opts = 1 + mem_q_cnt;
        if (k->ScanCode == SCAN_UP) { gAdvSubCur = (gAdvSubCur > 0) ? (gAdvSubCur - 1) : (total_opts - 1); return TRUE; }
        if (k->ScanCode == SCAN_DOWN) { gAdvSubCur = (gAdvSubCur + 1) % total_opts; return TRUE; }

        if (plus || minus || enter) {
            if (gAdvSubCur == 0) {
                INTN hq_s3 = find_motherboard_hii_q("ACPI Sleep State", "Suspend");
                if (hq_s3 >= 0) {
                    edit_hii_question_interactive((UINTN)hq_s3, plus, minus);
                } else {
                    const CHAR8 *s3_opts[2] = { "Suspend Disabled", "S3 (Suspend to RAM)" };
                    if (pick_u8_option("ACPI Sleep State", s3_opts, 2, &gSetup.cfg.acpi_s3_sleep, plus, minus)) {
                        gSetup.cfg_dirty = TRUE;
                    }
                }
            } else if ((gAdvSubCur - 1) < mem_q_cnt) {
                edit_hii_question_interactive(mem_q_idx[gAdvSubCur - 1], plus, minus);
            }
            return TRUE;
        }
    } else if (gAdvSub == ADV_SUB_STORAGE) {
        if (k->ScanCode == SCAN_UP || k->ScanCode == SCAN_DOWN) {
            gAdvSubCur = (gAdvSubCur + 1) % 2;
            return TRUE;
        }
        if (plus || minus || enter) {
            if (gAdvSubCur == 0) {
                INTN hq_sata = find_motherboard_hii_q("SATA Mode", "SATA Controller");
                if (hq_sata >= 0) {
                    edit_hii_question_interactive((UINTN)hq_sata, plus, minus);
                } else {
                    const CHAR8 *smode[3] = { "IDE Compatibility", "AHCI Mode", "RAID Mode" };
                    if (pick_u8_option("SATA Controller Mode", smode, 3, &gSetup.cfg.sata_mode, plus, minus))
                        gSetup.cfg_dirty = TRUE;
                }
            } else {
                INTN hq_usb = find_motherboard_hii_q("Legacy USB", "XHCI Hand-off");
                if (hq_usb >= 0) {
                    edit_hii_question_interactive((UINTN)hq_usb, plus, minus);
                } else {
                    const CHAR8 *uleg[3] = { "Disabled", "Enabled", "Auto" };
                    if (pick_u8_option("Legacy USB Support", uleg, 3, &gSetup.cfg.usb_legacy, plus, minus))
                        gSetup.cfg_dirty = TRUE;
                }
            }
            return TRUE;
        }
    } else if (gAdvSub == ADV_SUB_ACPI && gHw.acpi_count > 0) {
        if (k->ScanCode == SCAN_UP) { gAdvSubCur = (gAdvSubCur > 0) ? (gAdvSubCur - 1) : (gHw.acpi_count - 1); return TRUE; }
        if (k->ScanCode == SCAN_DOWN) { gAdvSubCur = (gAdvSubCur + 1) % gHw.acpi_count; return TRUE; }
        if (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') {
            const CHAR8 *opts[2] = {
                "Inspect / Live-Patch ACPI Table in Memory Hex Editor",
                "Recalculate & Fix ACPI Header Checksum"
            };
            INTN c = ui_select_modal(gHw.acpi_tables[gAdvSubCur].signature, opts, 2, 0);
            if (c == 0) {
                debug_open_hex_editor(gHw.acpi_tables[gAdvSubCur].phys_addr, gHw.acpi_tables[gAdvSubCur].signature);
                hw_refresh_acpi_status();
            } else if (c == 1) {
                if (hw_acpi_fix_checksum(gAdvSubCur))
                    ui_message_modal("ACPI Checksum", "Checksum recalculated and verified OK!", FALSE);
                else
                    ui_message_modal("ACPI Checksum", "Could not update checksum (Read-Only or FACS).", TRUE);
            }
            return TRUE;
        }
    } else if (gAdvSub == ADV_SUB_APPLE) {
        if (k->ScanCode == SCAN_UP) { gAdvSubCur = (gAdvSubCur > 0) ? (gAdvSubCur - 1) : 3; return TRUE; }
        if (k->ScanCode == SCAN_DOWN) { gAdvSubCur = (gAdvSubCur + 1) % 4; return TRUE; }
        if (gAdvSubCur == 0 && (enter || plus || minus)) {
            const CHAR8 *bopts[6] = {
                "Normal Boot (Clear boot-args)",
                "Verbose Mode (-v)",
                "Verbose + KeepSyms (-v keepsyms=1)",
                "Safe Mode (-x)",
                "Single-User Mode (-s)",
                "Enter Custom boot-args String..."
            };
            UINTN cur_b = 0;
            if (str_cmp(gSetup.apple_boot_args, "-v") == 0) cur_b = 1;
            else if (str_cmp(gSetup.apple_boot_args, "-v keepsyms=1") == 0) cur_b = 2;
            else if (str_cmp(gSetup.apple_boot_args, "-x") == 0) cur_b = 3;
            else if (str_cmp(gSetup.apple_boot_args, "-s") == 0) cur_b = 4;
            else if (gSetup.apple_boot_args[0]) cur_b = 5;

            INTN c = ui_pick_option_modal("macOS / Apple boot-args", bopts, 6, cur_b, cur_b);
            if (c == 0) { gSetup.apple_boot_args[0] = '\0'; gSetup.apple_boot_args_dirty = TRUE; }
            else if (c == 1) { str_cpy(gSetup.apple_boot_args, "-v", sizeof(gSetup.apple_boot_args)); gSetup.apple_boot_args_dirty = TRUE; }
            else if (c == 2) { str_cpy(gSetup.apple_boot_args, "-v keepsyms=1", sizeof(gSetup.apple_boot_args)); gSetup.apple_boot_args_dirty = TRUE; }
            else if (c == 3) { str_cpy(gSetup.apple_boot_args, "-x", sizeof(gSetup.apple_boot_args)); gSetup.apple_boot_args_dirty = TRUE; }
            else if (c == 4) { str_cpy(gSetup.apple_boot_args, "-s", sizeof(gSetup.apple_boot_args)); gSetup.apple_boot_args_dirty = TRUE; }
            else if (c == 5) {
                CHAR8 custom[96];
                if (ui_input_modal("Custom Apple boot-args", "Enter kernel flags (e.g. -v debug=0x100):",
                                   gSetup.apple_boot_args, custom, sizeof(custom), FALSE)) {
                    str_cpy(gSetup.apple_boot_args, custom, sizeof(gSetup.apple_boot_args));
                    gSetup.apple_boot_args_dirty = TRUE;
                }
            }
            return TRUE;
        } else if (gAdvSubCur == 1 && (enter || plus || minus)) {
            const CHAR8 *sopts[3] = {
                "SIP Enabled (00 00 00 00)",
                "SIP Disabled - Standard (67 00 00 00 / LE 0x00000067)",
                "SIP Fully Disabled (FF 0F 00 00 / LE 0x00000FFF)"
            };
            UINTN cur_s = (gSetup.apple_csr_config == 0x00000067U) ? 1 :
                          (gSetup.apple_csr_config == 0x00000FFFU) ? 2 : 0;
            INTN c = ui_pick_option_modal("macOS System Integrity Protection", sopts, 3, cur_s, cur_s);
            if (c == 0) { gSetup.apple_csr_config = 0x00000000U; gSetup.apple_csr_dirty = TRUE; }
            else if (c == 1) { gSetup.apple_csr_config = 0x00000067U; gSetup.apple_csr_dirty = TRUE; }
            else if (c == 2) { gSetup.apple_csr_config = 0x00000FFFU; gSetup.apple_csr_dirty = TRUE; }
            return TRUE;
        } else if (gAdvSubCur == 2 && (enter || plus || minus)) {
            const UINT8 vols[4] = { 0x80, 0x15, 0x40, 0x7F };
            const CHAR8 *vopts[4] = {
                "Mute Startup Chime (0x80)",
                "Low Volume (0x15)",
                "Medium Volume (0x40)",
                "High Volume (0x7F)"
            };
            UINTN cur_v = (gSetup.apple_audio_vol & 0x80U) ? 0 :
                          (gSetup.apple_audio_vol <= 0x20U) ? 1 :
                          (gSetup.apple_audio_vol <= 0x55U) ? 2 : 3;
            INTN c = ui_pick_option_modal("Mac Startup Chime Volume", vopts, 4, cur_v, cur_v);
            if (c >= 0) { gSetup.apple_audio_vol = vols[c]; gSetup.apple_vol_dirty = TRUE; }
            return TRUE;
        } else if (gAdvSubCur == 3 && (enter || plus || minus)) {
            const CHAR8 *mgpu_opts[3] = {
                "Auto / Default (Remove gpu-power-prefs)",
                "Force Integrated Intel iGPU Only (01 00 00 00)",
                "Dynamic / Discrete GPU Preferred (00 00 00 00)"
            };
            UINT8 m = gSetup.apple_gpu_mode;
            if (pick_u8_option("Apple Dual-GPU Power Prefs", mgpu_opts, 3, &m, plus, minus)) {
                gSetup.apple_gpu_mode  = m;
                gSetup.apple_gpu_dirty = TRUE;
            }
            return TRUE;
        }
    } else if (gAdvSub == ADV_SUB_HII) {
        UINTN q_cnt = get_filtered_hii_questions(gHiiFilteredIdx, HW_MAX_HII_QUESTIONS);
        UINTN total_items = 3 + q_cnt + gHw.hii_varstore_count;
        UINTN vis = (gUiRows > 6) ? (gUiRows - 6) : 10;

        if (k->ScanCode == SCAN_UP) { gAdvSubCur = (gAdvSubCur > 0) ? (gAdvSubCur - 1) : (total_items - 1); return TRUE; }
        if (k->ScanCode == SCAN_DOWN) { gAdvSubCur = (gAdvSubCur + 1) % total_items; return TRUE; }
        if (k->ScanCode == SCAN_PAGE_UP) { gAdvSubCur = (gAdvSubCur > vis) ? (gAdvSubCur - vis) : 0; return TRUE; }
        if (k->ScanCode == SCAN_PAGE_DOWN) { gAdvSubCur = (gAdvSubCur + vis < total_items) ? (gAdvSubCur + vis) : (total_items - 1); return TRUE; }

        if (gAdvSubCur == 0 && (enter || plus || minus)) {
            const CHAR8 *cat_opts[6] = {
                "All Decoded Motherboard Settings",
                "Hidden / Suppressed BIOS Options Only ([H])",
                "CPU / Overclock / CFG Lock / PBO / Voltage",
                "GPU / VRAM / Resizable BAR / Above 4G / PCIe",
                "Memory / XMP / EXPO / DOCP / Frequency",
                "Security / Intel ME / AMD PSP / SPI Flash / Locks"
            };
            if (pick_u8_option("HII Category / Hidden Filter", cat_opts, 6, &gHiiCatMode, plus, minus)) {
                gAdvSubCur = 0;
                gAdvSubScroll = 0;
            }
            return TRUE;
        }
        if (k->UnicodeChar == L'/' || (gAdvSubCur == 1 && (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n'))) {
            CHAR8 fbuf[40];
            if (ui_input_modal("Filter Motherboard HII / IFR Settings",
                               "Enter keyword (e.g. Lock, Ratio, PBO, UMA, ReBAR, XMP) or blank for all:",
                               gHiiFilter, fbuf, sizeof(fbuf), FALSE)) {
                str_cpy(gHiiFilter, fbuf, sizeof(gHiiFilter));
                gAdvSubCur = 1;
                gAdvSubScroll = 0;
            }
            return TRUE;
        }
        if (gAdvSubCur == 2 && (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n')) {
            dump_run_interactive_modal();
            return TRUE;
        }
        if (gAdvSubCur >= 3 && gAdvSubCur < 3 + q_cnt && (enter || plus || minus)) {
            edit_hii_question_interactive(gHiiFilteredIdx[gAdvSubCur - 3], plus, minus);
            return TRUE;
        }
        if (gAdvSubCur >= 3 + q_cnt && (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n')) {
            const HW_HII_VARSTORE_INFO *vs = &gHw.hii_varstores[gAdvSubCur - 3 - q_cnt];
            nvram_enumerate_all();
            INTN  match   = -1;
            UINTN best_sz = 0;
            for (UINTN i = 0; i < gVarCount; i++) {
                if (str_icmp(gVarList[i].name, vs->name) == 0 && gVarList[i].data_size >= best_sz) {
                    best_sz = gVarList[i].data_size;
                    match   = (INTN)i;
                }
            }
            if (match >= 0) {
                debug_open_var_editor((UINTN)match);
            } else {
                ui_message_modal("Backing Variable Not In NVRAM",
                    "This IFR VarStore has not yet been written as a standalone NVRAM variable.", FALSE);
            }
            return TRUE;
        }
    }

    return FALSE;
}

/* =========================================================================
 * TAB 3: SECURITY & TEMPORARY DEVICE / VENDOR SPOOFER (spoof.c)
 * ========================================================================= */
static VOID draw_security_tab(VOID) {
    CHAR8 status[80];
    build_footer_status(status, sizeof(status));
    spoof_draw_security_tab(status, &gSecCur, &gSecScroll);
}

static BOOLEAN handle_security_key(const EFI_INPUT_KEY *k) {
    return spoof_handle_security_key(k, &gSecCur);
}

/* =========================================================================
 * TAB 4: BOOT (Add / Delete Boot####, Priority, Options, Chainload .EFI)
 * ========================================================================= */
#define BOOT_FIXED_OPTS 8

static VOID run_add_boot_entry_flow(VOID) {
    EFI_HANDLE chosen_fs = NULL;
    CHAR16 chosen_path_w[128];
    CHAR8 default_lbl[56];
    default_lbl[0] = '\0';

    const CHAR8 *src_opts[2] = {
        "Browse Mounted Volumes & Folders for .EFI File...",
        "Select from Auto-Discovered OS Bootloaders..."
    };
    INTN mode = (gSetup.loader_count > 0) ? ui_select_modal("Add New UEFI Boot Entry", src_opts, 2, 0) : 0;
    if (mode < 0) return;

    if (mode == 1 && gSetup.loader_count > 0) {
        const CHAR8 *lptrs[NVRAM_MAX_EFI_LOADERS];
        for (UINTN i = 0; i < gSetup.loader_count; i++) lptrs[i] = gSetup.loaders[i].label;
        INTN lp = ui_select_modal("Select Discovered .EFI Bootloader", lptrs, gSetup.loader_count, 0);
        if (lp < 0) return;
        chosen_fs = gSetup.loaders[lp].fs_handle;
        wstr_cpy(chosen_path_w, gSetup.loaders[lp].path_w, 128);
        str_cpy(default_lbl, gSetup.loaders[lp].label, sizeof(default_lbl));
    } else {
        if (!nvram_browse_efi_file_interactive(&chosen_fs, chosen_path_w, 128, default_lbl, sizeof(default_lbl))) {
            return;
        }
    }

    CHAR8 desc[56];
    if (!ui_input_modal("New Boot Entry Label",
                        "Enter Boot Menu Description (stored in Boot####):",
                        default_lbl[0] ? default_lbl : "Custom UEFI OS",
                        desc, sizeof(desc), FALSE) || !desc[0]) {
        return;
    }

    const CHAR8 *pos_opts[2] = {
        "Add at Top of BootOrder (#1 Priority)",
        "Append at End of BootOrder"
    };
    INTN pos = ui_pick_option_modal("Boot Order Placement", pos_opts, 2, 0, 0);
    if (pos < 0) return;

    UINT16 new_num = 0;
    CHAR8 err[128];
    if (nvram_add_boot_entry(chosen_fs, chosen_path_w, desc, pos == 0, &new_num, err, sizeof(err))) {
        CHAR8 ok_msg[160], path_a[80];
        wstr_to_ascii(path_a, chosen_path_w, sizeof(path_a));
        snprintf_ascii(ok_msg, sizeof(ok_msg),
                       "Created Boot%04X: \"%s\"\nPath: %s\nAdded to UEFI BootOrder in NVRAM!",
                       (UINT32)new_num, desc, path_a);
        ui_message_modal("Boot Entry Added", ok_msg, FALSE);
    } else {
        ui_message_modal("Add Boot Entry Failed", err, TRUE);
    }
}

static VOID run_delete_boot_entry_flow(INTN preselected_bi) {
    if (gSetup.boot_count == 0) {
        ui_message_modal("No Boot Entries", "There are no Boot#### entries in NVRAM to remove.", TRUE);
        return;
    }

    INTN target_bi = preselected_bi;
    if (target_bi < 0 || (UINTN)target_bi >= gSetup.boot_count) {
        CHAR8 ebufs[NVRAM_MAX_BOOT_ENTRIES][64];
        const CHAR8 *eptrs[NVRAM_MAX_BOOT_ENTRIES];
        for (UINTN i = 0; i < gSetup.boot_count; i++) {
            snprintf_ascii(ebufs[i], sizeof(ebufs[i]), "Boot%04X: %s",
                           (UINT32)gSetup.boot_entries[i].boot_num,
                           gSetup.boot_entries[i].description);
            eptrs[i] = ebufs[i];
        }
        target_bi = ui_select_modal("Select Boot#### Entry to Remove", eptrs, gSetup.boot_count, 0);
        if (target_bi < 0) return;
    }

    CHAR8 q[128];
    snprintf_ascii(q, sizeof(q), "Permanently delete Boot%04X (\"%s\") from NVRAM and BootOrder?",
                   (UINT32)gSetup.boot_entries[target_bi].boot_num,
                   gSetup.boot_entries[target_bi].description);
    if (!ui_confirm_modal("Confirm Delete Boot Entry", q, FALSE)) {
        return;
    }

    CHAR8 err[128];
    if (nvram_delete_boot_entry((UINTN)target_bi, err, sizeof(err))) {
        ui_message_modal("Boot Entry Removed", "Deleted Boot#### variable and updated BootOrder in NVRAM.", FALSE);
    } else {
        ui_message_modal("Delete Failed", err, TRUE);
    }
}

static VOID draw_boot_tab(VOID) {
    CHAR8 status[80];
    build_footer_status(status, sizeof(status));

    UINTN total_items = BOOT_FIXED_OPTS + gSetup.boot_count + gSetup.loader_count + 1;
    if (gBootCur >= total_items) gBootCur = total_items - 1;

    const CHAR8 *help_txt =
        "Add or Remove UEFI Boot#### entries (Ins / Del or menu items)!\n"
        "Use +/- on Boot#### entries to reorder Boot Priority, or Enter to toggle Active/Delete/BootNext.\n"
        "Every option displays all available choices before changing.";

    ui_draw_setup_frame(TAB_BOOT, NULL, TRUE, "Boot Configuration", help_txt, status);

    UINTN lx = 2;
    UINTN lw = left_panel_width();
    UINTN vis_rows = gUiRows - 5;

    if (gBootCur < gBootScroll) gBootScroll = gBootCur;
    if (gBootCur >= gBootScroll + vis_rows) gBootScroll = gBootCur - vis_rows + 1;

    for (UINTN r = 0; r < vis_rows && (gBootScroll + r) < total_items; r++) {
        UINTN idx = gBootScroll + r;
        UINTN y = 3 + r;
        BOOLEAN sel = (idx == gBootCur);
        UINT8 a = sel ? gTheme.item_sel_attr : gTheme.item_attr;
        ui_hline(lx, y, lw, L' ', sel ? a : gTheme.body_attr);

        CHAR8 b[96];
        if (idx == 0) {
            snprintf_ascii(b, sizeof(b), "%u sec%s", gSetup.boot_timeout, gSetup.timeout_dirty ? " *" : "");
            draw_opt_row(lx, y, lw, sel, "Boot Menu Timeout", b);
        } else if (idx == 1) {
            draw_opt_row(lx, y, lw, sel, "Bootup NumLock State", gSetup.cfg.numlock_boot ? "On" : "Off");
        } else if (idx == 2) {
            draw_opt_row(lx, y, lw, sel, "Quiet Boot Logo", gSetup.cfg.quiet_boot ? "Enabled" : "Disabled");
        } else if (idx == 3) {
            draw_opt_row(lx, y, lw, sel, "Fast Boot", gSetup.cfg.fast_boot ? "Enabled" : "Disabled");
        } else if (idx == 4) {
            const CHAR8 *pxe[3] = { "Disabled", "IPv4 PXE", "IPv6 PXE" };
            draw_opt_row(lx, y, lw, sel, "UEFI Network PXE", pxe[gSetup.cfg.network_pxe % 3]);
        } else if (idx == 5) {
            BOOLEAN fw_ui = ((gSetup.os_indications & EFI_OS_INDICATIONS_BOOT_TO_FW_UI) != 0);
            draw_opt_row(lx, y, lw, sel, "Next Boot to FW UI", fw_ui ? "Enabled" : "Normal");
        } else if (idx == 6) {
            ui_putc(lx, y, L'+', a);
            ui_puts_n(lx + 2, y, "Add New Boot Entry (Browse .EFI File)...", lw - 2, a);
        } else if (idx == 7) {
            ui_putc(lx, y, L'-', a);
            snprintf_ascii(b, sizeof(b), "Delete / Remove Boot Entry (%u installed)...", (UINT32)gSetup.boot_count);
            ui_puts_n(lx + 2, y, b, lw - 2, a);
        } else if (idx < BOOT_FIXED_OPTS + gSetup.boot_count) {
            UINTN bi = idx - BOOT_FIXED_OPTS;
            const BOOT_ENTRY_ITEM *be = &gSetup.boot_entries[bi];
            snprintf_ascii(b, sizeof(b), "#%u Boot%04X %s %s",
                           (UINT32)(bi + 1), be->boot_num,
                           be->active ? "[Active]" : "[Disabl]",
                           be->description);
            ui_puts_n(lx, y, b, lw, a);
        } else if (idx < BOOT_FIXED_OPTS + gSetup.boot_count + gSetup.loader_count) {
            UINTN li = idx - BOOT_FIXED_OPTS - gSetup.boot_count;
            ui_putc(lx, y, gBox.arrow_r, a);
            snprintf_ascii(b, sizeof(b), "Chainload: %s", gSetup.loaders[li].label);
            ui_puts_n(lx + 2, y, b, lw - 2, a);
        } else {
            ui_putc(lx, y, gBox.arrow_r, a);
            ui_puts_n(lx + 2, y, "Chainload Custom .EFI File Path...", lw - 2, a);
        }
    }
}

static BOOLEAN handle_boot_key(const EFI_INPUT_KEY *k) {
    UINTN total_items = BOOT_FIXED_OPTS + gSetup.boot_count + gSetup.loader_count + 1;
    if (k->ScanCode == SCAN_UP) { gBootCur = (gBootCur > 0) ? (gBootCur - 1) : (total_items - 1); return TRUE; }
    if (k->ScanCode == SCAN_DOWN) { gBootCur = (gBootCur + 1) % total_items; return TRUE; }

    /* Shortcut keys on Boot Tab: Insert = Add Boot Entry, Delete = Remove Boot Entry */
    if (k->ScanCode == SCAN_INSERT) {
        run_add_boot_entry_flow();
        return TRUE;
    }
    if (k->ScanCode == SCAN_DELETE) {
        if (gBootCur >= BOOT_FIXED_OPTS && gBootCur < BOOT_FIXED_OPTS + gSetup.boot_count) {
            run_delete_boot_entry_flow((INTN)(gBootCur - BOOT_FIXED_OPTS));
        } else {
            run_delete_boot_entry_flow(-1);
        }
        return TRUE;
    }

    BOOLEAN plus  = (k->UnicodeChar == L'+' || k->UnicodeChar == L'=' || k->ScanCode == SCAN_F6);
    BOOLEAN minus = (k->UnicodeChar == L'-' || k->ScanCode == SCAN_F5);
    BOOLEAN enter = (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n' || k->UnicodeChar == L' ');

    if (gBootCur == 0 && (plus || minus || enter)) {
        if (plus) { gSetup.boot_timeout++; gSetup.timeout_dirty = TRUE; }
        else if (minus && gSetup.boot_timeout > 0) { gSetup.boot_timeout--; gSetup.timeout_dirty = TRUE; }
        else {
            CHAR8 in_s[16], cur_s[16];
            snprintf_ascii(cur_s, sizeof(cur_s), "%u", gSetup.boot_timeout);
            if (ui_input_modal("Set UEFI Boot Timeout", "Enter seconds (0 - 600):", cur_s, in_s, sizeof(in_s), FALSE)) {
                UINT64 v = 0;
                if (parse_dec_u64(in_s, &v) && v <= 600) {
                    gSetup.boot_timeout = (UINT16)v;
                    gSetup.timeout_dirty = TRUE;
                }
            }
        }
        return TRUE;
    } else if (gBootCur == 1 && (plus || minus || enter)) {
        if (pick_u8_option("Bootup NumLock State", kOffOnOpts, 2, &gSetup.cfg.numlock_boot, plus, minus)) {
            gSetup.cfg_dirty = TRUE;
            sync_motherboard_hii_bool("Bootup NumLock", "NumLock", gSetup.cfg.numlock_boot != 0);
        }
        return TRUE;
    } else if (gBootCur == 2 && (plus || minus || enter)) {
        if (pick_u8_option("Quiet Boot Logo", kDisEnOpts, 2, &gSetup.cfg.quiet_boot, plus, minus)) {
            gSetup.cfg_dirty = TRUE;
            sync_motherboard_hii_bool("Quiet Boot", "Full Screen Logo", gSetup.cfg.quiet_boot != 0);
        }
        return TRUE;
    } else if (gBootCur == 3 && (plus || minus || enter)) {
        if (pick_u8_option("Fast Boot", kDisEnOpts, 2, &gSetup.cfg.fast_boot, plus, minus)) {
            gSetup.cfg_dirty = TRUE;
            sync_motherboard_hii_bool("Fast Boot", "Ultra Fast", gSetup.cfg.fast_boot != 0);
        }
        return TRUE;
    } else if (gBootCur == 4 && (plus || minus || enter)) {
        const CHAR8 *pxe_opts[3] = { "Disabled", "IPv4 PXE Network Boot", "IPv6 PXE Network Boot" };
        if (pick_u8_option("UEFI Network PXE Stack", pxe_opts, 3, &gSetup.cfg.network_pxe, plus, minus)) {
            gSetup.cfg_dirty = TRUE;
            sync_motherboard_hii_bool("Network Stack", "PXE", gSetup.cfg.network_pxe != 0);
        }
        return TRUE;
    } else if (gBootCur == 5 && (plus || minus || enter)) {
        const CHAR8 *fw_opts[2] = { "Normal OS Boot", "Reboot Into Motherboard Firmware UI" };
        UINT8 fw = ((gSetup.os_indications & EFI_OS_INDICATIONS_BOOT_TO_FW_UI) != 0) ? 1 : 0;
        if (pick_u8_option("Next Boot to Firmware UI (OsIndications)", fw_opts, 2, &fw, plus, minus)) {
            if (fw) gSetup.os_indications |= EFI_OS_INDICATIONS_BOOT_TO_FW_UI;
            else gSetup.os_indications &= ~EFI_OS_INDICATIONS_BOOT_TO_FW_UI;
            gSetup.os_indications_dirty = TRUE;
        }
        return TRUE;
    } else if (gBootCur == 6 && (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n')) {
        run_add_boot_entry_flow();
        return TRUE;
    } else if (gBootCur == 7 && (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n')) {
        run_delete_boot_entry_flow(-1);
        return TRUE;
    } else if (gBootCur >= BOOT_FIXED_OPTS && gBootCur < BOOT_FIXED_OPTS + gSetup.boot_count) {
        UINTN bi = gBootCur - BOOT_FIXED_OPTS;
        if (plus && bi > 0) {
            BOOT_ENTRY_ITEM tmp = gSetup.boot_entries[bi - 1];
            gSetup.boot_entries[bi - 1] = gSetup.boot_entries[bi];
            gSetup.boot_entries[bi] = tmp;
            gSetup.boot_entries[bi - 1].in_boot_order = TRUE;
            gSetup.boot_order_dirty = TRUE;
            gBootCur--;
            return TRUE;
        } else if (minus && bi + 1 < gSetup.boot_count) {
            BOOT_ENTRY_ITEM tmp = gSetup.boot_entries[bi + 1];
            gSetup.boot_entries[bi + 1] = gSetup.boot_entries[bi];
            gSetup.boot_entries[bi] = tmp;
            gSetup.boot_order_dirty = TRUE;
            gBootCur++;
            return TRUE;
        } else if (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') {
            CHAR8 btitle[72];
            snprintf_ascii(btitle, sizeof(btitle), "Boot%04X: %s",
                           (UINT32)gSetup.boot_entries[bi].boot_num,
                           gSetup.boot_entries[bi].description);
            const CHAR8 *bopts[6] = {
                ">> Boot / Chainload Directly Now (No Reset - Keep Spoofs & Tweaks!)",
                "Change State (Enabled / Disabled)...",
                "Move Priority UP (+)",
                "Move Priority DOWN (-)",
                "Set BootNext & Warm Reset (Note: Wipes Temp Spoofs!)",
                "Delete / Remove This Boot#### Entry from NVRAM"
            };
            INTN c = ui_select_modal(btitle, bopts, 6, 0);
            if (c == 0) {
                CHAR8 cerr[160];
                EFI_STATUS cst = nvram_chainload_boot_entry(bi, cerr, sizeof(cerr));
                if (EFI_ERROR(cst)) {
                    ui_message_modal("Direct Chainload Result", cerr, TRUE);
                }
            } else if (c == 1) {
                const CHAR8 *act_opts[2] = { "Disabled (LOAD_OPTION Inactive)", "Active (LOAD_OPTION_ACTIVE)" };
                UINT8 act_v = gSetup.boot_entries[bi].active ? 1 : 0;
                if (pick_u8_option(btitle, act_opts, 2, &act_v, FALSE, FALSE)) {
                    gSetup.boot_entries[bi].active = (act_v != 0);
                    gSetup.boot_entries[bi].modified_attr = TRUE;
                }
            } else if (c == 2 && bi > 0) {
                BOOT_ENTRY_ITEM tmp = gSetup.boot_entries[bi - 1];
                gSetup.boot_entries[bi - 1] = gSetup.boot_entries[bi];
                gSetup.boot_entries[bi] = tmp;
                gSetup.boot_order_dirty = TRUE;
                gBootCur--;
            } else if (c == 3 && bi + 1 < gSetup.boot_count) {
                BOOT_ENTRY_ITEM tmp = gSetup.boot_entries[bi + 1];
                gSetup.boot_entries[bi + 1] = gSetup.boot_entries[bi];
                gSetup.boot_entries[bi] = tmp;
                gSetup.boot_order_dirty = TRUE;
                gBootCur++;
            } else if (c == 4) {
                if (gSpoofActive || gVolatileHwTweakActive) {
                    if (!ui_confirm_modal(
                            "Warning: Reset Wipes Temp Spoofs & Live Tweaks!",
                            "A Warm Reset will WIPE active Temporary Device Spoofs and live CPU/MSR/FIVR tweaks!\n"
                            "(Pick Option #1 'Boot / Chainload Directly Now' to keep them active.)\n\n"
                            "Reboot via BootNext anyway?",
                            FALSE)) {
                        return TRUE;
                    }
                }
                if (!EFI_ERROR(nvram_set_boot_next(gSetup.boot_entries[bi].boot_num))) {
                    if (gRT && gRT->ResetSystem) {
                        gRT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
                    }
                } else {
                    ui_message_modal("BootNext Error", "Firmware rejected setting BootNext variable.", TRUE);
                }
            } else if (c == 5) {
                run_delete_boot_entry_flow((INTN)bi);
            }
            return TRUE;
        }
    } else if ((k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') &&
               gBootCur < BOOT_FIXED_OPTS + gSetup.boot_count + gSetup.loader_count) {
        UINTN li = gBootCur - BOOT_FIXED_OPTS - gSetup.boot_count;
        if (ui_confirm_modal("Chainload EFI Bootloader", gSetup.loaders[li].label, TRUE)) {
            EFI_STATUS st = nvram_chainload_efi(gSetup.loaders[li].fs_handle, gSetup.loaders[li].path_w);
            if (EFI_ERROR(st)) {
                CHAR8 msg[80];
                snprintf_ascii(msg, sizeof(msg), "Chainload returned: %s", efi_status_str(st));
                ui_message_modal("Chainload Result", msg, TRUE);
            }
        }
        return TRUE;
    } else if (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') {
        EFI_HANDLE fs_h = NULL;
        CHAR16 wp[128];
        if (nvram_browse_efi_file_interactive(&fs_h, wp, 128, NULL, 0)) {
            EFI_STATUS st = nvram_chainload_efi(fs_h, wp);
            if (EFI_ERROR(st)) {
                CHAR8 msg[80];
                snprintf_ascii(msg, sizeof(msg), "Chainload returned: %s", efi_status_str(st));
                ui_message_modal("Chainload Result", msg, TRUE);
            }
        }
        return TRUE;
    }

    return FALSE;
}

/* =========================================================================
 * TAB 6: EXIT (Chainload OS, Save & Exit, Dump, Reset, Defaults, Shutdown)
 * ========================================================================= */
#define EXIT_ITEM_COUNT 11

static const CHAR8 *kExitItems[EXIT_ITEM_COUNT] = {
    ">> Boot / Chainload OS Now (No Reset - Keep Spoofs & Live Tweaks!)",
    "Save Changes and Exit (F10)",
    "Discard Changes and Exit",
    "Save Changes and Cold Reset",
    "Discard Changes and Reset",
    "Save Changes (Stay in Setup)",
    "Discard Staged Changes",
    "Restore Optimized Defaults (F9)",
    "EFI Dump (F12)",
    "Warm Reset System",
    "Power Off / Shutdown System"
};

static BOOLEAN confirm_reset_losing_volatile(const CHAR8 *title, const CHAR8 *normal_prompt) {
    if (gSpoofActive || gVolatileHwTweakActive) {
        CHAR8 warn_msg[360];
        snprintf_ascii(warn_msg, sizeof(warn_msg),
            "%s\n\n"
            "WARNING: %s WILL BE WIPED by a hardware reset!\n"
            "Use '>> Boot / Chainload OS Now <<' if you want temporary spoofs or live MSR/FIVR tweaks active!",
            normal_prompt,
            (gSpoofActive && gVolatileHwTweakActive) ? "Active Temp Device Spoofs AND Live Hardware Tweaks" :
            (gSpoofActive ? "Active Temporary Device/Vendor Spoofs" : "Live CPU/MSR/FIVR/PCIe Tweaks"));
        return ui_confirm_modal(title, warn_msg, FALSE);
    }
    return ui_confirm_modal(title, normal_prompt, TRUE);
}

static VOID draw_exit_tab(VOID) {
    CHAR8 status[80];
    build_footer_status(status, sizeof(status));

    const CHAR8 *help_txt =
        "Use 'Boot / Chainload OS Now' to boot Windows/Linux/OpenCore WITHOUT resetting hardware (keeps Temp Spoofs & live MSR/FIVR undervolts active)!\n"
        "Or commit persistent NVRAM / HII / BootOrder / RTC changes, run EFI Dump (F12), reset, or power off.";
    ui_draw_setup_frame(TAB_EXIT, NULL, TRUE, "Boot OS, Save & Reset", help_txt, status);

    UINTN lx = 2;
    UINTN lw = left_panel_width();
    for (UINTN i = 0; i < EXIT_ITEM_COUNT; i++) {
        BOOLEAN sel = (i == gExitCur);
        UINT8 a = sel ? gTheme.item_sel_attr
                      : ((i == 0 && (gSpoofActive || gVolatileHwTweakActive)) ? gTheme.warn_attr : gTheme.item_attr);
        ui_hline(lx, 4 + i, lw, L' ', sel ? a : ((i == 0 && (gSpoofActive || gVolatileHwTweakActive)) ? gTheme.warn_attr : gTheme.body_attr));
        ui_puts_n(lx, 4 + i, kExitItems[i], lw, a);
    }
}

static BOOLEAN handle_exit_key(const EFI_INPUT_KEY *k) {
    if (k->ScanCode == SCAN_UP) { gExitCur = (gExitCur > 0) ? (gExitCur - 1) : (EXIT_ITEM_COUNT - 1); return TRUE; }
    if (k->ScanCode == SCAN_DOWN) { gExitCur = (gExitCur + 1) % EXIT_ITEM_COUNT; return TRUE; }

    if (k->UnicodeChar == L'\r' || k->UnicodeChar == L'\n') {
        CHAR8 msg[96];
        if (gExitCur == 0) {
            nvram_boot_os_preserve_live_modal("Boot / Chainload OS Now (Zero Reset)");
        } else if (gExitCur == 1) {
            if (ui_confirm_modal("Save & Exit Setup", "Save configuration changes and exit?", TRUE)) {
                nvram_commit_staged_changes(msg, sizeof(msg));
                gShouldExitSetup = TRUE;
            }
        } else if (gExitCur == 2) {
            if (nvram_pending_changes_count() == 0 ||
                ui_confirm_modal("Exit Without Saving", "Quit without saving staged changes?", TRUE)) {
                gShouldExitSetup = TRUE;
            }
        } else if (gExitCur == 3) {
            if (confirm_reset_losing_volatile("Save & Cold Reset", "Save persistent NVRAM changes and cold-reset system?")) {
                nvram_commit_staged_changes(msg, sizeof(msg));
                if (gRT && gRT->ResetSystem) gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
            }
        } else if (gExitCur == 4) {
            if (confirm_reset_losing_volatile("Discard & Reset", "Discard staged changes and reset system now?")) {
                if (gRT && gRT->ResetSystem) gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
            }
        } else if (gExitCur == 5) {
            if (ui_confirm_modal("Save Configuration", "Write all staged changes to UEFI NVRAM & RTC now?", TRUE)) {
                nvram_commit_staged_changes(msg, sizeof(msg));
                ui_message_modal("Changes Saved", msg, FALSE);
            }
        } else if (gExitCur == 6) {
            if (ui_confirm_modal("Discard Staged Changes", "Reload live state from NVRAM and discard edits?", TRUE)) {
                nvram_init_state();
            }
        } else if (gExitCur == 7) {
            if (ui_confirm_modal("Load Optimized Defaults", "Load Optimized Defaults?", TRUE)) {
                nvram_load_optimized_defaults();
            }
        } else if (gExitCur == 8) {
            dump_run_interactive_modal();
        } else if (gExitCur == 9) {
            if (confirm_reset_losing_volatile("Warm Reset", "Perform a UEFI Warm Reset now?")) {
                if (gRT && gRT->ResetSystem) gRT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
            }
        } else if (gExitCur == 10) {
            if (ui_confirm_modal("Power Off System", "Shut down and power off hardware now?", TRUE)) {
                if (gRT && gRT->ResetSystem) gRT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
            }
        }
        return TRUE;
    }
    return FALSE;
}

/* =========================================================================
 * Supervisor Password Gate (if enabled in NVRAM)
 * ========================================================================= */
static BOOLEAN check_supervisor_password_gate(VOID) {
    if (!gSetup.cfg.has_supervisor_pw) return TRUE;

    ui_clear(gTheme.body_attr);
    ui_present();

    for (UINTN tries = 0; tries < 3; tries++) {
        CHAR8 pw[40];
        if (!ui_input_modal("Enter Supervisor Password",
                            "Setup Password Required:", "", pw, sizeof(pw), FALSE)) {
            return FALSE;
        }
        if (nvram_hash_password(pw) == gSetup.cfg.supervisor_pw_hash) {
            return TRUE;
        }
        ui_message_modal("Invalid Password", "Incorrect Supervisor Password.", TRUE);
    }
    return FALSE;
}

/* =========================================================================
 * UEFI Application Entry Point (efi_main)
 * ========================================================================= */
EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    gImageHandle = ImageHandle;
    gST          = SystemTable;
    gBS          = SystemTable ? SystemTable->BootServices : NULL;
    gRT          = SystemTable ? SystemTable->RuntimeServices : NULL;

    if (!gST || !gBS || !gST->ConOut || !gST->ConIn) {
        return EFI_UNSUPPORTED;
    }

    if (gBS->SetWatchdogTimer) {
        gBS->SetWatchdogTimer(0, 0, 0, NULL);
    }

    ui_init();
    drain_keys();

    /* Collect PC / Mac / VM Hardware Specs, SMBIOS, CPUID+MADT+MSRs, Memory, ACPI, PCIe, HII, ME/PSP/SPI */
    nvram_enumerate_all();
    hw_collect_all();
    unlock_refresh_all(TRUE);
    unlock_apply_startup_autopatch(NULL, 0);
    spoof_init();
    nvram_init_state();
    memscan_init();
    debug_init();

    if (!check_supervisor_password_gate()) {
        return EFI_ACCESS_DENIED;
    }

    /* Main Oh my EFI! Event Loop (Keyboard-Only, Zero Flicker) */
    while (!gShouldExitSetup) {
        switch (gActiveTab) {
            case TAB_MAIN:     draw_main_tab();     break;
            case TAB_ADVANCED: draw_advanced_tab(); break;
            case TAB_MEMSCAN:  memscan_draw_tab();  break;
            case TAB_SECURITY: draw_security_tab(); break;
            case TAB_BOOT:     draw_boot_tab();     break;
            case TAB_DEBUG:    debug_draw_tab();    break;
            case TAB_EXIT:     draw_exit_tab();     break;
            default:           draw_main_tab();     break;
        }
        ui_present();

        EFI_INPUT_KEY key;
        if (!wait_key_timeout_ms(&key, 500)) {
            continue;
        }

        /* Global Function Keys (F1 Help, F9 Defaults, F10 Save & Exit, F12 Dump All, Ctrl+L Redraw) */
        if (key.ScanCode == SCAN_F1 || key.UnicodeChar == L'?') {
            ui_general_help_modal();
            continue;
        }
        if (key.ScanCode == SCAN_F9) {
            if (ui_confirm_modal("Load Optimized Defaults", "Load Optimized Defaults?", TRUE)) {
                nvram_load_optimized_defaults();
            }
            continue;
        }
        if (key.ScanCode == SCAN_F10 || key.UnicodeChar == 0x13 /* Ctrl+S */) {
            if (ui_confirm_modal("Save & Exit Setup", "Save configuration and exit?", TRUE)) {
                CHAR8 msg[96];
                nvram_commit_staged_changes(msg, sizeof(msg));
                break;
            }
            continue;
        }
        if (key.ScanCode == SCAN_F12) {
            dump_run_interactive_modal();
            continue;
        }
        if (key.UnicodeChar == 0x0C /* Ctrl+L */) {
            ui_force_redraw();
            continue;
        }

        BOOLEAN handled = FALSE;
        switch (gActiveTab) {
            case TAB_MAIN:     handled = handle_main_key(&key);     break;
            case TAB_ADVANCED: handled = handle_advanced_key(&key); break;
            case TAB_MEMSCAN:  handled = memscan_handle_key(&key);  break;
            case TAB_SECURITY: handled = handle_security_key(&key); break;
            case TAB_BOOT:     handled = handle_boot_key(&key);     break;
            case TAB_DEBUG:    handled = debug_handle_key(&key);    break;
            case TAB_EXIT:     handled = handle_exit_key(&key);     break;
        }
        if (handled) continue;

        if (key.ScanCode == SCAN_LEFT || key.UnicodeChar == L'[') {
            gAdvSub = ADV_SUB_NONE;
            gActiveTab = (gActiveTab > 0) ? (gActiveTab - 1) : (TAB_COUNT - 1);
        } else if (key.ScanCode == SCAN_RIGHT || key.UnicodeChar == L']') {
            gAdvSub = ADV_SUB_NONE;
            gActiveTab = (gActiveTab + 1) % TAB_COUNT;
        } else if (key.ScanCode == SCAN_ESC || key.UnicodeChar == 0x1B) {
            if (ui_confirm_modal("Exit Oh my EFI!", "Quit without saving?", FALSE)) {
                break;
            }
        }
    }

    if (gST && gST->ConOut) {
        gST->ConOut->SetAttribute(gST->ConOut, EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BACKGROUND_BLACK));
        gST->ConOut->ClearScreen(gST->ConOut);
        if (gST->ConOut->EnableCursor) {
            gST->ConOut->EnableCursor(gST->ConOut, TRUE);
        }
    }
    return EFI_SUCCESS;
}
