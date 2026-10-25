#include "ui.h"
#include "util.h"

typedef struct {
    CHAR16 ch;
    UINT8  attr;
} UI_CELL;

UINTN        gUiCols = 80;
UINTN        gUiRows = 25;
UI_PALETTE   gTheme;
UI_BOX_CHARS gBox;
UINTN        gConsoleModeCount = 0;
UI_CONSOLE_MODE_INFO gConsoleModes[UI_MAX_CONSOLE_MODES];
INT32        gCurrentConsoleMode = 0;
UINT8        gCurrentThemeIdx = UI_THEME_APTIO_2011;

static UI_CELL gBackBuf[UI_MAX_ROWS][UI_MAX_COLS];
static UI_CELL gFrontBuf[UI_MAX_ROWS][UI_MAX_COLS];
static UI_CELL gModalSaveBuf[UI_MAX_ROWS][UI_MAX_COLS];
static BOOLEAN gFrontValid = FALSE;

static const CHAR8 *kTabNames[7] = {
    "Main", "Advanced", "MemScan", "Security", "Boot", "Debug", "Exit"
};

VOID ui_set_theme(UINT8 theme_idx) {
    if (theme_idx >= UI_THEME_COUNT) theme_idx = UI_THEME_APTIO_2011;
    gCurrentThemeIdx = theme_idx;

    if (theme_idx == UI_THEME_APTIO_2011) {
        /* Authentic 2011 AMI Aptio IV Setup Utility Color Scheme */
        gTheme.header_attr       = EFI_TEXT_ATTR(EFI_WHITE,     EFI_BACKGROUND_BLUE);
        gTheme.tab_bar_attr      = EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BACKGROUND_BLUE);
        gTheme.tab_active_attr   = EFI_TEXT_ATTR(EFI_BLUE,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.body_attr         = EFI_TEXT_ATTR(EFI_BLACK,     EFI_BACKGROUND_LIGHTGRAY);
        gTheme.border_attr       = EFI_TEXT_ATTR(EFI_BLUE,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.section_attr      = EFI_TEXT_ATTR(EFI_BLUE,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.label_attr        = EFI_TEXT_ATTR(EFI_BLACK,     EFI_BACKGROUND_LIGHTGRAY);
        gTheme.value_attr        = EFI_TEXT_ATTR(EFI_DARKGRAY,  EFI_BACKGROUND_LIGHTGRAY);
        gTheme.item_attr         = EFI_TEXT_ATTR(EFI_BLUE,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.item_sel_attr     = EFI_TEXT_ATTR(EFI_WHITE,     EFI_BACKGROUND_BLUE);
        gTheme.dim_attr          = EFI_TEXT_ATTR(EFI_DARKGRAY,  EFI_BACKGROUND_LIGHTGRAY);
        gTheme.dim_sel_attr      = EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BACKGROUND_BLUE);
        gTheme.help_title_attr   = EFI_TEXT_ATTR(EFI_BLUE,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.help_text_attr    = EFI_TEXT_ATTR(EFI_BLACK,     EFI_BACKGROUND_LIGHTGRAY);
        gTheme.footer_attr       = EFI_TEXT_ATTR(EFI_WHITE,     EFI_BACKGROUND_BLUE);
        gTheme.modal_attr        = EFI_TEXT_ATTR(EFI_WHITE,     EFI_BACKGROUND_BLUE);
        gTheme.modal_border_attr = EFI_TEXT_ATTR(EFI_YELLOW,    EFI_BACKGROUND_BLUE);
        gTheme.modal_sel_attr    = EFI_TEXT_ATTR(EFI_BLACK,     EFI_BACKGROUND_LIGHTGRAY);
        gTheme.warn_attr         = EFI_TEXT_ATTR(EFI_YELLOW,    EFI_BACKGROUND_RED);
        gTheme.shadow_attr       = EFI_TEXT_ATTR(EFI_DARKGRAY,  EFI_BACKGROUND_BLACK);
    } else if (theme_idx == UI_THEME_CLASSIC_BLUE) {
        /* Classic Award / Phoenix Blue Setup Theme */
        gTheme.header_attr       = EFI_TEXT_ATTR(EFI_BLACK,     EFI_BACKGROUND_CYAN);
        gTheme.tab_bar_attr      = EFI_TEXT_ATTR(EFI_WHITE,     EFI_BACKGROUND_CYAN);
        gTheme.tab_active_attr   = EFI_TEXT_ATTR(EFI_YELLOW,    EFI_BACKGROUND_BLUE);
        gTheme.body_attr         = EFI_TEXT_ATTR(EFI_WHITE,     EFI_BACKGROUND_BLUE);
        gTheme.border_attr       = EFI_TEXT_ATTR(EFI_LIGHTCYAN, EFI_BACKGROUND_BLUE);
        gTheme.section_attr      = EFI_TEXT_ATTR(EFI_YELLOW,    EFI_BACKGROUND_BLUE);
        gTheme.label_attr        = EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BACKGROUND_BLUE);
        gTheme.value_attr        = EFI_TEXT_ATTR(EFI_WHITE,     EFI_BACKGROUND_BLUE);
        gTheme.item_attr         = EFI_TEXT_ATTR(EFI_LIGHTCYAN, EFI_BACKGROUND_BLUE);
        gTheme.item_sel_attr     = EFI_TEXT_ATTR(EFI_WHITE,     EFI_BACKGROUND_RED);
        gTheme.dim_attr          = EFI_TEXT_ATTR(EFI_DARKGRAY,  EFI_BACKGROUND_BLUE);
        gTheme.dim_sel_attr      = EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BACKGROUND_RED);
        gTheme.help_title_attr   = EFI_TEXT_ATTR(EFI_YELLOW,    EFI_BACKGROUND_BLUE);
        gTheme.help_text_attr    = EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BACKGROUND_BLUE);
        gTheme.footer_attr       = EFI_TEXT_ATTR(EFI_BLACK,     EFI_BACKGROUND_CYAN);
        gTheme.modal_attr        = EFI_TEXT_ATTR(EFI_BLACK,     EFI_BACKGROUND_LIGHTGRAY);
        gTheme.modal_border_attr = EFI_TEXT_ATTR(EFI_BLUE,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.modal_sel_attr    = EFI_TEXT_ATTR(EFI_WHITE,     EFI_BACKGROUND_RED);
        gTheme.warn_attr         = EFI_TEXT_ATTR(EFI_YELLOW,    EFI_BACKGROUND_RED);
        gTheme.shadow_attr       = EFI_TEXT_ATTR(EFI_DARKGRAY,  EFI_BACKGROUND_BLACK);
    } else {
        /* High-Contrast Dark Theme (great for serial consoles / Retina / OLED) */
        gTheme.header_attr       = EFI_TEXT_ATTR(EFI_BLACK,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.tab_bar_attr      = EFI_TEXT_ATTR(EFI_LIGHTGRAY,  EFI_BACKGROUND_BLACK);
        gTheme.tab_active_attr   = EFI_TEXT_ATTR(EFI_BLACK,      EFI_BACKGROUND_CYAN);
        gTheme.body_attr         = EFI_TEXT_ATTR(EFI_LIGHTGRAY,  EFI_BACKGROUND_BLACK);
        gTheme.border_attr       = EFI_TEXT_ATTR(EFI_LIGHTCYAN,  EFI_BACKGROUND_BLACK);
        gTheme.section_attr      = EFI_TEXT_ATTR(EFI_YELLOW,     EFI_BACKGROUND_BLACK);
        gTheme.label_attr        = EFI_TEXT_ATTR(EFI_LIGHTGRAY,  EFI_BACKGROUND_BLACK);
        gTheme.value_attr        = EFI_TEXT_ATTR(EFI_WHITE,      EFI_BACKGROUND_BLACK);
        gTheme.item_attr         = EFI_TEXT_ATTR(EFI_LIGHTGREEN, EFI_BACKGROUND_BLACK);
        gTheme.item_sel_attr     = EFI_TEXT_ATTR(EFI_BLACK,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.dim_attr          = EFI_TEXT_ATTR(EFI_DARKGRAY,   EFI_BACKGROUND_BLACK);
        gTheme.dim_sel_attr      = EFI_TEXT_ATTR(EFI_DARKGRAY,   EFI_BACKGROUND_LIGHTGRAY);
        gTheme.help_title_attr   = EFI_TEXT_ATTR(EFI_YELLOW,     EFI_BACKGROUND_BLACK);
        gTheme.help_text_attr    = EFI_TEXT_ATTR(EFI_LIGHTGRAY,  EFI_BACKGROUND_BLACK);
        gTheme.footer_attr       = EFI_TEXT_ATTR(EFI_BLACK,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.modal_attr        = EFI_TEXT_ATTR(EFI_WHITE,      EFI_BACKGROUND_BLUE);
        gTheme.modal_border_attr = EFI_TEXT_ATTR(EFI_LIGHTCYAN,  EFI_BACKGROUND_BLUE);
        gTheme.modal_sel_attr    = EFI_TEXT_ATTR(EFI_BLACK,      EFI_BACKGROUND_LIGHTGRAY);
        gTheme.warn_attr         = EFI_TEXT_ATTR(EFI_YELLOW,     EFI_BACKGROUND_RED);
        gTheme.shadow_attr       = EFI_TEXT_ATTR(EFI_DARKGRAY,   EFI_BACKGROUND_BLACK);
    }
    gFrontValid = FALSE;
}

static VOID detect_box_chars(VOID) {
    CHAR16 test_str[] = {
        0x2500, 0x2502, 0x250C, 0x2510, 0x2514, 0x2518,
        0x252C, 0x2534, 0x251C, 0x2524, 0x253C, 0x25BA, 0x25B2, 0x25BC, 0
    };
    BOOLEAN unicode_ok = TRUE;
    if (gST && gST->ConOut && gST->ConOut->TestString) {
        if (EFI_ERROR(gST->ConOut->TestString(gST->ConOut, test_str))) {
            unicode_ok = FALSE;
        }
    }
    if (unicode_ok) {
        gBox.hline   = 0x2500; /* ─ */
        gBox.vline   = 0x2502; /* │ */
        gBox.tl      = 0x250C; /* ┌ */
        gBox.tr      = 0x2510; /* ┐ */
        gBox.bl      = 0x2514; /* └ */
        gBox.br      = 0x2518; /* ┘ */
        gBox.tee_t   = 0x252C; /* ┬ */
        gBox.tee_b   = 0x2534; /* ┴ */
        gBox.tee_l   = 0x251C; /* ├ */
        gBox.tee_r   = 0x2524; /* ┤ */
        gBox.cross   = 0x253C; /* ┼ */
        gBox.arrow_r = 0x25BA; /* ► */
        gBox.arrow_u = 0x25B2; /* ▲ */
        gBox.arrow_d = 0x25BC; /* ▼ */
    } else {
        gBox.hline   = L'-';
        gBox.vline   = L'|';
        gBox.tl      = L'+';
        gBox.tr      = L'+';
        gBox.bl      = L'+';
        gBox.br      = L'+';
        gBox.tee_t   = L'+';
        gBox.tee_b   = L'+';
        gBox.tee_l   = L'+';
        gBox.tee_r   = L'+';
        gBox.cross   = L'+';
        gBox.arrow_r = L'>';
        gBox.arrow_u = L'^';
        gBox.arrow_d = L'v';
    }
}

BOOLEAN ui_set_console_mode(INT32 mode_num) {
    if (!gST || !gST->ConOut) return FALSE;
    UINTN cols = 0, rows = 0;
    if (EFI_ERROR(gST->ConOut->QueryMode(gST->ConOut, (UINTN)mode_num, &cols, &rows))) {
        return FALSE;
    }
    if (cols < 80 || rows < 24) return FALSE;
    if (EFI_ERROR(gST->ConOut->SetMode(gST->ConOut, (UINTN)mode_num))) {
        return FALSE;
    }
    if (cols > UI_MAX_COLS) cols = UI_MAX_COLS;
    if (rows > UI_MAX_ROWS) rows = UI_MAX_ROWS;
    gUiCols = cols;
    gUiRows = rows;
    gCurrentConsoleMode = mode_num;
    if (gST->ConOut->EnableCursor) {
        gST->ConOut->EnableCursor(gST->ConOut, FALSE);
    }
    ui_force_redraw();
    return TRUE;
}

VOID ui_init(VOID) {
    /*
     * On Intel iMac / MacBook (Apple EFI 1.10 & 2.x), firmware starts in
     * graphics boot-screen mode where ConOut is hidden behind the Apple boot
     * screen until ConsoleControl->SetMode(EfiConsoleControlScreenText) is called.
     */
    EFI_CONSOLE_CONTROL_PROTOCOL *cc = NULL;
    if (!EFI_ERROR(efi_locate_protocol(&gEfiConsoleControlProtocolGuid, (VOID **)&cc)) && cc) {
        cc->SetMode(cc, EfiConsoleControlScreenText);
    }

    ui_set_theme(UI_THEME_APTIO_2011);

    /* Enumerate valid text modes */
    gConsoleModeCount = 0;
    INT32 mode_80x25 = -1;
    INT32 mode_100x31 = -1;
    INT32 fallback_mode = -1;

    if (gST && gST->ConOut && gST->ConOut->Mode) {
        INT32 max_m = gST->ConOut->Mode->MaxMode;
        if (max_m <= 0) max_m = 1;
        for (INT32 m = 0; m < max_m && gConsoleModeCount < UI_MAX_CONSOLE_MODES; m++) {
            UINTN c = 0, r = 0;
            if (!EFI_ERROR(gST->ConOut->QueryMode(gST->ConOut, (UINTN)m, &c, &r))) {
                if (c >= 80 && r >= 24 && c <= UI_MAX_COLS && r <= UI_MAX_ROWS) {
                    gConsoleModes[gConsoleModeCount].mode_num = m;
                    gConsoleModes[gConsoleModeCount].cols = c;
                    gConsoleModes[gConsoleModeCount].rows = r;
                    gConsoleModeCount++;
                    if (c == 80 && r == 25 && mode_80x25 < 0) mode_80x25 = m;
                    if (c == 100 && r == 31 && mode_100x31 < 0) mode_100x31 = m;
                    if (fallback_mode < 0) fallback_mode = m;
                }
            }
        }
    }

    /* Prefer classic 80x25 2011 BIOS resolution by default, else 100x31, else current/first */
    INT32 target = mode_80x25;
    if (target < 0) target = mode_100x31;
    if (target < 0) target = fallback_mode;

    if (target >= 0) {
        ui_set_console_mode(target);
    } else if (gST && gST->ConOut) {
        UINTN c = 80, r = 25;
        INT32 cur = gST->ConOut->Mode ? gST->ConOut->Mode->Mode : 0;
        if (!EFI_ERROR(gST->ConOut->QueryMode(gST->ConOut, (UINTN)cur, &c, &r))) {
            if (c >= 40 && c <= UI_MAX_COLS) gUiCols = c;
            if (r >= 20 && r <= UI_MAX_ROWS) gUiRows = r;
        }
        gCurrentConsoleMode = cur;
    }

    if (gST && gST->ConOut && gST->ConOut->EnableCursor) {
        gST->ConOut->EnableCursor(gST->ConOut, FALSE);
    }

    detect_box_chars();
    ui_force_redraw();
}

VOID ui_force_redraw(VOID) {
    gFrontValid = FALSE;
    if (gST && gST->ConOut) {
        gST->ConOut->SetAttribute(gST->ConOut, gTheme.footer_attr);
        gST->ConOut->ClearScreen(gST->ConOut);
        if (gST->ConOut->EnableCursor) {
            gST->ConOut->EnableCursor(gST->ConOut, FALSE);
        }
    }
}

VOID ui_clear(UINT8 attr) {
    for (UINTN r = 0; r < gUiRows; r++) {
        for (UINTN c = 0; c < gUiCols; c++) {
            gBackBuf[r][c].ch = L' ';
            gBackBuf[r][c].attr = attr;
        }
    }
}

VOID ui_fill_rect(UINTN x, UINTN y, UINTN w, UINTN h, CHAR16 ch, UINT8 attr) {
    for (UINTN r = y; r < y + h && r < gUiRows; r++) {
        for (UINTN c = x; c < x + w && c < gUiCols; c++) {
            gBackBuf[r][c].ch = ch;
            gBackBuf[r][c].attr = attr;
        }
    }
}

VOID ui_putc(UINTN x, UINTN y, CHAR16 ch, UINT8 attr) {
    if (x < gUiCols && y < gUiRows) {
        gBackBuf[y][x].ch = ch;
        gBackBuf[y][x].attr = attr;
    }
}

VOID ui_puts(UINTN x, UINTN y, const CHAR8 *s, UINT8 attr) {
    if (!s || y >= gUiRows) return;
    while (*s && x < gUiCols) {
        UINT8 b = (UINT8)*s++;
        gBackBuf[y][x].ch = (b >= 0x20 && b <= 0x7E) ? (CHAR16)b : L'?';
        gBackBuf[y][x].attr = attr;
        x++;
    }
}

VOID ui_puts_n(UINTN x, UINTN y, const CHAR8 *s, UINTN max_w, UINT8 attr) {
    if (!s || y >= gUiRows || max_w == 0) return;
    UINTN n = 0;
    while (*s && x < gUiCols && n < max_w) {
        UINT8 b = (UINT8)*s++;
        gBackBuf[y][x].ch = (b >= 0x20 && b <= 0x7E) ? (CHAR16)b : L'?';
        gBackBuf[y][x].attr = attr;
        x++;
        n++;
    }
}

VOID ui_wputs_n(UINTN x, UINTN y, const CHAR16 *ws, UINTN max_w, UINT8 attr) {
    if (!ws || y >= gUiRows || max_w == 0) return;
    UINTN n = 0;
    while (*ws && x < gUiCols && n < max_w) {
        CHAR16 wc = *ws++;
        if (wc < 0x20) wc = L' ';
        gBackBuf[y][x].ch = wc;
        gBackBuf[y][x].attr = attr;
        x++;
        n++;
    }
}

VOID ui_printf(UINTN x, UINTN y, UINT8 attr, const CHAR8 *fmt, ...) {
    CHAR16 wbuf[256];
    va_list ap;
    if (y >= gUiRows || x >= gUiCols) return;
    va_start(ap, fmt);
    wvsnprintf(wbuf, sizeof(wbuf) / sizeof(wbuf[0]), fmt, ap);
    va_end(ap);
    ui_wputs_n(x, y, wbuf, gUiCols - x, attr);
}

VOID ui_hline(UINTN x, UINTN y, UINTN w, CHAR16 ch, UINT8 attr) {
    if (y >= gUiRows) return;
    for (UINTN c = x; c < x + w && c < gUiCols; c++) {
        gBackBuf[y][c].ch = ch;
        gBackBuf[y][c].attr = attr;
    }
}

VOID ui_vline(UINTN x, UINTN y, UINTN h, CHAR16 ch, UINT8 attr) {
    if (x >= gUiCols) return;
    for (UINTN r = y; r < y + h && r < gUiRows; r++) {
        gBackBuf[r][x].ch = ch;
        gBackBuf[r][x].attr = attr;
    }
}

VOID ui_draw_box(UINTN x, UINTN y, UINTN w, UINTN h, UINT8 border_attr, UINT8 fill_attr, BOOLEAN shadow) {
    if (w < 2 || h < 2 || x >= gUiCols || y >= gUiRows) return;
    ui_fill_rect(x, y, w, h, L' ', fill_attr);
    ui_hline(x + 1, y, w - 2, gBox.hline, border_attr);
    ui_hline(x + 1, y + h - 1, w - 2, gBox.hline, border_attr);
    ui_vline(x, y + 1, h - 2, gBox.vline, border_attr);
    ui_vline(x + w - 1, y + 1, h - 2, gBox.vline, border_attr);
    ui_putc(x, y, gBox.tl, border_attr);
    ui_putc(x + w - 1, y, gBox.tr, border_attr);
    ui_putc(x, y + h - 1, gBox.bl, border_attr);
    ui_putc(x + w - 1, y + h - 1, gBox.br, border_attr);

    if (shadow) {
        /* Classic 2011 BIOS 2-col right & 1-row bottom drop shadow */
        for (UINTN r = y + 1; r <= y + h && r < gUiRows; r++) {
            for (UINTN c = x + w; c < x + w + 2 && c < gUiCols; c++) {
                gBackBuf[r][c].attr = gTheme.shadow_attr;
            }
        }
        if (y + h < gUiRows) {
            for (UINTN c = x + 2; c < x + w + 2 && c < gUiCols; c++) {
                gBackBuf[y + h][c].attr = gTheme.shadow_attr;
            }
        }
    }
}

static UINTN ui_count_wrapped_lines(UINTN w, const CHAR8 *text) {
    if (!text || w == 0) return 1;
    UINTN line = 0;
    const CHAR8 *p = text;
    while (*p) {
        if (*p == '\n') {
            p++;
            line++;
            continue;
        }
        UINTN count = 0;
        UINTN last_space = 0;
        BOOLEAN has_space = FALSE;
        while (p[count] && p[count] != '\n' && count < w) {
            if (p[count] == ' ') {
                last_space = count;
                has_space = TRUE;
            }
            count++;
        }
        UINTN take = count;
        if (p[count] && p[count] != '\n' && p[count] != ' ' && has_space && last_space > 0) {
            take = last_space;
        }
        p += take;
        while (*p == ' ') p++;
        if (*p == '\n') p++;
        line++;
    }
    return (line == 0) ? 1 : line;
}

VOID ui_draw_wrapped(UINTN x, UINTN y, UINTN w, UINTN max_lines, const CHAR8 *text, UINT8 attr) {
    if (!text || w == 0 || max_lines == 0) return;
    UINTN line = 0;
    const CHAR8 *p = text;
    while (*p && line < max_lines && (y + line) < gUiRows) {
        if (*p == '\n') {
            p++;
            line++;
            continue;
        }
        /* Find word wrap boundary */
        UINTN count = 0;
        UINTN last_space = 0;
        BOOLEAN has_space = FALSE;
        while (p[count] && p[count] != '\n' && count < w) {
            if (p[count] == ' ') {
                last_space = count;
                has_space = TRUE;
            }
            count++;
        }
        UINTN take = count;
        if (p[count] && p[count] != '\n' && p[count] != ' ' && has_space && last_space > 0) {
            take = last_space;
        }
        ui_puts_n(x, y + line, p, take, attr);
        p += take;
        while (*p == ' ') p++;
        if (*p == '\n') p++;
        line++;
    }
}

VOID ui_present(VOID) {
    if (!gST || !gST->ConOut) return;
    CHAR16 run[UI_MAX_COLS + 1];

    for (UINTN r = 0; r < gUiRows; r++) {
        /*
         * Avoid writing to the bottom-right corner cell (gUiCols - 1, gUiRows - 1)
         * because UEFI SimpleTextOut scrolls the console up 1 line when printing there.
         */
        UINTN col_limit = (r == gUiRows - 1) ? (gUiCols - 1) : gUiCols;
        UINTN c = 0;
        while (c < col_limit) {
            if (gFrontValid &&
                gBackBuf[r][c].ch == gFrontBuf[r][c].ch &&
                gBackBuf[r][c].attr == gFrontBuf[r][c].attr) {
                c++;
                continue;
            }
            UINT8 attr = gBackBuf[r][c].attr;
            UINTN start_c = c;
            UINTN n = 0;
            while (c < col_limit && gBackBuf[r][c].attr == attr) {
                if (gFrontValid &&
                    gBackBuf[r][c].ch == gFrontBuf[r][c].ch &&
                    gBackBuf[r][c].attr == gFrontBuf[r][c].attr) {
                    /* Look ahead 2 cells: coalescing tiny unchanged gaps saves cursor calls */
                    if (c + 1 >= col_limit ||
                        (gBackBuf[r][c + 1].ch == gFrontBuf[r][c + 1].ch &&
                         gBackBuf[r][c + 1].attr == gFrontBuf[r][c + 1].attr)) {
                        break;
                    }
                }
                run[n++] = gBackBuf[r][c].ch;
                gFrontBuf[r][c] = gBackBuf[r][c];
                c++;
            }
            run[n] = 0;
            gST->ConOut->SetAttribute(gST->ConOut, attr);
            gST->ConOut->SetCursorPosition(gST->ConOut, start_c, r);
            gST->ConOut->OutputString(gST->ConOut, run);
        }
    }
    gFrontValid = TRUE;
}

VOID ui_draw_setup_frame(
    UINTN active_tab,
    const CHAR8 *submenu_title,
    BOOLEAN split_right_panel,
    const CHAR8 *help_title,
    const CHAR8 *help_body,
    const CHAR8 *status_left
) {
    ui_clear(gTheme.body_attr);

    /* Row 0: Top Header Bar ("Oh my EFI!") */
    ui_hline(0, 0, gUiCols, L' ', gTheme.header_attr);
    const CHAR8 *hdr = OHMYEFI_TITLE;
    UINTN hlen = str_len(hdr);
    UINTN hx = (gUiCols > hlen) ? (gUiCols - hlen) / 2 : 0;
    ui_puts_n(hx, 0, hdr, gUiCols, gTheme.header_attr);

    /* Row 1: Top Navigation Tab Bar */
    ui_hline(0, 1, gUiCols, L' ', gTheme.tab_bar_attr);
    UINTN tx = 2;
    for (UINTN i = 0; i < 7; i++) {
        UINT8 tattr = (i == active_tab) ? gTheme.tab_active_attr : gTheme.tab_bar_attr;
        UINTN nlen = str_len(kTabNames[i]);
        if (tx + nlen + 2 < gUiCols) {
            ui_putc(tx, 1, L' ', tattr);
            ui_puts(tx + 1, 1, kTabNames[i], tattr);
            ui_putc(tx + 1 + nlen, 1, L' ', tattr);
            tx += nlen + 3;
        }
    }

    /* Main Workspace Frame: Rows 2 .. gUiRows - 2 */
    UINTN frame_y = 2;
    UINTN frame_h = gUiRows - 3;
    ui_draw_box(0, frame_y, gUiCols, frame_h, gTheme.border_attr, gTheme.body_attr, FALSE);

    if (submenu_title && submenu_title[0]) {
        ui_printf(3, frame_y, gTheme.section_attr, "[ %s ]", submenu_title);
    }

    UINTN split_x = gUiCols;
    if (split_right_panel) {
        /* 2/3 Left Item Area, 1/3 Right Help + 2011 Key Legend */
        split_x = (gUiCols * 2) / 3;
        if (split_x < 50 && gUiCols >= 80) split_x = 52;
        if (gUiCols - split_x < 27 && gUiCols >= 80) split_x = gUiCols - 28;

        ui_putc(split_x, frame_y, gBox.tee_t, gTheme.border_attr);
        ui_vline(split_x, frame_y + 1, frame_h - 2, gBox.vline, gTheme.border_attr);
        ui_putc(split_x, frame_y + frame_h - 1, gBox.tee_b, gTheme.border_attr);

        /* Right Panel Split: Top = Item Specific Help, Bottom = 2011 Key Legend */
        UINTN legend_rows = 9;
        UINTN mid_y = frame_y + frame_h - 1 - legend_rows - 1;
        if (mid_y > frame_y + 3) {
            ui_putc(split_x, mid_y, gBox.tee_l, gTheme.border_attr);
            ui_hline(split_x + 1, mid_y, gUiCols - split_x - 2, gBox.hline, gTheme.border_attr);
            ui_putc(gUiCols - 1, mid_y, gBox.tee_r, gTheme.border_attr);

            UINTN rx = split_x + 2;
            UINTN rw = (gUiCols > rx + 1) ? (gUiCols - rx - 1) : 1;

            /* Item Specific Help */
            const CHAR8 *ht = (help_title && help_title[0]) ? help_title : "Item Specific Help";
            ui_puts_n(rx, frame_y + 1, ht, rw, gTheme.help_title_attr);
            if (help_body && help_body[0] && mid_y > frame_y + 3) {
                ui_draw_wrapped(rx, frame_y + 3, rw, mid_y - (frame_y + 3), help_body, gTheme.help_text_attr);
            }

            /* Authentic 2011 Key Legend */
            UINTN ly = mid_y + 1;
            ui_puts_n(rx, ly + 0, "-> <-: Select Screen", rw, gTheme.help_text_attr);
            ui_puts_n(rx, ly + 1, "Up/Dn: Select Item",   rw, gTheme.help_text_attr);
            ui_puts_n(rx, ly + 2, "Enter: Select Option", rw, gTheme.help_text_attr);
            ui_puts_n(rx, ly + 3, "+/-  : Change Opt.",   rw, gTheme.help_text_attr);
            ui_puts_n(rx, ly + 4, "F1/? : General Help",  rw, gTheme.help_text_attr);
            ui_puts_n(rx, ly + 5, "F9   : Opt. Defaults", rw, gTheme.help_text_attr);
            ui_puts_n(rx, ly + 6, "F10  : Save & Exit",   rw, gTheme.help_text_attr);
            ui_puts_n(rx, ly + 7, "F12  : EFI Dump",      rw, gTheme.help_text_attr);
            ui_puts_n(rx, ly + 8, "ESC  : Exit / Back",   rw, gTheme.help_text_attr);
        }
    }

    /* Status & Live RTC Clock on Bottom Frame Border (Row gUiRows - 2) */
    UINTN border_bot_y = frame_y + frame_h - 1;
    if (status_left && status_left[0] && gUiCols >= 40) {
        UINTN max_st = split_right_panel ? (split_x > 4 ? split_x - 4 : 10) : (gUiCols - 18);
        CHAR8 st_tmp[96];
        snprintf_ascii(st_tmp, sizeof(st_tmp), "[ %s ]", status_left);
        ui_puts_n(2, border_bot_y, st_tmp, max_st, gTheme.section_attr);
    }
    if (gRT && gRT->GetTime && gUiCols >= 30) {
        EFI_TIME tm;
        if (!EFI_ERROR(gRT->GetTime(&tm, NULL))) {
            ui_printf(gUiCols - 14, border_bot_y, gTheme.section_attr,
                      "[ %02u:%02u:%02u ]", tm.Hour, tm.Minute, tm.Second);
        }
    }

    /* Bottom Footer Row ("Down Below", gUiRows - 1): Version & Copyright */
    ui_hline(0, gUiRows - 1, gUiCols, L' ', gTheme.footer_attr);
    const CHAR8 *ver_str = OHMYEFI_COPYRIGHT;
    UINTN vlen = str_len(ver_str);
    UINTN vx = (gUiCols > vlen + 1) ? (gUiCols - vlen) / 2 : 1;
    ui_puts_n(vx, gUiRows - 1, ver_str, gUiCols - 2, gTheme.footer_attr);
}

static VOID modal_save(VOID) {
    memcpy(gModalSaveBuf, gBackBuf, sizeof(gBackBuf));
}

static VOID modal_restore(VOID) {
    memcpy(gBackBuf, gModalSaveBuf, sizeof(gBackBuf));
    ui_present();
}

BOOLEAN ui_confirm_modal(const CHAR8 *title, const CHAR8 *question, BOOLEAN default_yes) {
    modal_save();
    BOOLEAN yes = default_yes;
    const CHAR8 *qtxt = question ? question : "Are you sure?";

    UINTN mw = 48;
    BOOLEAN has_nl = FALSE;
    for (const CHAR8 *p = qtxt; *p; p++) {
        if (*p == '\n') { has_nl = TRUE; break; }
    }
    if (has_nl || str_len(qtxt) > 90) mw = 66;
    if (title && str_len(title) + 8 > mw) mw = str_len(title) + 8;
    if (mw > gUiCols - 4) mw = gUiCols - 4;
    if (mw < 20) mw = 20;

    UINTN max_lines = (gUiRows > 9) ? (gUiRows - 9) : 3;
    UINTN lines = ui_count_wrapped_lines(mw - 6, qtxt);
    if (lines < 3) lines = 3;
    if (lines > max_lines) lines = max_lines;

    UINTN mh = lines + 5;
    UINTN mx = (gUiCols - mw) / 2;
    UINTN my = (gUiRows - mh) / 2;

    for (;;) {
        memcpy(gBackBuf, gModalSaveBuf, sizeof(gBackBuf));
        ui_draw_box(mx, my, mw, mh, gTheme.modal_border_attr, gTheme.modal_attr, TRUE);
        if (title) {
            UINTN tlen = str_len(title);
            UINTN tx = mx + ((mw > tlen + 4) ? (mw - tlen - 4) / 2 : 1);
            ui_printf(tx, my, gTheme.modal_border_attr, "[ %s ]", title);
        }
        ui_draw_wrapped(mx + 3, my + 2, mw - 6, lines, qtxt, gTheme.modal_attr);

        UINTN by = my + mh - 2;
        UINTN bx_yes = mx + (mw / 2) - 10;
        UINTN bx_no  = mx + (mw / 2) + 3;
        ui_puts(bx_yes, by, "[ Yes ]", yes ? gTheme.modal_sel_attr : gTheme.modal_attr);
        ui_puts(bx_no,  by, "[ No ]",  !yes ? gTheme.modal_sel_attr : gTheme.modal_attr);

        ui_present();

        EFI_INPUT_KEY k;
        wait_key_blocking(&k);
        if (k.ScanCode == SCAN_LEFT || k.ScanCode == SCAN_RIGHT || k.UnicodeChar == L'\t') {
            yes = !yes;
        } else if (k.UnicodeChar == L'y' || k.UnicodeChar == L'Y') {
            modal_restore();
            return TRUE;
        } else if (k.UnicodeChar == L'n' || k.UnicodeChar == L'N' ||
                   k.ScanCode == SCAN_ESC || k.UnicodeChar == 0x1B) {
            modal_restore();
            return FALSE;
        } else if (k.UnicodeChar == L'\r' || k.UnicodeChar == L'\n') {
            modal_restore();
            return yes;
        }
    }
}

VOID ui_message_modal(const CHAR8 *title, const CHAR8 *body, BOOLEAN is_warning) {
    modal_save();
    const CHAR8 *btxt = body ? body : "";

    UINTN mw = 58;
    BOOLEAN has_nl = FALSE;
    for (const CHAR8 *p = btxt; *p; p++) {
        if (*p == '\n') { has_nl = TRUE; break; }
    }
    if (has_nl || str_len(btxt) > 160) mw = 68;
    if (title && str_len(title) + 8 > mw) mw = str_len(title) + 8;
    if (mw > gUiCols - 4) mw = gUiCols - 4;
    if (mw < 20) mw = 20;

    UINTN max_lines = (gUiRows > 9) ? (gUiRows - 9) : 4;
    UINTN lines = ui_count_wrapped_lines(mw - 6, btxt);
    if (lines < 6) lines = 6;
    if (lines > max_lines) lines = max_lines;

    UINTN mh = lines + 5;
    UINTN mx = (gUiCols - mw) / 2;
    UINTN my = (gUiRows - mh) / 2;
    UINT8 fill = is_warning ? gTheme.warn_attr : gTheme.modal_attr;
    UINT8 brd  = is_warning ? gTheme.warn_attr : gTheme.modal_border_attr;

    memcpy(gBackBuf, gModalSaveBuf, sizeof(gBackBuf));
    ui_draw_box(mx, my, mw, mh, brd, fill, TRUE);
    if (title) {
        UINTN tlen = str_len(title);
        UINTN tx = mx + ((mw > tlen + 4) ? (mw - tlen - 4) / 2 : 1);
        ui_printf(tx, my, brd, "[ %s ]", title);
    }
    ui_draw_wrapped(mx + 3, my + 2, mw - 6, lines, btxt, fill);
    ui_puts(mx + (mw - 6) / 2, my + mh - 2, "[ OK ]", gTheme.modal_sel_attr);
    ui_present();

    for (;;) {
        EFI_INPUT_KEY k;
        wait_key_blocking(&k);
        if (k.UnicodeChar == L'\r' || k.UnicodeChar == L'\n' ||
            k.UnicodeChar == L' '  || k.ScanCode == SCAN_ESC || k.UnicodeChar == 0x1B) {
            break;
        }
    }
    modal_restore();
}

INTN ui_select_modal(const CHAR8 *title, const CHAR8 *const *options, UINTN count, UINTN current_idx) {
    if (!options || count == 0) return -1;
    modal_save();

    UINTN max_olen = title ? str_len(title) + 6 : 16;
    for (UINTN i = 0; i < count; i++) {
        UINTN l = str_len(options[i]) + 6;
        if (l > max_olen) max_olen = l;
    }
    UINTN mw = max_olen + 4;
    if (mw < 30) mw = 30;
    if (mw > gUiCols - 6) mw = gUiCols - 6;

    UINTN vis = count;
    if (vis > gUiRows - 8) vis = gUiRows - 8;
    UINTN mh = vis + 4;
    UINTN mx = (gUiCols - mw) / 2;
    UINTN my = (gUiRows - mh) / 2;

    UINTN sel = (current_idx < count) ? current_idx : 0;
    UINTN scroll = 0;

    for (;;) {
        if (sel < scroll) scroll = sel;
        if (sel >= scroll + vis) scroll = sel - vis + 1;

        memcpy(gBackBuf, gModalSaveBuf, sizeof(gBackBuf));
        ui_draw_box(mx, my, mw, mh, gTheme.modal_border_attr, gTheme.modal_attr, TRUE);
        if (title) {
            ui_printf(mx + 2, my, gTheme.modal_border_attr, "[ %s ]", title);
        }
        for (UINTN i = 0; i < vis; i++) {
            UINTN idx = scroll + i;
            UINT8 a = (idx == sel) ? gTheme.modal_sel_attr : gTheme.modal_attr;
            ui_hline(mx + 2, my + 2 + i, mw - 4, L' ', a);
            ui_puts_n(mx + 3, my + 2 + i, options[idx], mw - 6, a);
        }
        ui_present();

        EFI_INPUT_KEY k;
        wait_key_blocking(&k);
        if (k.ScanCode == SCAN_UP || k.UnicodeChar == L'-' || k.ScanCode == SCAN_F5) {
            sel = (sel > 0) ? (sel - 1) : (count - 1);
        } else if (k.ScanCode == SCAN_DOWN || k.UnicodeChar == L'+' || k.UnicodeChar == L'=' || k.ScanCode == SCAN_F6) {
            sel = (sel + 1 < count) ? (sel + 1) : 0;
        } else if (k.ScanCode == SCAN_PAGE_UP) {
            sel = (sel > vis) ? (sel - vis) : 0;
        } else if (k.ScanCode == SCAN_PAGE_DOWN) {
            sel = (sel + vis < count) ? (sel + vis) : (count - 1);
        } else if (k.ScanCode == SCAN_HOME) {
            sel = 0;
        } else if (k.ScanCode == SCAN_END) {
            sel = count - 1;
        } else if (k.UnicodeChar == L'\r' || k.UnicodeChar == L'\n') {
            modal_restore();
            return (INTN)sel;
        } else if (k.ScanCode == SCAN_ESC || k.UnicodeChar == 0x1B) {
            modal_restore();
            return -1;
        }
    }
}

INTN ui_pick_option_modal(
    const CHAR8 *setting_title,
    const CHAR8 *const *options,
    UINTN count,
    UINTN current_idx,
    UINTN initial_sel
) {
    if (!options || count == 0) return -1;
    modal_save();

    const CHAR8 *cur_name = (current_idx < count && options[current_idx]) ? options[current_idx] : "Custom";
    CHAR8 hdr_title[72];
    snprintf_ascii(hdr_title, sizeof(hdr_title), "Options: %s", setting_title ? setting_title : "Setting");

    UINTN max_olen = str_len(hdr_title) + 6;
    UINTN sub_len = str_len(cur_name) + 26;
    if (sub_len > max_olen) max_olen = sub_len;

    for (UINTN i = 0; i < count; i++) {
        UINTN l = str_len(options[i]) + 18;
        if (l > max_olen) max_olen = l;
    }
    if (max_olen < 54) max_olen = 54;

    UINTN mw = max_olen + 4;
    if (mw > gUiCols - 4) mw = gUiCols - 4;

    UINTN vis = count;
    if (vis > gUiRows - 10) vis = gUiRows - 10;
    if (vis == 0) vis = 1;
    UINTN mh = vis + 6;
    UINTN mx = (gUiCols - mw) / 2;
    UINTN my = (gUiRows - mh) / 2;

    UINTN sel = (initial_sel < count) ? initial_sel : ((current_idx < count) ? current_idx : 0);
    UINTN scroll = 0;

    for (;;) {
        if (sel < scroll) scroll = sel;
        if (sel >= scroll + vis) scroll = sel - vis + 1;

        memcpy(gBackBuf, gModalSaveBuf, sizeof(gBackBuf));
        ui_draw_box(mx, my, mw, mh, gTheme.modal_border_attr, gTheme.modal_attr, TRUE);
        ui_printf(mx + 2, my, gTheme.modal_border_attr, "[ %s ]", hdr_title);

        CHAR8 cur_line[96];
        snprintf_ascii(cur_line, sizeof(cur_line), "Current: [%s] - Choose new value:", cur_name);
        ui_puts_n(mx + 3, my + 1, cur_line, mw - 6, gTheme.modal_border_attr);
        ui_hline(mx + 1, my + 2, mw - 2, gBox.hline, gTheme.modal_border_attr);

        for (UINTN i = 0; i < vis; i++) {
            UINTN idx = scroll + i;
            BOOLEAN is_cur = (idx == current_idx);
            UINT8 a = (idx == sel) ? gTheme.modal_sel_attr : gTheme.modal_attr;
            ui_hline(mx + 2, my + 3 + i, mw - 4, L' ', a);

            CHAR8 row_txt[96];
            snprintf_ascii(row_txt, sizeof(row_txt), "%s %s%s",
                           is_cur ? "(*)" : "( )",
                           options[idx],
                           is_cur ? "  [Current]" : "");
            ui_puts_n(mx + 3, my + 3 + i, row_txt, mw - 6, a);
        }

        ui_hline(mx + 1, my + mh - 2, mw - 2, gBox.hline, gTheme.modal_border_attr);
        ui_puts_n(mx + 3, my + mh - 1, "[Up/Dn/+/-: Select]  [Enter: Apply]  [ESC: Cancel]",
                  mw - 6, gTheme.modal_border_attr);
        ui_present();

        EFI_INPUT_KEY k;
        wait_key_blocking(&k);
        if (k.ScanCode == SCAN_UP || k.UnicodeChar == L'-' || k.ScanCode == SCAN_F5) {
            sel = (sel > 0) ? (sel - 1) : (count - 1);
        } else if (k.ScanCode == SCAN_DOWN || k.UnicodeChar == L'+' || k.UnicodeChar == L'=' ||
                   k.UnicodeChar == L' ' || k.ScanCode == SCAN_F6) {
            sel = (sel + 1 < count) ? (sel + 1) : 0;
        } else if (k.ScanCode == SCAN_PAGE_UP) {
            sel = (sel > vis) ? (sel - vis) : 0;
        } else if (k.ScanCode == SCAN_PAGE_DOWN) {
            sel = (sel + vis < count) ? (sel + vis) : (count - 1);
        } else if (k.ScanCode == SCAN_HOME) {
            sel = 0;
        } else if (k.ScanCode == SCAN_END) {
            sel = count - 1;
        } else if (k.UnicodeChar == L'\r' || k.UnicodeChar == L'\n') {
            modal_restore();
            return (INTN)sel;
        } else if (k.ScanCode == SCAN_ESC || k.UnicodeChar == 0x1B) {
            modal_restore();
            return -1;
        }
    }
}

BOOLEAN ui_input_modal(
    const CHAR8 *title,
    const CHAR8 *prompt,
    const CHAR8 *initial,
    CHAR8 *out_buf,
    UINTN max_len,
    BOOLEAN hex_only
) {
    if (!out_buf || max_len < 2) return FALSE;
    modal_save();

    CHAR8 buf[128];
    UINTN cap = (max_len < sizeof(buf)) ? max_len : sizeof(buf);
    str_cpy(buf, initial ? initial : "", cap);
    UINTN len = str_len(buf);
    UINTN cur = len;

    UINTN mw = 60;
    if (mw > gUiCols - 4) mw = gUiCols - 4;
    UINTN mh = 9;
    UINTN mx = (gUiCols - mw) / 2;
    UINTN my = (gUiRows - mh) / 2;
    UINTN field_w = mw - 6;

    for (;;) {
        memcpy(gBackBuf, gModalSaveBuf, sizeof(gBackBuf));
        ui_draw_box(mx, my, mw, mh, gTheme.modal_border_attr, gTheme.modal_attr, TRUE);
        if (title) {
            ui_printf(mx + 2, my, gTheme.modal_border_attr, "[ %s ]", title);
        }
        if (prompt) {
            ui_puts_n(mx + 3, my + 2, prompt, field_w, gTheme.modal_attr);
        }

        /* Input Field Box */
        ui_hline(mx + 3, my + 4, field_w, L' ', gTheme.modal_sel_attr);
        UINTN view_off = 0;
        if (cur >= field_w - 1) view_off = cur - (field_w - 2);
        ui_puts_n(mx + 3, my + 4, buf + view_off, field_w - 1, gTheme.modal_sel_attr);

        /* Highlight visual cursor cell inside input field */
        UINTN cx = mx + 3 + (cur - view_off);
        CHAR16 cch = (cur < len) ? (CHAR16)(UINT8)buf[cur] : L'_';
        ui_putc(cx, my + 4, cch, EFI_TEXT_ATTR(EFI_YELLOW, EFI_BACKGROUND_BLACK));

        ui_puts_n(mx + 3, my + 6, "Enter: Confirm   ESC: Cancel   Bksp/Del: Erase", field_w, gTheme.modal_attr);
        ui_present();

        EFI_INPUT_KEY k;
        wait_key_blocking(&k);
        if (k.ScanCode == SCAN_ESC || k.UnicodeChar == 0x1B) {
            modal_restore();
            return FALSE;
        } else if (k.UnicodeChar == L'\r' || k.UnicodeChar == L'\n') {
            str_cpy(out_buf, buf, max_len);
            modal_restore();
            return TRUE;
        } else if (k.ScanCode == SCAN_LEFT) {
            if (cur > 0) cur--;
        } else if (k.ScanCode == SCAN_RIGHT) {
            if (cur < len) cur++;
        } else if (k.ScanCode == SCAN_HOME) {
            cur = 0;
        } else if (k.ScanCode == SCAN_END) {
            cur = len;
        } else if (k.UnicodeChar == 0x08) { /* Backspace */
            if (cur > 0) {
                memmove(buf + cur - 1, buf + cur, len - cur + 1);
                cur--;
                len--;
            }
        } else if (k.ScanCode == SCAN_DELETE) {
            if (cur < len) {
                memmove(buf + cur, buf + cur + 1, len - cur);
                len--;
            }
        } else if (k.UnicodeChar >= 0x20 && k.UnicodeChar <= 0x7E) {
            CHAR8 c = (CHAR8)k.UnicodeChar;
            BOOLEAN ok = TRUE;
            if (hex_only) {
                ok = ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F') || c == 'x' || c == 'X' || c == ' ');
            }
            if (ok && len + 1 < cap) {
                memmove(buf + cur + 1, buf + cur, len - cur + 1);
                buf[cur] = c;
                cur++;
                len++;
            }
        }
    }
}

VOID ui_general_help_modal(VOID) {
    const CHAR8 *help_txt =
        "Oh my EFI! v" OHMYEFI_VERSION " - Copyright (C) 2026 blueskychan-dev\n"
        "  Left / Right (or [ / ]) : Switch Setup Screen Tabs\n"
        "  Up / Down / PgUp / PgDn : Move Item Highlight / Scroll\n"
        "  Enter / + / -           : Show Available Options & Change Value\n"
        "  Ins / Del (on Boot Tab) : Add New / Delete UEFI Boot#### Entry\n"
        "  F1 (or ?)               : Show This General Help Dialog\n"
        "  F9                      : Load Optimized Default Settings\n"
        "  F10 (or Ctrl+S)         : Save Changes to NVRAM & Exit\n"
        "  F12                     : EFI Dump (Save Report/HII/ACPI/Vars to Disk)\n"
        "  ESC                     : Return from Submenu / Exit Prompt";

    modal_save();
    UINTN mw = 70;
    if (mw > gUiCols - 4) mw = gUiCols - 4;
    UINTN mh = 16;
    UINTN mx = (gUiCols - mw) / 2;
    UINTN my = (gUiRows - mh) / 2;

    memcpy(gBackBuf, gModalSaveBuf, sizeof(gBackBuf));
    ui_draw_box(mx, my, mw, mh, gTheme.modal_border_attr, gTheme.modal_attr, TRUE);
    ui_puts(mx + (mw - 18) / 2, my, "[ General Help ]", gTheme.modal_border_attr);
    ui_draw_wrapped(mx + 3, my + 2, mw - 6, mh - 5, help_txt, gTheme.modal_attr);
    ui_puts(mx + (mw - 6) / 2, my + mh - 2, "[ OK ]", gTheme.modal_sel_attr);
    ui_present();

    for (;;) {
        EFI_INPUT_KEY k;
        wait_key_blocking(&k);
        if (k.UnicodeChar == L'\r' || k.UnicodeChar == L'\n' ||
            k.UnicodeChar == L' '  || k.ScanCode == SCAN_ESC || k.UnicodeChar == 0x1B ||
            k.ScanCode == SCAN_F1) {
            break;
        }
    }
    modal_restore();
}
