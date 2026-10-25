#ifndef EFI_SETUP_UI_H
#define EFI_SETUP_UI_H

#include "efi.h"

#define UI_MAX_COLS 160
#define UI_MAX_ROWS 60

#define OHMYEFI_TITLE     "Oh my EFI!"
#define OHMYEFI_VERSION   "0.5.0"
#define OHMYEFI_COPYRIGHT "Version 0.5.0 - Copyright (C) 2026 blueskychan-dev"

/* Color Themes */
#define UI_THEME_APTIO_2011   0
#define UI_THEME_CLASSIC_BLUE 1
#define UI_THEME_HIGH_CONTRAST 2
#define UI_THEME_COUNT        3

typedef struct {
    UINT8 header_attr;
    UINT8 tab_bar_attr;
    UINT8 tab_active_attr;
    UINT8 body_attr;
    UINT8 border_attr;
    UINT8 section_attr;
    UINT8 label_attr;
    UINT8 value_attr;
    UINT8 item_attr;
    UINT8 item_sel_attr;
    UINT8 dim_attr;
    UINT8 dim_sel_attr;
    UINT8 help_title_attr;
    UINT8 help_text_attr;
    UINT8 footer_attr;
    UINT8 modal_attr;
    UINT8 modal_border_attr;
    UINT8 modal_sel_attr;
    UINT8 warn_attr;
    UINT8 shadow_attr;
} UI_PALETTE;

typedef struct {
    INT32 mode_num;
    UINTN cols;
    UINTN rows;
} UI_CONSOLE_MODE_INFO;

#define UI_MAX_CONSOLE_MODES 16

/* Box drawing characters (Unicode or ASCII fallback) */
typedef struct {
    CHAR16 hline;
    CHAR16 vline;
    CHAR16 tl;
    CHAR16 tr;
    CHAR16 bl;
    CHAR16 br;
    CHAR16 tee_t;
    CHAR16 tee_b;
    CHAR16 tee_l;
    CHAR16 tee_r;
    CHAR16 cross;
    CHAR16 arrow_r;
    CHAR16 arrow_u;
    CHAR16 arrow_d;
} UI_BOX_CHARS;

extern UINTN        gUiCols;
extern UINTN        gUiRows;
extern UI_PALETTE   gTheme;
extern UI_BOX_CHARS gBox;
extern UINTN        gConsoleModeCount;
extern UI_CONSOLE_MODE_INFO gConsoleModes[UI_MAX_CONSOLE_MODES];
extern INT32        gCurrentConsoleMode;
extern UINT8        gCurrentThemeIdx;

/* Initialization & Mode Control */
VOID    ui_init(VOID);
VOID    ui_set_theme(UINT8 theme_idx);
BOOLEAN ui_set_console_mode(INT32 mode_num);
VOID    ui_force_redraw(VOID);

/* Backbuffer Drawing Primitives */
VOID ui_clear(UINT8 attr);
VOID ui_fill_rect(UINTN x, UINTN y, UINTN w, UINTN h, CHAR16 ch, UINT8 attr);
VOID ui_putc(UINTN x, UINTN y, CHAR16 ch, UINT8 attr);
VOID ui_puts(UINTN x, UINTN y, const CHAR8 *s, UINT8 attr);
VOID ui_puts_n(UINTN x, UINTN y, const CHAR8 *s, UINTN max_w, UINT8 attr);
VOID ui_wputs_n(UINTN x, UINTN y, const CHAR16 *ws, UINTN max_w, UINT8 attr);
VOID ui_printf(UINTN x, UINTN y, UINT8 attr, const CHAR8 *fmt, ...);
VOID ui_hline(UINTN x, UINTN y, UINTN w, CHAR16 ch, UINT8 attr);
VOID ui_vline(UINTN x, UINTN y, UINTN h, CHAR16 ch, UINT8 attr);
VOID ui_draw_box(UINTN x, UINTN y, UINTN w, UINTN h, UINT8 border_attr, UINT8 fill_attr, BOOLEAN shadow);
VOID ui_draw_wrapped(UINTN x, UINTN y, UINTN w, UINTN max_lines, const CHAR8 *text, UINT8 attr);

/* Flush diff to UEFI SimpleTextOut */
VOID ui_present(VOID);

/* Standard 2011 Setup Frame Chrome */
VOID ui_draw_setup_frame(
    UINTN active_tab,
    const CHAR8 *submenu_title,
    BOOLEAN split_right_panel,
    const CHAR8 *help_title,
    const CHAR8 *help_body,
    const CHAR8 *status_left
);

/* Reusable 2011 BIOS Popups & Modals */
BOOLEAN ui_confirm_modal(const CHAR8 *title, const CHAR8 *question, BOOLEAN default_yes);
VOID    ui_message_modal(const CHAR8 *title, const CHAR8 *body, BOOLEAN is_warning);
INTN    ui_select_modal(const CHAR8 *title, const CHAR8 *const *options, UINTN count, UINTN current_idx);
INTN    ui_pick_option_modal(
    const CHAR8 *setting_title,
    const CHAR8 *const *options,
    UINTN count,
    UINTN current_idx,
    UINTN initial_sel
);
BOOLEAN ui_input_modal(
    const CHAR8 *title,
    const CHAR8 *prompt,
    const CHAR8 *initial,
    CHAR8 *out_buf,
    UINTN max_len,
    BOOLEAN hex_only
);
VOID    ui_general_help_modal(VOID);

#endif /* EFI_SETUP_UI_H */
