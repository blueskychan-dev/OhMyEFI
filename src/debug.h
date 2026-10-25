#ifndef EFI_SETUP_DEBUG_H
#define EFI_SETUP_DEBUG_H

#include "efi.h"

/* Standalone modal/fullscreen editors reusable from MemScan, Advanced, and Debug */
VOID debug_open_hex_editor(UINT64 initial_addr, const CHAR8 *title_hint);
VOID debug_open_var_editor(UINTN var_idx);
VOID debug_open_pci_config_editor(UINTN pci_idx);

/* Debug Tab state & handlers */
VOID    debug_init(VOID);
VOID    debug_draw_tab(VOID);
BOOLEAN debug_handle_key(const EFI_INPUT_KEY *k);

#endif /* EFI_SETUP_DEBUG_H */
