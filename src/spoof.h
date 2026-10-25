#ifndef EFI_SETUP_SPOOF_H
#define EFI_SETUP_SPOOF_H

#include "efi.h"

/*
 * Oh my EFI! v0.5.0 — Temporary Hardware, Vendor & Device Identity Spoofer
 *
 * IMPORTANT: All spoofs applied here live strictly in RAM (relocated EfiACPIMemoryNVS
 * SMBIOS 2.1/3.0 tables, live ACPI SDT headers, and live PCI config registers).
 * They are 100% TEMPORARY: a Cold/Warm Reset or Power Off wipes them completely.
 * Users MUST boot/chainload their OS directly from the Security page for spoofs to apply!
 */

extern BOOLEAN gSpoofActive;
extern UINTN   gSpoofEditCount;

VOID    spoof_init(VOID);
BOOLEAN spoof_restore_factory_identity(CHAR8 *msg_out, UINTN max_msg);
VOID    spoof_draw_security_tab(const CHAR8 *footer_status, UINTN *io_cur, UINTN *io_scroll);
BOOLEAN spoof_handle_security_key(const EFI_INPUT_KEY *k, UINTN *io_cur);

#endif /* EFI_SETUP_SPOOF_H */
