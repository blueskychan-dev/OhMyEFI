#ifndef EFI_SETUP_DUMP_H
#define EFI_SETUP_DUMP_H

#include "efi.h"

/*
 * Dump all firmware, hardware, HII/IFR packages, decoded feature-unlock offsets,
 * SMBIOS, ACPI (.aml), PCI 256B config spaces, Memory Map, and NVRAM variables
 * into the same directory that booted this .efi binary (with fallback to first
 * writable EFI volume if boot media is read-only).
 */
BOOLEAN dump_everything_to_boot_dir(CHAR8 *summary_out, UINTN max_summary);
VOID    dump_run_interactive_modal(VOID);

#endif /* EFI_SETUP_DUMP_H */
