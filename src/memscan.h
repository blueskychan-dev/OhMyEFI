#ifndef EFI_SETUP_MEMSCAN_H
#define EFI_SETUP_MEMSCAN_H

#include "efi.h"

#define MEMSCAN_MAX_TARGETS 96
#define MEMSCAN_MAX_HITS    512

typedef enum {
    TARGET_KIND_SMBIOS_STR = 0,
    TARGET_KIND_SMBIOS_TBL = 1,
    TARGET_KIND_ACPI_TBL   = 2,
    TARGET_KIND_ACPI_NVS   = 3,
    TARGET_KIND_RT_DATA    = 4,
    TARGET_KIND_NVRAM_VAR  = 5
} MEMSCAN_TARGET_KIND;

typedef struct {
    MEMSCAN_TARGET_KIND kind;
    CHAR8               category[14];
    CHAR8               name[32];
    UINT64              phys_addr;
    UINT64              length;
    UINTN               aux_index; /* e.g. ACPI table idx or NVRAM var idx */
    BOOLEAN             writable;
    CHAR8               detail[48];
} MEMSCAN_MOD_TARGET;

typedef enum {
    SCAN_TYPE_ASCII  = 0,
    SCAN_TYPE_UTF16  = 1,
    SCAN_TYPE_HEX    = 2,
    SCAN_TYPE_UINT8  = 3,
    SCAN_TYPE_UINT16 = 4,
    SCAN_TYPE_UINT32 = 5,
    SCAN_TYPE_UINT64 = 6,
    SCAN_TYPE_COUNT  = 7
} MEMSCAN_DATA_TYPE;

typedef enum {
    SCAN_SCOPE_FW_PERSIST = 0, /* ACPI Reclaim + ACPI NVS + Runtime Data */
    SCAN_SCOPE_ACPI_ONLY  = 1, /* ACPI Reclaim + ACPI NVS */
    SCAN_SCOPE_FW_ALL     = 2, /* ACPI + Runtime + BootServices Data */
    SCAN_SCOPE_ALL_RAM    = 3, /* All safe RAM incl. Conventional (excl. MMIO/Reserved) */
    SCAN_SCOPE_COUNT      = 4
} MEMSCAN_SCOPE;

typedef struct {
    UINT64  addr;
    UINT32  mem_type;
    BOOLEAN writable;
    UINT8   prev_bytes[8];
    UINT8   cur_bytes[8];
} MEMSCAN_HIT;

typedef struct {
    /* Auto-discovered modifiable firmware targets */
    UINTN              target_count;
    MEMSCAN_MOD_TARGET targets[MEMSCAN_MAX_TARGETS];

    /* Custom value/pattern scanner state */
    MEMSCAN_DATA_TYPE  data_type;
    MEMSCAN_SCOPE      scope;
    CHAR8              last_query[64];
    UINT8              pattern[64];
    UINTN              pattern_len;
    UINTN              hit_count;
    UINTN              total_matches_found;
    UINT64             bytes_scanned;
    MEMSCAN_HIT       *hits; /* Allocated from pool (skipped during self-scan) */
    UINTN              hits_alloc_size;
} MEMSCAN_STATE;

extern MEMSCAN_STATE gMemScan;

VOID memscan_init(VOID);
VOID memscan_discover_targets(VOID);

/* Custom scanner operations */
BOOLEAN memscan_run_first_scan(const CHAR8 *query_str, CHAR8 *status_out, UINTN max_status);
BOOLEAN memscan_run_next_exact(const CHAR8 *query_str, CHAR8 *status_out, UINTN max_status);
UINTN   memscan_run_next_diff(BOOLEAN changed_only, CHAR8 *status_out, UINTN max_status);

/* Interactive MemScan Tab Renderer & Input Handler */
VOID memscan_draw_tab(VOID);
BOOLEAN memscan_handle_key(const EFI_INPUT_KEY *k);

#endif /* EFI_SETUP_MEMSCAN_H */
