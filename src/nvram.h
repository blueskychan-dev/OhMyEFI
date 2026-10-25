#ifndef EFI_SETUP_NVRAM_H
#define EFI_SETUP_NVRAM_H

#include "efi.h"

#define NVRAM_MAX_VARS         512
#define NVRAM_MAX_BOOT_ENTRIES 32
#define NVRAM_MAX_EFI_LOADERS  32

typedef struct {
    CHAR16   name_w[64];
    CHAR8    name[64];
    EFI_GUID guid;
    UINT32   attributes;
    UINTN    data_size;
    UINT8    preview[24];
    CHAR8    preview_str[36];
    BOOLEAN  is_writable_hint;
} NVRAM_VAR_ENTRY;

typedef struct {
    UINT16  boot_num;
    UINT32  attributes;
    BOOLEAN active;
    BOOLEAN in_boot_order;
    BOOLEAN modified_attr;
    CHAR8   description[56];
    CHAR8   file_path_str[72];
} BOOT_ENTRY_ITEM;

typedef struct {
    EFI_HANDLE fs_handle;
    CHAR16     path_w[128];
    CHAR8      path_ascii[96];
    CHAR8      label[64];
} DISCOVERED_EFI_LOADER;

/* Persistent Oh my EFI! Setup Configuration Stored in Real NVRAM */
#define SETUP_CFG_MAGIC 0x2011CF62U

typedef struct {
    UINT32  magic;
    UINT8   theme_idx;
    INT16   preferred_con_mode;
    UINT8   cpu_virtualization; /* 0=Disabled, 1=Enabled */
    UINT8   cpu_hyperthreading; /* 0=Disabled, 1=Enabled */
    UINT8   cpu_cstates;        /* 0=Disabled, 1=Auto, 2=Enabled */
    UINT8   cpu_turbo;          /* 0=Disabled, 1=Enabled */
    UINT8   sata_mode;          /* 0=IDE, 1=AHCI, 2=RAID */
    UINT8   fast_boot;          /* 0=Disabled, 1=Enabled */
    UINT8   quiet_boot;         /* 0=Disabled, 1=Enabled */
    UINT8   numlock_boot;       /* 0=Off, 1=On */
    UINT8   network_pxe;        /* 0=Disabled, 1=IPv4 PXE, 2=IPv6 PXE */
    UINT8   usb_legacy;         /* 0=Disabled, 1=Enabled, 2=Auto */
    UINT8   acpi_s3_sleep;      /* 0=Disabled, 1=S3 STR */
    UINT8   primary_display;    /* 0=Auto, 1=Integrated iGPU, 2=Discrete PCIe GPU */
    UINT8   igd_dvmt_prealloc;  /* 0=32MB, 1=64MB, 2=96MB, 3=128MB, 4=256MB, 5=512MB */
    UINT8   pcie_aspm_policy;   /* 0=Disabled, 1=L0s, 2=L1, 3=L0s+L1, 4=OS Controlled */
    UINT8   above_4g_decode;    /* 0=Disabled, 1=Enabled */
    UINT8   has_supervisor_pw;
    UINT32  supervisor_pw_hash;
} PACKED SETUP_UTILITY_CONFIG;

typedef struct {
    /* Persistent Setup Config */
    SETUP_UTILITY_CONFIG cfg;
    BOOLEAN              cfg_dirty;

    /* Real UEFI Global Boot Variables */
    UINT16               boot_timeout;
    UINT16               boot_current;
    BOOLEAN              has_boot_current;
    BOOLEAN              timeout_dirty;
    BOOLEAN              boot_order_dirty;
    UINTN                boot_count;
    BOOT_ENTRY_ITEM      boot_entries[NVRAM_MAX_BOOT_ENTRIES];

    /* OS Indications (Boot to Firmware UI) */
    UINT64               os_indications_sup;
    UINT64               os_indications;
    BOOLEAN              os_indications_dirty;

    /* Security Status (Read-Only Hardware Telemetry) */
    BOOLEAN              secure_boot_enabled;
    BOOLEAN              setup_mode_enabled;
    BOOLEAN              pk_present;
    BOOLEAN              kek_present;
    BOOLEAN              db_present;
    BOOLEAN              dbx_present;

    /* Apple / Intel Mac NVRAM Variables */
    BOOLEAN              apple_vars_found;
    BOOLEAN              apple_boot_args_dirty;
    CHAR8                apple_boot_args[96];
    BOOLEAN              apple_csr_present;
    BOOLEAN              apple_csr_dirty;
    UINT32               apple_csr_config;
    BOOLEAN              apple_vol_present;
    BOOLEAN              apple_vol_dirty;
    UINT8                apple_audio_vol;

    /* Apple Dual-GPU Mux Preference (FA4CE28D-B62F-4C99-9CC3-6815686E30F9:gpu-power-prefs) */
    BOOLEAN              apple_gpu_present;
    BOOLEAN              apple_gpu_dirty;
    UINT8                apple_gpu_mode; /* 0=Auto(Unset), 1=Force Intel iGPU, 2=Discrete/Dynamic */

    /* Staged Hardware RTC Date/Time Edit */
    BOOLEAN              rtc_dirty;
    EFI_TIME             staged_rtc;

    /* Discovered .efi OS Bootloaders on Mounted Volumes */
    UINTN                loader_count;
    DISCOVERED_EFI_LOADER loaders[NVRAM_MAX_EFI_LOADERS];

    /* NVRAM Storage Info (UEFI 2.0+) */
    BOOLEAN              storage_info_valid;
    UINT64               max_storage_bytes;
    UINT64               rem_storage_bytes;
    UINT64               max_var_bytes;
} SETUP_LIVE_STATE;

extern SETUP_LIVE_STATE gSetup;
extern UINTN            gVarCount;
extern NVRAM_VAR_ENTRY *gVarList;

/* Initialize, Load, Stage, Save, Defaults */
VOID    nvram_init_state(VOID);
VOID    nvram_reload_boot_entries(VOID);
VOID    nvram_load_optimized_defaults(VOID);
UINTN   nvram_pending_changes_count(VOID);
BOOLEAN nvram_commit_staged_changes(CHAR8 *status_msg, UINTN max_msg);

/* Password helper */
UINT32  nvram_hash_password(const CHAR8 *pw);

/* Enumerate all NVRAM variables for Debug & MemScan */
VOID    nvram_enumerate_all(VOID);

/* Direct Variable Read / Write / Delete */
EFI_STATUS nvram_read_var(const CHAR16 *name_w, EFI_GUID *guid, UINT32 *attrs_out, UINTN *size_out, UINT8 **data_out);
EFI_STATUS nvram_write_var(const CHAR16 *name_w, EFI_GUID *guid, UINT32 attrs, UINTN size, const VOID *data);
EFI_STATUS nvram_delete_var(const CHAR16 *name_w, EFI_GUID *guid);

/* Boot Entry Add / Remove & Interactive File Browser */
BOOLEAN nvram_browse_efi_file_interactive(
    EFI_HANDLE *out_fs,
    CHAR16 *out_path_w,
    UINTN max_wchars,
    CHAR8 *out_default_label,
    UINTN max_label
);
BOOLEAN nvram_add_boot_entry(
    EFI_HANDLE fs_handle,
    const CHAR16 *path_w,
    const CHAR8 *description_ascii,
    BOOLEAN place_first,
    UINT16 *out_boot_num,
    CHAR8 *err_out,
    UINTN max_err
);
BOOLEAN nvram_delete_boot_entry(
    UINTN boot_idx,
    CHAR8 *err_out,
    UINTN max_err
);

/* Bootloader Discovery & Zero-Reset Chainloading (Preserves Temp Spoofs & Live MSR/PCI Tweaks!) */
VOID       nvram_scan_efi_bootloaders(VOID);
EFI_STATUS nvram_chainload_efi(EFI_HANDLE fs_handle, const CHAR16 *path_w);
EFI_STATUS nvram_chainload_boot_entry(UINT16 boot_num, CHAR8 *err_out, UINTN max_err);
VOID       nvram_boot_os_preserve_live_modal(const CHAR8 *modal_title);
EFI_STATUS nvram_set_boot_next(UINT16 boot_num);

#endif /* EFI_SETUP_NVRAM_H */
