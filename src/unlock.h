#ifndef EFI_SETUP_UNLOCK_H
#define EFI_SETUP_UNLOCK_H

#include "efi.h"

#define UNLOCK_FIVR_PLANE_COUNT 5

typedef struct {
    BOOLEAN supported;
    BOOLEAN plundervolt_locked;
    BOOLEAN plane_valid[UNLOCK_FIVR_PLANE_COUNT];
    INT32   plane_mv[UNLOCK_FIVR_PLANE_COUNT];
} UNLOCK_FIVR_INFO;

typedef struct {
    /* Intel ME / CSME (PCI 00:16.0 HECI1 + Intel Boot Guard) */
    BOOLEAN me_present;
    BOOLEAN me_enumerated_pci;
    INTN    me_pci_idx;
    UINT8   me_bus;
    UINT8   me_dev;
    UINT8   me_func;
    UINT16  me_vid;
    UINT16  me_did;
    UINT16  me_cmd;
    UINT64  heci_bar0;
    BOOLEAN heci_mmio_ok;
    UINT32  hfsts[6];          /* 0x40, 0x48, 0x60, 0x64, 0x68, 0x6C */
    UINT8   working_state;     /* HFSTS1[3:0] */
    BOOLEAN mfg_mode;          /* HFSTS1[4]   */
    BOOLEAN fpt_bad;           /* HFSTS1[5]   */
    UINT8   op_state;          /* HFSTS1[8:6] */
    BOOLEAN fw_init_done;      /* HFSTS1[9]   */
    UINT8   error_code;        /* HFSTS1[15:12] */
    UINT8   op_mode;           /* HFSTS1[19:16] */
    CHAR8   working_state_str[28];
    CHAR8   op_mode_str[32];

    BOOLEAN boot_guard_valid;
    BOOLEAN boot_guard_verified;
    BOOLEAN boot_guard_measured;
    BOOLEAN boot_guard_fpf_locked;

    BOOLEAN fw_ver_valid;
    UINT16  fw_major;
    UINT16  fw_minor;
    UINT16  fw_hotfix;
    UINT16  fw_build;

    BOOLEAN hmrfpo_queried;
    UINT8   hmrfpo_status;     /* 0=Locked/Dis, 1=Locked, 2=Enabled/Active */

    /* AMD Platform Security Processor (PSP / CCP) + SMN / SMU / IOMMU */
    BOOLEAN amd_psp_present;
    INTN    amd_psp_pci_idx;
    UINT8   psp_bus;
    UINT8   psp_dev;
    UINT8   psp_func;
    UINT16  psp_vid;
    UINT16  psp_did;
    UINT16  psp_cmd;
    UINT64  psp_bar;

    BOOLEAN amd_smn_ok;
    UINT16  amd_root_did;
    BOOLEAN amd_iommu_present;
    UINT16  amd_iommu_did;
    BOOLEAN amd_tctl_valid;
    INT32   amd_tctl_c;
    BOOLEAN smu_ver_valid;
    UINT8   smu_major;
    UINT8   smu_minor;
    UINT8   smu_patch;
} UNLOCK_ME_PSP_INFO;

typedef struct {
    BOOLEAN present;
    BOOLEAN is_amd_fch;
    BOOLEAN is_pch_1f5;
    UINT8   bus;
    UINT8   dev;
    UINT8   func;
    UINT16  vid;
    UINT16  did;
    CHAR8   controller_name[36];

    BOOLEAN bios_cntl_valid;
    UINT8   bios_cntl;         /* Offset 0xDC */
    BOOLEAN bioswe;            /* Bit 0: BIOS Write Enable */
    BOOLEAN ble;               /* Bit 1: BIOS Lock Enable (SMM Trap) */
    BOOLEAN eiss;              /* Bit 5: Enable InSMM.STS / SMM_BWP */

    BOOLEAN spibar_valid;
    UINT64  spibar_phys;
    UINT16  hsfsts;            /* SPIBAR + 0x04 */
    BOOLEAN flockdn;           /* Bit 15: Flash Configuration Lock-Down */
    BOOLEAN fdv;               /* Bit 14: Flash Descriptor Valid */
    BOOLEAN fdopss;            /* Bit 13: 0=Override Jumper Active, 1=Normal */
    UINT32  frap;              /* SPIBAR + 0x50 */
    UINT8   brra;              /* Host CPU Read Access  [Desc/BIOS/ME/GbE] */
    UINT8   brwa;              /* Host CPU Write Access [Desc/BIOS/ME/GbE] */
    UINT32  fpr[5];            /* FPR0..FPR4 Flash Protected Ranges */
    UINT8   fpr_wpe_count;     /* Active write-protected ranges */
} UNLOCK_SPI_INFO;

extern UNLOCK_FIVR_INFO   gUnlockFivr;
extern UNLOCK_ME_PSP_INFO gUnlockMePsp;
extern UNLOCK_SPI_INFO    gUnlockSpi;

/* Extract hidden Setup HII PackageLists from EFI_FIRMWARE_VOLUME2_PROTOCOL PE32 .rsrc / RAW sections */
VOID unlock_append_fv_hii_packages(UINT8 **io_buf, UINTN *io_size, UINTN *out_added_lists);

/* Probe / Refresh FIVR MSR 0x150, Intel ME / AMD PSP, and PCH/ICH9/FCH SPI Flash Locks */
VOID unlock_refresh_all(BOOLEAN deep_probe);

/* Intel FIVR Live Voltage Offset Controls (MSR 0x150) */
BOOLEAN unlock_fivr_set_plane_mv(UINT8 plane, INT32 target_mv, CHAR8 *err_out, UINTN max_err);
VOID    unlock_edit_fivr_plane_interactive(UINT8 plane);
VOID    unlock_edit_fivr_core_cache_sync_interactive(VOID);

/* Built-in datasone/grub-mod-setup_var (setup_var / setup_var2 / setup_var_3 / setup_var_vs / setup_var_cv) */
VOID unlock_open_setup_var_modal(VOID);

/* Dortania OpenCore MSR 0xE2 (CFG Lock) All-Core Consistency Verifier & Unlocker */
VOID unlock_verify_msr_e2_all_cores_modal(VOID);

/* Persistent Startup Hardware Auto-Apply Profile (OhMyEfiAutoPatch in NVRAM) */
BOOLEAN unlock_has_startup_autopatch(VOID);
BOOLEAN unlock_apply_startup_autopatch(CHAR8 *status_out, UINTN max_status);
VOID    unlock_manage_autopatch_modal(VOID);

/* Interactive Advanced -> Unlock Hub Submenu (TAB_ADVANCED == 1) */
VOID    unlock_draw_submenu(UINTN tab_idx, const CHAR8 *footer_status, UINTN *io_cur, UINTN *io_scroll);
BOOLEAN unlock_handle_submenu_key(const EFI_INPUT_KEY *k, UINTN *io_cur, UINTN *io_scroll);

/* Append ME/PSP, SPI/BIOS_CNTL & FIVR telemetry to F12 EFI Dump Report */
VOID unlock_append_report_section(VOID (*put_fn)(VOID *ctx, const CHAR8 *s), VOID *ctx);

#endif /* EFI_SETUP_UNLOCK_H */
