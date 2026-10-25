#ifndef EFI_SETUP_HWINFO_H
#define EFI_SETUP_HWINFO_H

#include "efi.h"

#define HW_MAX_DIMMS         16
#define HW_MAX_ACPI_TABLES   32
#define HW_MAX_PCI_DEVS      96
#define HW_MAX_DISKS         24
#define HW_MAX_GOP_MODES     24
#define HW_MAX_HII_STORES    128
#define HW_MAX_HII_QUESTIONS 4096
#define HW_MAX_HII_Q_OPTS    16
#define HW_MAX_GPUS          4

typedef struct {
    CHAR8   locator[24];
    CHAR8   mem_type[12];
    CHAR8   manufacturer[24];
    CHAR8   part_number[24];
    CHAR8   serial[24];
    UINT32  size_mb;
    UINT16  speed_mhz;
    BOOLEAN populated;
} HW_DIMM_INFO;

typedef struct {
    CHAR8   signature[5];
    CHAR8   oem_id[7];
    CHAR8   oem_table_id[9];
    UINT64  phys_addr;
    UINT32  length;
    UINT8   revision;
    BOOLEAN checksum_ok;
    BOOLEAN writable;
} HW_ACPI_TABLE_INFO;

typedef struct {
    EFI_PCI_IO_PROTOCOL *pci_io;
    UINT16  seg;
    UINT8   bus;
    UINT8   dev;
    UINT8   func;
    UINT16  vendor_id;
    UINT16  device_id;
    UINT16  subsys_vendor_id;
    UINT16  subsys_id;
    UINT16  command;
    UINT16  status;
    UINT8   class_code;
    UINT8   subclass;
    UINT8   prog_if;
    UINT8   rev_id;
    UINT32  bar0;
    CHAR8   vendor_name[20];
    CHAR8   class_name[28];

    /* PCIe Capability & Link / Power Controls */
    UINT8   pcie_cap_off;      /* 0 if conventional PCI */
    UINT8   pcie_cap_ver;
    UINT8   pcie_port_type;
    UINT8   pcie_max_speed;    /* 1=2.5GT/s(Gen1)..5=32GT/s(Gen5) */
    UINT8   pcie_max_width;    /* x1..x32 */
    UINT8   pcie_cur_speed;
    UINT8   pcie_cur_width;
    UINT8   pcie_aspm_sup;     /* 0=None, 1=L0s, 2=L1, 3=L0s+L1 */
    UINT8   pcie_aspm_cur;     /* 0=Disabled, 1=L0s, 2=L1, 3=L0s+L1 */
    UINT8   pcie_target_speed; /* Link Control 2 bits 3:0 */
    BOOLEAN pcie_relaxed_ord;  /* Device Control bit 4 */
    UINT8   pcie_max_read_req; /* Device Control bits 14:12 (0=128B..5=4096B) */

    /* GPU VRAM / Aperture & Resizable BAR Telemetry (Class 0x03) */
    UINT64  vram_bar_base;
    UINT64  vram_bar_size;
    BOOLEAN rebar_supported;
    UINT16  rebar_ext_off;       /* ECAM offset of best ReBAR CapReg (+4 = CtlReg) */
    UINT32  rebar_cap_mask;      /* Supported sizes bitmask [31:4] (bit k = 2^(k-4) MB) */
    UINT8   rebar_cur_size_exp;  /* Current size exponent S (2^S MB, e.g. 8=256MB, 14=16GB) */
    UINT8   rebar_max_size_exp;  /* Max supported exponent S */
} HW_PCI_DEV_INFO;

typedef struct {
    UINT32  media_id;
    UINT32  block_size;
    UINT64  total_bytes;
    UINT64  size_mb;
    BOOLEAN removable;
    BOOLEAN read_only;
    BOOLEAN is_partition;
    CHAR8   label[56];
} HW_DISK_INFO;

typedef struct {
    UINT32 mode_num;
    UINT32 width;
    UINT32 height;
} HW_GOP_MODE_INFO;

typedef struct {
    CHAR8    name[36];
    EFI_GUID guid;
    UINT16   varstore_id;
    UINT16   size;
    BOOLEAN  is_efi_varstore;
} HW_HII_VARSTORE_INFO;

/* Decoded Motherboard HII / IFR Question (for Feature Unlock & Live Edit) */
#define HII_QTYPE_ONE_OF   0x05
#define HII_QTYPE_CHECKBOX 0x06
#define HII_QTYPE_NUMERIC  0x07

typedef struct {
    CHAR8  label[40];
    UINT64 value;
} HW_HII_OPTION;

typedef struct {
    UINT8         qtype;
    UINT8         width;         /* 1, 2, 4, or 8 bytes */
    BOOLEAN       is_bitfield;   /* Inside EDKII_IFR_BIT_VARSTORE_GUID (var_offset & bit_width in bits!) */
    UINT8         bit_width;     /* Bit width (1..64) when is_bitfield == TRUE */
    BOOLEAN       read_only;
    BOOLEAN       is_suppressed; /* Wrapped in EFI_IFR_SUPPRESS_IF (Hidden BIOS Option!) */
    BOOLEAN       is_grayout;    /* Wrapped in EFI_IFR_GRAY_OUT_IF / DISABLE_IF */
    UINT16        question_id;
    UINT16        varstore_id;
    UINT16        var_offset;
    INT16         varstore_idx;  /* Index in gHw.hii_varstores, or -1 */
    CHAR8         formset_title[32];
    CHAR8         prompt[52];
    CHAR8         help[96];
    UINT64        min_val;
    UINT64        max_val;
    UINT64        step_val;
    UINT8         opt_count;
    HW_HII_OPTION opts[HW_MAX_HII_Q_OPTS];
} HW_HII_QUESTION;

/* Live Ring-0 CPU MSR Telemetry & Controls (#GP-guarded, Intel + AMD) */
typedef struct {
    BOOLEAN is_intel;
    BOOLEAN is_amd;

    /* Intel Architectural & Model-Specific MSRs */
    BOOLEAN misc_valid;          /* MSR 0x1A0 IA32_MISC_ENABLE */
    UINT64  misc_val;
    BOOLEAN fast_strings;        /* Bit 0 */
    BOOLEAN auto_tcc;            /* Bit 3 */
    BOOLEAN eist_enabled;        /* Bit 16 (SpeedStep) */
    BOOLEAN turbo_hw_avail;      /* CPUID.06H:EAX[1] */
    BOOLEAN turbo_disabled;      /* Bit 38 of 0x1A0 (1=Disabled, 0=Enabled) */

    BOOLEAN power_ctl_valid;     /* MSR 0x1FC MSR_POWER_CTL */
    UINT64  power_ctl_val;
    BOOLEAN bd_prochot;          /* Bit 0 */
    BOOLEAN c1e_enable;          /* Bit 1 */

    BOOLEAN cst_cfg_valid;       /* MSR 0xE2 MSR_PMG_CST_CONFIG_CONTROL */
    UINT64  cst_cfg_val;
    BOOLEAN cfg_locked;          /* Bit 15 (CFG Lock!) */
    UINT8   pkg_cstate_limit;    /* Bits 2:0 */

    BOOLEAN feat_ctl_valid;      /* MSR 0x3A IA32_FEATURE_CONTROL */
    UINT64  feat_ctl_val;
    BOOLEAN vmx_locked;          /* Bit 0 */
    BOOLEAN vmx_outside_smx;     /* Bit 2 */

    BOOLEAN plat_info_valid;     /* MSR 0xCE MSR_PLATFORM_INFO */
    UINT64  plat_info_val;
    UINT8   intel_min_ratio;     /* Bits 47:40 (x100 MHz) */
    UINT8   intel_base_ratio;    /* Bits 15:8  (x100 MHz) */
    BOOLEAN intel_tdp_ratio_unl; /* Bit 28 (Programmable Turbo Ratio Limit) */
    BOOLEAN intel_tdp_pwr_unl;   /* Bit 29 (Programmable TDP Limit) */

    BOOLEAN perf_valid;          /* MSR 0x198 / 0x199 IA32_PERF_STATUS / CTL */
    UINT8   intel_cur_ratio;     /* 0x198 Bits 15:8 */
    UINT8   intel_target_ratio;  /* 0x199 Bits 15:8 */

    BOOLEAN turbo_limit_valid;   /* MSR 0x1AD MSR_TURBO_RATIO_LIMIT */
    UINT64  turbo_limit_val;
    UINT8   intel_turbo_1c;      /* Bits 7:0 */
    UINT8   intel_turbo_allc;    /* Highest core-group ratio */

    BOOLEAN flex_oc_valid;       /* MSR 0x194 MSR_FLEX_RATIO */
    UINT64  flex_oc_val;
    BOOLEAN oc_locked;           /* Bit 20 (OC_LOCK - Overclocking Lock!) */
    BOOLEAN flex_enabled;        /* Bit 16 */
    UINT8   flex_ratio;          /* Bits 15:8 */

    BOOLEAN pkg_pwr_valid;       /* MSR 0x606 + 0x610 RAPL Package Power Limit */
    UINT64  pkg_pwr_val;
    UINT8   rapl_pwr_unit;       /* Bits 3:0 of 0x606 (1 / 2^unit Watts) */
    BOOLEAN pkg_pwr_locked;      /* Bit 63 of 0x610 */
    UINT16  pl1_watts;
    UINT16  pl2_watts;

    /* AMD Zen / Ryzen / Threadripper / EPYC / K10+ MSRs */
    BOOLEAN amd_hwcr_valid;      /* MSR 0xC0010015 MSR_K7_HWCR */
    UINT64  amd_hwcr_val;
    BOOLEAN amd_cpb_disabled;    /* Bit 25 (Core Performance Boost Disable) */
    BOOLEAN amd_smm_locked;      /* Bit 0  (SMMLock) */

    BOOLEAN amd_pstate_valid;    /* MSR 0xC0010061..0xC0010066 Hardware P-States */
    BOOLEAN amd_zen4_5mhz_fid;   /* TRUE on Zen4/Zen5 5MHz 12-bit FID */
    UINT8   amd_cur_pstate;      /* 0xC0010063 active P-state (0..7) */
    UINT8   amd_max_pstate;      /* 0xC0010061 max P-state index */
    UINT64  amd_p0_raw;          /* 0xC0010064 P0 definition */
    UINT32  amd_p0_mhz;          /* Computed P0 Frequency in MHz */
    UINT32  amd_p0_mv;           /* Computed P0 Core Voltage in mV (SVI2) */
    UINT8   amd_p0_vid;          /* Raw 8-bit SVI2 VID */
    UINT32  amd_p1_mhz;          /* 0xC0010065 P1 Frequency in MHz */
    UINT32  amd_p2_mhz;          /* 0xC0010066 P2 Frequency in MHz */

    BOOLEAN amd_vmcr_valid;      /* MSR 0xC0010114 MSR_VM_CR */
    UINT64  amd_vmcr_val;
    BOOLEAN amd_svm_locked;      /* Bit 3 (SVMLock) */
    BOOLEAN amd_svm_disabled;    /* Bit 4 (SVMDIS) */
} HW_CPU_MSR_INFO;

typedef struct {
    /* Firmware & UEFI */
    CHAR8   fw_vendor[48];
    UINT32  fw_revision;
    UINT16  uefi_major;
    UINT16  uefi_minor;
    BOOLEAN is_apple_mac;
    UINT64  image_base;
    UINT64  image_size;

    /* SMBIOS System / Logic Board / BIOS */
    BOOLEAN smbios_present;
    BOOLEAN smbios_is_v3;
    UINT8   smbios_major;
    UINT8   smbios_minor;
    UINT64  smbios_ep_addr;
    UINT64  smbios_table_addr;
    UINT32  smbios_table_size;
    BOOLEAN smbios_writable;

    CHAR8   bios_vendor[48];
    CHAR8   bios_version[48];
    CHAR8   bios_date[24];
    UINT64  bios_ver_ram_addr;
    UINTN   bios_ver_ram_maxlen;

    CHAR8   sys_manufacturer[48];
    CHAR8   sys_product[48];
    CHAR8   sys_version[48];
    CHAR8   sys_serial[48];
    CHAR8   sys_sku[36];
    CHAR8   sys_family[36];
    CHAR8   sys_uuid[40];
    UINT64  sys_serial_ram_addr;
    UINTN   sys_serial_ram_maxlen;
    UINT64  sys_product_ram_addr;
    UINTN   sys_product_ram_maxlen;

    CHAR8   board_manufacturer[48];
    CHAR8   board_product[48];
    CHAR8   board_version[32];
    CHAR8   board_serial[48];
    UINT64  board_serial_ram_addr;
    UINTN   board_serial_ram_maxlen;

    UINT8   chassis_type_code;
    CHAR8   chassis_manufacturer[48];
    CHAR8   chassis_type[28];
    CHAR8   chassis_serial[48];
    CHAR8   chassis_asset_tag[48];

    /* Processor (CPUID + MADT + SMBIOS + MP Services + MSRs) */
    CHAR8   cpu_vendor[16];
    CHAR8   cpu_brand[56];
    CHAR8   cpu_smbios_manufacturer[36];
    CHAR8   cpu_smbios_version[56];
    UINT32  cpu_signature;
    UINT32  cpu_family;
    UINT32  cpu_model;
    UINT32  cpu_stepping;
    UINT32  cpu_cores;
    UINT32  cpu_threads;
    UINT32  cpu_smt_per_core;
    UINT32  cpu_madt_threads;
    UINT32  cpu_mp_threads;
    UINT32  cpu_mp_total_threads;
    UINT32  cpu_smbios_cores;
    UINT32  cpu_smbios_threads;
    UINT32  cpu_max_mhz;
    UINT32  cpu_cur_mhz;
    UINT8   phys_addr_bits;
    UINT8   virt_addr_bits;
    BOOLEAN feat_lm64;
    BOOLEAN feat_vmx;
    BOOLEAN feat_svm;
    BOOLEAN feat_aes;
    BOOLEAN feat_avx;
    BOOLEAN feat_avx2;
    BOOLEAN feat_sse41;
    BOOLEAN feat_sse42;
    BOOLEAN feat_nx;
    BOOLEAN feat_x2apic;
    BOOLEAN feat_hypervisor;
    CHAR8   hypervisor_id[16];
    CHAR8   hypervisor_name[28];
    HW_CPU_MSR_INFO cpu_msr;

    /* Memory Summary */
    UINT64  total_ram_bytes;
    UINT64  usable_ram_bytes;
    UINT64  acpi_ram_bytes;
    UINT64  runtime_ram_bytes;
    UINT64  boot_svcs_bytes;
    UINT64  reserved_ram_bytes;
    UINT64  mmio_bytes;
    UINTN   mem_desc_count;

    UINTN        dimm_count;
    UINTN        dimm_populated_count;
    UINT64       smbios_ram_mb;
    HW_DIMM_INFO dimms[HW_MAX_DIMMS];

    /* ACPI */
    UINT64             acpi_rsdp_addr;
    UINT8              acpi_revision;
    CHAR8              acpi_oem_id[8];
    UINT64             mcfg_ecam_base;
    UINTN              acpi_count;
    HW_ACPI_TABLE_INFO acpi_tables[HW_MAX_ACPI_TABLES];

    /* PCI / PCIe & GPU / VRAM */
    UINTN           pci_count;
    HW_PCI_DEV_INFO pci_devs[HW_MAX_PCI_DEVS];
    UINTN           gpu_count;
    UINTN           gpu_pci_indices[HW_MAX_GPUS];

    /* Intel Host Bridge (00:00.0) GMCH Graphics Control (Stolen VRAM / DVMT) */
    BOOLEAN igd_ggc_present;
    UINTN   igd_host_pci_idx;
    UINT16  igd_ggc_raw;
    BOOLEAN igd_ggc_locked;
    BOOLEAN igd_vga_disable;
    UINT32  igd_stolen_mb;
    UINT32  igd_gtt_mb;

    /* Block Storage */
    UINTN        disk_count;
    HW_DISK_INFO disks[HW_MAX_DISKS];

    /* Graphics (GOP) */
    BOOLEAN          gop_present;
    UINT32           gop_cur_mode;
    UINT32           gop_width;
    UINT32           gop_height;
    UINT64           gop_fb_base;
    UINT64           gop_fb_size;
    CHAR8            gop_format[16];
    UINTN            gop_mode_count;
    HW_GOP_MODE_INFO gop_modes[HW_MAX_GOP_MODES];

    /* Firmware HII / IFR */
    BOOLEAN              hii_present;
    UINTN                hii_raw_bytes;
    UINTN                hii_pkg_list_count;
    UINTN                hii_fv_pkg_count;
    UINTN                hii_formset_count;
    UINTN                hii_varstore_count;
    HW_HII_VARSTORE_INFO hii_varstores[HW_MAX_HII_STORES];
    UINTN                hii_question_cap;
    UINTN                hii_question_count;
    UINTN                hii_hidden_count;
    HW_HII_QUESTION     *hii_questions; /* Pool-allocated array */
} HW_SYSTEM_INFO;

extern HW_SYSTEM_INFO gHw;
extern BOOLEAN        gVolatileHwTweakActive;

VOID    hw_collect_all(VOID);
VOID    hw_refresh_smbios_and_acpi_only(VOID);
VOID    hw_refresh_memory_summary(VOID);
VOID    hw_refresh_acpi_status(VOID);
BOOLEAN hw_acpi_fix_checksum(UINTN table_idx);
BOOLEAN hw_patch_smbios_string_in_ram(UINT64 str_addr, UINTN max_len, const CHAR8 *new_str);
BOOLEAN hw_set_gop_mode(UINT32 mode_num);

/* Live CPU Frequency, Overclock, Lock & All-Core MSR Controls (Intel + AMD) */
VOID    hw_refresh_cpu_msrs(VOID);
BOOLEAN hw_write_cpu_msr_all_cores(UINT32 msr, UINT64 val);
BOOLEAN hw_write_cpu_msr_bit(UINT32 msr, UINT8 bit_idx, BOOLEAN set_one);
BOOLEAN hw_intel_set_target_ratio(UINT8 ratio);
BOOLEAN hw_intel_set_turbo_allcore_ratio(UINT8 ratio);
BOOLEAN hw_intel_set_flex_ratio(UINT8 flex_ratio, BOOLEAN enable);
BOOLEAN hw_intel_unlock_cfg_lock_msr(VOID);
BOOLEAN hw_intel_set_pkg_power_limits_watts(UINT16 pl1_w, UINT16 pl2_w);
BOOLEAN hw_amd_set_p0_freq_mhz(UINT32 target_mhz);
BOOLEAN hw_amd_set_p0_vid(UINT8 new_vid);
BOOLEAN hw_amd_set_active_pstate(UINT8 pstate);
BOOLEAN hw_mp_set_enabled_threads(UINTN target_enabled, CHAR8 *err_out, UINTN max_err);

/* Live PCIe, Resizable BAR, Raw PCI Config & Intel GMCH VRAM Controls */
BOOLEAN hw_pci_cfg_read8_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT8 *out_val);
BOOLEAN hw_pci_cfg_read16_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT16 *out_val);
BOOLEAN hw_pci_cfg_read32_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT32 *out_val);
BOOLEAN hw_pci_cfg_write8_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT8 val);
BOOLEAN hw_pci_cfg_write16_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT16 val);
BOOLEAN hw_pci_cfg_write32_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT32 val);
VOID    hw_refresh_pci_dev(UINTN pci_idx);
VOID    hw_refresh_igd_ggc(VOID);
BOOLEAN hw_pci_set_aspm(UINTN pci_idx, UINT8 aspm_val);
BOOLEAN hw_pci_set_target_speed(UINTN pci_idx, UINT8 target_gen);
BOOLEAN hw_pci_set_relaxed_ordering(UINTN pci_idx, BOOLEAN enable);
BOOLEAN hw_pci_set_max_read_req(UINTN pci_idx, UINT8 mr_code);
BOOLEAN hw_pci_set_command_bit(UINTN pci_idx, UINT16 mask, BOOLEAN enable);
BOOLEAN hw_pci_set_rebar_size_exp(UINTN pci_idx, UINT8 size_exp);
BOOLEAN hw_igd_set_stolen_vram_mb(UINT32 target_mb);
BOOLEAN hw_igd_set_vga_disable(BOOLEAN disable_igd);

/* HII / IFR & setup_var_3 Helpers */
EFI_STATUS hw_export_raw_hii_packages(UINT8 **out_buf, UINTN *out_size);
BOOLEAN    hw_locate_varstore_nvram(
    const HW_HII_VARSTORE_INFO *vs,
    UINTN min_req_size,
    CHAR16 *out_wname,
    UINTN max_wchars,
    EFI_GUID *out_guid,
    UINTN *out_size
);
BOOLEAN    hw_hii_read_question_val(UINTN q_idx, UINT64 *out_val, BOOLEAN *out_in_nvram);
BOOLEAN    hw_hii_write_question_val(UINTN q_idx, UINT64 new_val, CHAR8 *err_out, UINTN max_err);
INTN       hw_hii_find_question_icase(const CHAR8 *kw1, const CHAR8 *kw2);

#endif /* EFI_SETUP_HWINFO_H */
