#include "hwinfo.h"
#include "nvram.h"
#include "unlock.h"
#include "util.h"

HW_SYSTEM_INFO gHw;
BOOLEAN        gVolatileHwTweakActive = FALSE;

typedef EFI_STATUS (EFIAPI *PCI_GET_BAR_ATTR_FN)(
    EFI_PCI_IO_PROTOCOL *This,
    UINT8 BarIndex,
    UINT64 *Supports,
    VOID **Resources
);

typedef struct {
    UINT8  Desc;
    UINT16 Len;
    UINT8  ResType;
    UINT8  GenFlag;
    UINT8  SpecificFlag;
    UINT64 AddrSpaceGranularity;
    UINT64 AddrRangeMin;
    UINT64 AddrRangeMax;
    UINT64 AddrTranslationOffset;
    UINT64 AddrLen;
} PACKED ACPI_QWORD_ADDR_SPACE_DESC;

static const CHAR8 *pci_vendor_lookup(UINT16 vid) {
    switch (vid) {
        case 0x8086: return "Intel";
        case 0x1022: return "AMD";
        case 0x1002: return "AMD/ATI";
        case 0x10DE: return "NVIDIA";
        case 0x106B: return "Apple";
        case 0x14E4: return "Broadcom";
        case 0x10EC: return "Realtek";
        case 0x168C: return "Qualcomm/Atheros";
        case 0x1AF4: return "RedHat/VirtIO";
        case 0x1B36: return "QEMU";
        case 0x1234: return "QEMU/Bochs";
        case 0x15AD: return "VMware";
        case 0x80EE: return "VirtualBox";
        case 0x1AB8: return "Parallels";
        case 0x1414: return "Microsoft";
        case 0x144D: return "Samsung";
        case 0x1987: return "Phison";
        case 0x1B4B: return "Marvell";
        case 0x1B21: return "ASMedia";
        case 0x1106: return "VIA";
        case 0x1033: return "NEC/Renesas";
        case 0x11AB: return "Marvell";
        case 0x1D6A: return "Aquantia";
        case 0x15B7: return "WD/SanDisk";
        case 0x1C5C: return "SK hynix";
        case 0x1344: return "Micron/Crucial";
        case 0x104C: return "Texas Inst.";
        case 0x1180: return "Ricoh";
        case 0x17AA: return "Lenovo";
        case 0x1043: return "ASUS";
        case 0x1458: return "Gigabyte";
        case 0x1462: return "MSI";
        case 0x1028: return "Dell";
        case 0x103C: return "HP";
        case 0x14C3: return "MediaTek";
        default:     return "PCI Vendor";
    }
}

static const CHAR8 *pci_class_lookup(UINT8 cls, UINT8 sub, UINT8 pif) {
    switch (cls) {
        case 0x01:
            if (sub == 0x01) return "IDE Controller";
            if (sub == 0x06) return (pif == 0x01) ? "SATA AHCI Ctrl" : "SATA Controller";
            if (sub == 0x08) return "NVMe SSD Ctrl";
            if (sub == 0x00) return "SCSI Controller";
            if (sub == 0x04) return "RAID Controller";
            return "Mass Storage Ctrl";
        case 0x02:
            if (sub == 0x00) return "Ethernet Ctrl";
            if (sub == 0x80) return "Wi-Fi / Network";
            return "Network Controller";
        case 0x03:
            if (sub == 0x00) return "VGA Compatible GPU";
            if (sub == 0x02) return "3D Graphics GPU";
            return "Display Controller";
        case 0x04:
            if (sub == 0x03) return "HD Audio Device";
            return "Multimedia Device";
        case 0x05:
            return "Memory Controller";
        case 0x06:
            if (sub == 0x00) return "Host Bridge";
            if (sub == 0x01) return "ISA / LPC Bridge";
            if (sub == 0x04) return "PCI-to-PCI Bridge";
            return "System Bridge";
        case 0x07:
            return "Serial / MEI Comm";
        case 0x08:
            if (sub == 0x06) return "IOMMU / System MMU";
            return "Base System Periph";
        case 0x0C:
            if (sub == 0x03) {
                if (pif == 0x30) return "USB 3.x xHCI Ctrl";
                if (pif == 0x20) return "USB 2.0 EHCI Ctrl";
                if (pif == 0x10) return "USB 1.1 OHCI Ctrl";
                if (pif == 0x00) return "USB 1.1 UHCI Ctrl";
                if (pif == 0x40) return "USB4 / Thunderbolt";
                return "USB Controller";
            }
            if (sub == 0x05) return "SMBus Controller";
            if (sub == 0x00) return "FireWire (IEEE1394)";
            return "Serial Bus Ctrl";
        case 0x0D:
            return "Wireless / BT Ctrl";
        case 0x10:
            if (sub == 0x80) return "PSP / Crypto Co-Proc";
            return "Encryption Ctrl";
        case 0x11:
            return "Thermal / Perf DSP";
        case 0x13:
            return "Instrumentation / SoC";
        default:
            return "PCI Device";
    }
}

static const CHAR8 *smbios_chassis_str(UINT8 code) {
    switch (code & 0x7F) {
        case 0x01: return "Other";
        case 0x03: return "Desktop";
        case 0x04: return "Low Profile Desktop";
        case 0x06: return "Mini Tower";
        case 0x07: return "Tower";
        case 0x08: return "Portable";
        case 0x09: return "Laptop";
        case 0x0A: return "Notebook";
        case 0x0D: return "All-in-One (iMac/AIO)";
        case 0x0E: return "Sub Notebook";
        case 0x11: return "Main Server Chassis";
        case 0x17: return "Rack Mount Chassis";
        case 0x1E: return "Tablet";
        case 0x1F: return "Convertible";
        case 0x20: return "Detachable";
        case 0x23: return "Mini PC";
        default:   return "Standard Enclosure";
    }
}

static const CHAR8 *smbios_mem_type_str(UINT8 t) {
    switch (t) {
        case 0x03: return "DRAM";
        case 0x0F: return "SDRAM";
        case 0x12: return "DDR";
        case 0x13: return "DDR2";
        case 0x18: return "DDR3";
        case 0x1A: return "DDR4";
        case 0x1B: return "LPDDR";
        case 0x1C: return "LPDDR2";
        case 0x1D: return "LPDDR3";
        case 0x1E: return "LPDDR4";
        case 0x22: return "DDR5";
        case 0x23: return "LPDDR5";
        default:   return "RAM";
    }
}

static VOID trim_ascii_spaces(CHAR8 *s) {
    if (!s) return;
    UINTN start = 0;
    while (s[start] == ' ' || s[start] == '\t') start++;
    if (start > 0) {
        UINTN l = str_len(s + start);
        memmove(s, s + start, l + 1);
    }
    UINTN len = str_len(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[--len] = '\0';
    }
}

/* =========================================================================
 * CPU Frequency, Overclock, Lock & All-Core MSR Controls (#GP-guarded)
 * Supports both Intel (SpeedStep/PerfCtl, Turbo 0x1AD, Flex/OC Lock 0x194,
 * CFG Lock 0xE2, RAPL Power Limit 0x610) and AMD (Zen/Ryzen P-State FID/DID/VID
 * 0xC0010064, CPB Turbo 0xC0010015, Active P-State 0xC0010062, SVM 0xC0010114).
 * ========================================================================= */
typedef struct {
    UINT32 msr;
    UINT64 val;
} SMP_MSR_WRITE_ARG;

static VOID EFIAPI ap_write_msr_proc(VOID *buffer) {
    const SMP_MSR_WRITE_ARG *arg = (const SMP_MSR_WRITE_ARG *)buffer;
    if (arg) {
        cpu_safe_wrmsr(arg->msr, arg->val);
    }
}

static UINT32 decode_amd_pstate_mhz(UINT64 raw, BOOLEAN zen4_5mhz, UINT32 *out_mv, UINT8 *out_vid) {
    if (out_mv) *out_mv = 0;
    if (out_vid) *out_vid = 0;
    if ((raw & (1ULL << 63)) == 0) return 0;

    UINT8 vid = (UINT8)((raw >> 14) & 0xFFULL);
    if (out_vid) *out_vid = vid;
    if (out_mv) {
        UINT32 drop_uv = (UINT32)vid * 6250U;
        *out_mv = (drop_uv < 1550000U) ? ((1550000U - drop_uv) / 1000U) : 0;
    }

    if (zen4_5mhz) {
        UINT32 fid12 = (UINT32)(raw & 0xFFFULL);
        return fid12 * 5U;
    } else {
        UINT32 fid8 = (UINT32)(raw & 0xFFULL);
        UINT32 dfs  = (UINT32)((raw >> 8) & 0x3FULL);
        if (dfs == 0) return 0;
        return (fid8 * 200U) / dfs;
    }
}

VOID hw_refresh_cpu_msrs(VOID) {
    memset(&gHw.cpu_msr, 0, sizeof(gHw.cpu_msr));

    BOOLEAN is_intel = (str_ncmp(gHw.cpu_vendor, "GenuineIntel", 12) == 0);
    BOOLEAN is_amd   = (str_ncmp(gHw.cpu_vendor, "AuthenticAMD", 12) == 0);
    gHw.cpu_msr.is_intel = is_intel;
    gHw.cpu_msr.is_amd   = is_amd;

    UINT32 a = 0, b = 0, c = 0, d = 0;
    cpu_cpuid(0, 0, &a, &b, &c, &d);
    if (a >= 6) {
        cpu_cpuid(6, 0, &a, &b, &c, &d);
        gHw.cpu_msr.turbo_hw_avail = ((a & (1U << 1)) != 0);
    }

    UINT64 val = 0;
    if (!is_amd) {
        /* Intel / x86 Architectural & Overclocking MSRs */
        if (cpu_safe_rdmsr(0x1A0U, &val)) {
            gHw.cpu_msr.misc_valid     = TRUE;
            gHw.cpu_msr.misc_val       = val;
            gHw.cpu_msr.fast_strings   = ((val & (1ULL << 0)) != 0);
            gHw.cpu_msr.auto_tcc       = ((val & (1ULL << 3)) != 0);
            gHw.cpu_msr.eist_enabled   = ((val & (1ULL << 16)) != 0);
            gHw.cpu_msr.turbo_disabled = ((val & (1ULL << 38)) != 0);
        }
        if (cpu_safe_rdmsr(0x1FCU, &val)) {
            gHw.cpu_msr.power_ctl_valid = TRUE;
            gHw.cpu_msr.power_ctl_val   = val;
            gHw.cpu_msr.bd_prochot      = ((val & (1ULL << 0)) != 0);
            gHw.cpu_msr.c1e_enable      = ((val & (1ULL << 1)) != 0);
        }
        if (cpu_safe_rdmsr(0xE2U, &val)) {
            gHw.cpu_msr.cst_cfg_valid    = TRUE;
            gHw.cpu_msr.cst_cfg_val      = val;
            gHw.cpu_msr.cfg_locked       = ((val & (1ULL << 15)) != 0);
            gHw.cpu_msr.pkg_cstate_limit = (UINT8)(val & 0x7ULL);
        }
        if (cpu_safe_rdmsr(0x3AU, &val)) {
            gHw.cpu_msr.feat_ctl_valid  = TRUE;
            gHw.cpu_msr.feat_ctl_val    = val;
            gHw.cpu_msr.vmx_locked      = ((val & (1ULL << 0)) != 0);
            gHw.cpu_msr.vmx_outside_smx = ((val & (1ULL << 2)) != 0);
        }
        if (cpu_safe_rdmsr(0xCEU, &val) && ((val >> 8) & 0xFFULL) != 0) {
            gHw.cpu_msr.plat_info_valid     = TRUE;
            gHw.cpu_msr.plat_info_val       = val;
            gHw.cpu_msr.intel_base_ratio    = (UINT8)((val >> 8) & 0xFFULL);
            gHw.cpu_msr.intel_min_ratio     = (UINT8)((val >> 40) & 0xFFULL);
            gHw.cpu_msr.intel_tdp_ratio_unl = ((val & (1ULL << 28)) != 0);
            gHw.cpu_msr.intel_tdp_pwr_unl   = ((val & (1ULL << 29)) != 0);
        }
        UINT64 pstat = 0, pctl = 0;
        if (cpu_safe_rdmsr(0x199U, &pctl)) {
            gHw.cpu_msr.perf_valid         = TRUE;
            gHw.cpu_msr.intel_target_ratio = (UINT8)((pctl >> 8) & 0xFFULL);
            if (cpu_safe_rdmsr(0x198U, &pstat)) {
                gHw.cpu_msr.intel_cur_ratio = (UINT8)((pstat >> 8) & 0xFFULL);
            }
        }
        if (cpu_safe_rdmsr(0x1ADU, &val) && (val & 0xFFULL) != 0) {
            gHw.cpu_msr.turbo_limit_valid = TRUE;
            gHw.cpu_msr.turbo_limit_val   = val;
            gHw.cpu_msr.intel_turbo_1c    = (UINT8)(val & 0xFFULL);
            UINT8 last_nz = gHw.cpu_msr.intel_turbo_1c;
            for (UINTN g = 1; g < 8; g++) {
                UINT8 gr = (UINT8)((val >> (g * 8)) & 0xFFULL);
                if (gr != 0) last_nz = gr;
            }
            gHw.cpu_msr.intel_turbo_allc = last_nz;
        }
        if (cpu_safe_rdmsr(0x194U, &val)) {
            gHw.cpu_msr.flex_oc_valid = TRUE;
            gHw.cpu_msr.flex_oc_val   = val;
            gHw.cpu_msr.oc_locked     = ((val & (1ULL << 20)) != 0);
            gHw.cpu_msr.flex_enabled  = ((val & (1ULL << 16)) != 0);
            gHw.cpu_msr.flex_ratio    = (UINT8)((val >> 8) & 0xFFULL);
        }
        UINT64 unit_v = 0, pl_v = 0;
        if (cpu_safe_rdmsr(0x606U, &unit_v) && cpu_safe_rdmsr(0x610U, &pl_v)) {
            UINT8 pu = (UINT8)(unit_v & 0x0FULL);
            if (pu <= 12) {
                gHw.cpu_msr.pkg_pwr_valid  = TRUE;
                gHw.cpu_msr.pkg_pwr_val    = pl_v;
                gHw.cpu_msr.rapl_pwr_unit  = pu;
                gHw.cpu_msr.pkg_pwr_locked = ((pl_v & (1ULL << 63)) != 0);
                gHw.cpu_msr.pl1_watts      = (UINT16)((pl_v & 0x7FFFULL) >> pu);
                gHw.cpu_msr.pl2_watts      = (UINT16)(((pl_v >> 32) & 0x7FFFULL) >> pu);
            }
        }
    }

    if (is_amd) {
        /* AMD Ryzen / Zen / Threadripper / EPYC Hardware MSRs */
        if (cpu_safe_rdmsr(0xC0010015U, &val)) {
            gHw.cpu_msr.amd_hwcr_valid   = TRUE;
            gHw.cpu_msr.amd_hwcr_val     = val;
            gHw.cpu_msr.amd_cpb_disabled = ((val & (1ULL << 25)) != 0);
            gHw.cpu_msr.amd_smm_locked   = ((val & 1ULL) != 0);
        }
        if (cpu_safe_rdmsr(0xC0010114U, &val)) {
            gHw.cpu_msr.amd_vmcr_valid   = TRUE;
            gHw.cpu_msr.amd_vmcr_val     = val;
            gHw.cpu_msr.amd_svm_locked   = ((val & (1ULL << 3)) != 0);
            gHw.cpu_msr.amd_svm_disabled = ((val & (1ULL << 4)) != 0);
        }
        if (gHw.cpu_family >= 0x17U && cpu_safe_rdmsr(0xC0010064U, &val) && (val & (1ULL << 63))) {
            BOOLEAN zen4_5mhz = (gHw.cpu_family >= 0x1AU) ||
                                (gHw.cpu_family == 0x19U &&
                                 ((gHw.cpu_model >= 0x10U && gHw.cpu_model <= 0x1FU) ||
                                  gHw.cpu_model >= 0x60U));
            UINT32 mhz0 = decode_amd_pstate_mhz(val, zen4_5mhz,
                                                &gHw.cpu_msr.amd_p0_mv,
                                                &gHw.cpu_msr.amd_p0_vid);
            if (mhz0 >= 400U && mhz0 <= 7500U) {
                gHw.cpu_msr.amd_pstate_valid  = TRUE;
                gHw.cpu_msr.amd_zen4_5mhz_fid = zen4_5mhz;
                gHw.cpu_msr.amd_p0_raw        = val;
                gHw.cpu_msr.amd_p0_mhz        = mhz0;
                UINT64 ps_lim = 0, ps_st = 0, p1 = 0, p2 = 0;
                if (cpu_safe_rdmsr(0xC0010061U, &ps_lim)) {
                    gHw.cpu_msr.amd_max_pstate = (UINT8)((ps_lim >> 4) & 0x7ULL);
                    if (gHw.cpu_msr.amd_max_pstate == 0) gHw.cpu_msr.amd_max_pstate = 2;
                }
                if (cpu_safe_rdmsr(0xC0010063U, &ps_st)) {
                    gHw.cpu_msr.amd_cur_pstate = (UINT8)(ps_st & 0x7ULL);
                }
                if (cpu_safe_rdmsr(0xC0010065U, &p1)) {
                    gHw.cpu_msr.amd_p1_mhz = decode_amd_pstate_mhz(p1, zen4_5mhz, NULL, NULL);
                }
                if (cpu_safe_rdmsr(0xC0010066U, &p2)) {
                    gHw.cpu_msr.amd_p2_mhz = decode_amd_pstate_mhz(p2, zen4_5mhz, NULL, NULL);
                }
            }
        }
    }
}

BOOLEAN hw_write_cpu_msr_all_cores(UINT32 msr, UINT64 val) {
    if (!cpu_safe_wrmsr(msr, val)) {
        hw_refresh_cpu_msrs();
        return FALSE;
    }
    EFI_MP_SERVICES_PROTOCOL *mp = NULL;
    if (!EFI_ERROR(efi_locate_protocol(&gEfiMpServicesProtocolGuid, (VOID **)&mp)) &&
        mp && mp->StartupAllAPs) {
        SMP_MSR_WRITE_ARG arg;
        arg.msr = msr;
        arg.val = val;
        mp->StartupAllAPs(mp, ap_write_msr_proc, TRUE, NULL, 250000, &arg, NULL);
    }
    hw_refresh_cpu_msrs();
    gVolatileHwTweakActive = TRUE;
    return TRUE;
}

BOOLEAN hw_write_cpu_msr_bit(UINT32 msr, UINT8 bit_idx, BOOLEAN set_one) {
    if (bit_idx >= 64) return FALSE;
    UINT64 cur = 0;
    if (!cpu_safe_rdmsr(msr, &cur)) return FALSE;
    UINT64 mask = (1ULL << bit_idx);
    UINT64 target = set_one ? (cur | mask) : (cur & ~mask);
    if (!hw_write_cpu_msr_all_cores(msr, target)) return FALSE;
    UINT64 verify = 0;
    if (!cpu_safe_rdmsr(msr, &verify)) return FALSE;
    return (((verify & mask) != 0) == (set_one != FALSE));
}

BOOLEAN hw_intel_set_target_ratio(UINT8 ratio) {
    if (ratio < 4 || ratio > 85) return FALSE;
    if (gHw.cpu_msr.misc_valid && !gHw.cpu_msr.eist_enabled) {
        hw_write_cpu_msr_bit(0x1A0U, 16, TRUE);
    }
    UINT64 cur = 0;
    if (!cpu_safe_rdmsr(0x199U, &cur)) return FALSE;
    UINT64 nval = (cur & ~0xFF00ULL) | ((UINT64)ratio << 8);
    if (!hw_write_cpu_msr_all_cores(0x199U, nval)) return FALSE;
    return (gHw.cpu_msr.intel_target_ratio == ratio);
}

BOOLEAN hw_intel_set_turbo_allcore_ratio(UINT8 ratio) {
    if (ratio < 8 || ratio > 90) return FALSE;
    UINT64 cur = 0;
    if (!cpu_safe_rdmsr(0x1ADU, &cur)) return FALSE;
    UINT64 nval = 0;
    for (UINTN b = 0; b < 8; b++) {
        UINT8 orig = (UINT8)((cur >> (b * 8)) & 0xFFULL);
        UINT8 set_b = (orig != 0 || b == 0) ? ratio : 0;
        nval |= ((UINT64)set_b << (b * 8));
    }
    if (!hw_write_cpu_msr_all_cores(0x1ADU, nval)) return FALSE;
    return (gHw.cpu_msr.intel_turbo_1c == ratio);
}

BOOLEAN hw_intel_set_flex_ratio(UINT8 flex_ratio, BOOLEAN enable) {
    UINT64 cur = 0;
    if (!cpu_safe_rdmsr(0x194U, &cur)) return FALSE;
    if ((cur & (1ULL << 20)) != 0) return FALSE; /* OC_LOCK set */
    UINT64 nval = (cur & ~0x1FF00ULL) | ((UINT64)flex_ratio << 8) | (enable ? (1ULL << 16) : 0ULL);
    if (!hw_write_cpu_msr_all_cores(0x194U, nval)) return FALSE;
    return (gHw.cpu_msr.flex_enabled == (enable != FALSE));
}

BOOLEAN hw_intel_unlock_cfg_lock_msr(VOID) {
    UINT64 cur = 0;
    if (!cpu_safe_rdmsr(0xE2U, &cur)) return FALSE;
    if ((cur & (1ULL << 15)) == 0) return TRUE;
    hw_write_cpu_msr_all_cores(0xE2U, cur & ~(1ULL << 15));
    return !gHw.cpu_msr.cfg_locked;
}

BOOLEAN hw_intel_set_pkg_power_limits_watts(UINT16 pl1_w, UINT16 pl2_w) {
    if (!gHw.cpu_msr.pkg_pwr_valid || gHw.cpu_msr.pkg_pwr_locked) return FALSE;
    if (pl1_w < 5 || pl2_w < 5) return FALSE;
    UINT64 cur = 0;
    if (!cpu_safe_rdmsr(0x610U, &cur)) return FALSE;
    UINT64 scale = 1ULL << gHw.cpu_msr.rapl_pwr_unit;
    UINT64 raw1 = (UINT64)pl1_w * scale;
    UINT64 raw2 = (UINT64)pl2_w * scale;
    if (raw1 > 0x7FFFULL) raw1 = 0x7FFFULL;
    if (raw2 > 0x7FFFULL) raw2 = 0x7FFFULL;
    UINT64 nval = (cur & ~(0x7FFFULL | (0x7FFFULL << 32))) |
                  raw1 | (1ULL << 15) | (raw2 << 32) | (1ULL << 47);
    if (!cpu_safe_wrmsr(0x610U, nval)) {
        hw_refresh_cpu_msrs();
        return FALSE;
    }
    hw_refresh_cpu_msrs();
    gVolatileHwTweakActive = TRUE;
    return (gHw.cpu_msr.pl1_watts == (UINT16)(raw1 >> gHw.cpu_msr.rapl_pwr_unit));
}

BOOLEAN hw_amd_set_p0_freq_mhz(UINT32 target_mhz) {
    if (!gHw.cpu_msr.amd_pstate_valid || target_mhz < 800U || target_mhz > 6200U) return FALSE;
    UINT64 p0 = 0;
    if (!cpu_safe_rdmsr(0xC0010064U, &p0)) return FALSE;

    UINT64 nval = p0;
    if (gHw.cpu_msr.amd_zen4_5mhz_fid) {
        UINT64 fid12 = (target_mhz + 2U) / 5U;
        if (fid12 < 160ULL) fid12 = 160ULL;
        if (fid12 > 1240ULL) fid12 = 1240ULL;
        nval = (p0 & ~0xFFFULL) | (fid12 & 0xFFFULL) | (1ULL << 63);
    } else {
        UINT64 dfs  = 8ULL; /* 25 MHz step (200 / 8) */
        UINT64 fid8 = ((UINT64)target_mhz * dfs + 100ULL) / 200ULL;
        if (fid8 < 0x20ULL) fid8 = 0x20ULL;
        if (fid8 > 0xF8ULL) fid8 = 0xF8ULL;
        nval = (p0 & ~0x3FFFULL) | (dfs << 8) | (fid8 & 0xFFULL) | (1ULL << 63);
    }

    if (!hw_write_cpu_msr_all_cores(0xC0010064U, nval)) return FALSE;
    hw_write_cpu_msr_all_cores(0xC0010062U, 0ULL);
    if (gHw.cpu_msr.amd_p0_mhz > 0) {
        gHw.cpu_cur_mhz = gHw.cpu_msr.amd_p0_mhz;
    }
    return TRUE;
}

BOOLEAN hw_amd_set_p0_vid(UINT8 new_vid) {
    if (!gHw.cpu_msr.amd_pstate_valid) return FALSE;
    /* Guard voltage range to 0.750V (VID 128) .. 1.475V (VID 12) */
    if (new_vid < 12U || new_vid > 128U) return FALSE;
    UINT64 p0 = 0;
    if (!cpu_safe_rdmsr(0xC0010064U, &p0)) return FALSE;
    UINT64 nval = (p0 & ~(0xFFULL << 14)) | ((UINT64)new_vid << 14);
    if (!hw_write_cpu_msr_all_cores(0xC0010064U, nval)) return FALSE;
    hw_write_cpu_msr_all_cores(0xC0010062U, 0ULL);
    return (gHw.cpu_msr.amd_p0_vid == new_vid);
}

BOOLEAN hw_amd_set_active_pstate(UINT8 pstate) {
    if (!gHw.cpu_msr.amd_pstate_valid || pstate > 2) return FALSE;
    return hw_write_cpu_msr_all_cores(0xC0010062U, (UINT64)pstate);
}

/* =========================================================================
 * CPUID + MADT + MP Services + SMBIOS Accurate Core/Thread Topology
 * (Fixes Sandy Bridge MacBook Pro Early 2011 16C/16T APIC ID max count bug!)
 * ========================================================================= */
static UINT32 g_cpuid_pkg_threads  = 0;
static UINT32 g_cpuid_leaf4_cores  = 0;
static UINT32 g_amd_pkg_threads    = 0;

static VOID collect_cpu_cpuid_and_mp(VOID) {
    UINT32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    g_cpuid_pkg_threads = 0;
    g_cpuid_leaf4_cores = 0;
    g_amd_pkg_threads   = 0;

    cpu_cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    UINT32 max_basic = eax;

    memcpy(gHw.cpu_vendor + 0, &ebx, 4);
    memcpy(gHw.cpu_vendor + 4, &edx, 4);
    memcpy(gHw.cpu_vendor + 8, &ecx, 4);
    gHw.cpu_vendor[12] = '\0';

    BOOLEAN is_intel = (str_ncmp(gHw.cpu_vendor, "GenuineIntel", 12) == 0);
    BOOLEAN is_amd   = (str_ncmp(gHw.cpu_vendor, "AuthenticAMD", 12) == 0);

    if (max_basic >= 1) {
        cpu_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
        gHw.cpu_signature = eax;
        UINT32 stepping = eax & 0xF;
        UINT32 model    = (eax >> 4) & 0xF;
        UINT32 family   = (eax >> 8) & 0xF;
        UINT32 ext_mod  = (eax >> 16) & 0xF;
        UINT32 ext_fam  = (eax >> 20) & 0xFF;
        if (family == 6 || family == 15) {
            model += (ext_mod << 4);
        }
        if (family == 15) {
            family += ext_fam;
        }
        gHw.cpu_family   = family;
        gHw.cpu_model    = model;
        gHw.cpu_stepping = stepping;

        gHw.feat_vmx        = ((ecx & (1U << 5))  != 0);
        gHw.feat_sse41      = ((ecx & (1U << 19)) != 0);
        gHw.feat_sse42      = ((ecx & (1U << 20)) != 0);
        gHw.feat_x2apic     = ((ecx & (1U << 21)) != 0);
        gHw.feat_aes        = ((ecx & (1U << 25)) != 0);
        gHw.feat_avx        = ((ecx & (1U << 28)) != 0);
        gHw.feat_hypervisor = ((ecx & (1U << 31)) != 0);
    }

    /*
     * Intel Extended Topology Enumeration: Leaf 0x1F (V2) or Leaf 0x0B (V1).
     * Supported on Nehalem, Sandy Bridge (MBP Early 2011!), Ivy Bridge, Haswell,
     * Skylake/Kaby Lake (ThinkPad P51), Coffee Lake, Alder Lake+, and modern VMs.
     * Note: CPUID.01H:EBX[23:16] on Sandy Bridge is hardcoded to 16 (max addressable
     * APIC IDs in package), NOT actual core/thread count! Leaf 0x0B gives real topology.
     */
    UINT32 topo_leaf = 0;
    if (max_basic >= 0x1FU) {
        cpu_cpuid(0x1FU, 0, &eax, &ebx, &ecx, &edx);
        if (((ecx >> 8) & 0xFFU) != 0 && (ebx & 0xFFFFU) != 0) {
            topo_leaf = 0x1FU;
        }
    }
    if (topo_leaf == 0 && max_basic >= 0x0BU) {
        cpu_cpuid(0x0BU, 0, &eax, &ebx, &ecx, &edx);
        if (((ecx >> 8) & 0xFFU) != 0 && (ebx & 0xFFFFU) != 0) {
            topo_leaf = 0x0BU;
        }
    }
    if (topo_leaf != 0) {
        for (UINT32 sub = 0; sub < 8; sub++) {
            cpu_cpuid(topo_leaf, sub, &eax, &ebx, &ecx, &edx);
            UINT32 lvl_type = (ecx >> 8) & 0xFFU;
            UINT32 lvl_cnt  = ebx & 0xFFFFU;
            if (lvl_type == 0) break;
            if (lvl_type == 1 && lvl_cnt > 0) {
                gHw.cpu_smt_per_core = lvl_cnt;
            } else if (lvl_type >= 2 && lvl_cnt > 0) {
                g_cpuid_pkg_threads = lvl_cnt;
            }
        }
    }

    /* Pre-Nehalem Intel Deterministic Cache Parameters Leaf 0x04 (Core Duo / Core 2 Duo Macs) */
    if (is_intel && max_basic >= 4) {
        cpu_cpuid(4, 0, &eax, &ebx, &ecx, &edx);
        if ((eax & 0x1FU) != 0) {
            g_cpuid_leaf4_cores = ((eax >> 26) & 0x3FU) + 1U;
        }
    }

    if (max_basic >= 7) {
        cpu_cpuid(7, 0, &eax, &ebx, &ecx, &edx);
        gHw.feat_avx2 = ((ebx & (1U << 5)) != 0);
    }

    /* Extended CPUID Leaves */
    cpu_cpuid(0x80000000U, 0, &eax, &ebx, &ecx, &edx);
    UINT32 max_ext = eax;
    if (max_ext >= 0x80000001U) {
        cpu_cpuid(0x80000001U, 0, &eax, &ebx, &ecx, &edx);
        gHw.feat_nx   = ((edx & (1U << 20)) != 0);
        gHw.feat_lm64 = ((edx & (1U << 29)) != 0);
        gHw.feat_svm  = ((ecx & (1U << 2))  != 0);
    }
    if (max_ext >= 0x80000004U) {
        UINT32 brand_words[12];
        cpu_cpuid(0x80000002U, 0, &brand_words[0], &brand_words[1], &brand_words[2],  &brand_words[3]);
        cpu_cpuid(0x80000003U, 0, &brand_words[4], &brand_words[5], &brand_words[6],  &brand_words[7]);
        cpu_cpuid(0x80000004U, 0, &brand_words[8], &brand_words[9], &brand_words[10], &brand_words[11]);
        memcpy(gHw.cpu_brand, brand_words, 48);
        gHw.cpu_brand[48] = '\0';
        trim_ascii_spaces(gHw.cpu_brand);
    } else {
        str_cpy(gHw.cpu_brand, gHw.cpu_vendor, sizeof(gHw.cpu_brand));
    }
    if (max_ext >= 0x80000008U) {
        cpu_cpuid(0x80000008U, 0, &eax, &ebx, &ecx, &edx);
        gHw.phys_addr_bits = (UINT8)(eax & 0xFF);
        gHw.virt_addr_bits = (UINT8)((eax >> 8) & 0xFF);
        if (is_amd) {
            g_amd_pkg_threads = (ecx & 0xFFU) + 1U;
        }
    } else {
        gHw.phys_addr_bits = gHw.feat_lm64 ? 36 : 32;
        gHw.virt_addr_bits = gHw.feat_lm64 ? 48 : 32;
    }
    if (is_amd && max_ext >= 0x8000001EU) {
        cpu_cpuid(0x8000001EU, 0, &eax, &ebx, &ecx, &edx);
        UINT32 tpc = ((ebx >> 8) & 0xFFU) + 1U;
        if (tpc > 0 && gHw.cpu_smt_per_core == 0) {
            gHw.cpu_smt_per_core = tpc;
        }
    }

    /* Hypervisor Signature Leaf */
    if (gHw.feat_hypervisor) {
        cpu_cpuid(0x40000000U, 0, &eax, &ebx, &ecx, &edx);
        memcpy(gHw.hypervisor_id + 0, &ebx, 4);
        memcpy(gHw.hypervisor_id + 4, &ecx, 4);
        memcpy(gHw.hypervisor_id + 8, &edx, 4);
        gHw.hypervisor_id[12] = '\0';

        if (str_ncmp(gHw.hypervisor_id, "KVMKVMKVM", 9) == 0)
            str_cpy(gHw.hypervisor_name, "QEMU / KVM", sizeof(gHw.hypervisor_name));
        else if (str_ncmp(gHw.hypervisor_id, "TCGTCGTCGTCG", 12) == 0)
            str_cpy(gHw.hypervisor_name, "QEMU (TCG Emulation)", sizeof(gHw.hypervisor_name));
        else if (str_ncmp(gHw.hypervisor_id, "VMwareVMware", 12) == 0)
            str_cpy(gHw.hypervisor_name, "VMware Workstation/ESXi", sizeof(gHw.hypervisor_name));
        else if (str_ncmp(gHw.hypervisor_id, "VBoxVBoxVBox", 12) == 0)
            str_cpy(gHw.hypervisor_name, "Oracle VirtualBox", sizeof(gHw.hypervisor_name));
        else if (str_ncmp(gHw.hypervisor_id, "Microsoft Hv", 12) == 0)
            str_cpy(gHw.hypervisor_name, "Microsoft Hyper-V", sizeof(gHw.hypervisor_name));
        else if (str_contains_icase(gHw.hypervisor_id, "prl"))
            str_cpy(gHw.hypervisor_name, "Parallels Desktop", sizeof(gHw.hypervisor_name));
        else if (gHw.hypervisor_id[0])
            str_cpy(gHw.hypervisor_name, gHw.hypervisor_id, sizeof(gHw.hypervisor_name));
        else
            str_cpy(gHw.hypervisor_name, "Virtual Machine", sizeof(gHw.hypervisor_name));
    } else {
        str_cpy(gHw.hypervisor_name, "Bare Metal Hardware", sizeof(gHw.hypervisor_name));
    }

    /* Query UEFI PI MP Services Protocol (present on UEFI 2.x PCs; absent on Apple EFI 1.10) */
    EFI_MP_SERVICES_PROTOCOL *mp = NULL;
    if (!EFI_ERROR(efi_locate_protocol(&gEfiMpServicesProtocolGuid, (VOID **)&mp)) && mp) {
        UINTN num_all = 0, num_en = 0;
        if (!EFI_ERROR(mp->GetNumberOfProcessors(mp, &num_all, &num_en)) && num_all > 0) {
            gHw.cpu_mp_total_threads = (UINT32)num_all;
            gHw.cpu_mp_threads       = (UINT32)(num_en > 0 ? num_en : num_all);
        }
    }

    hw_refresh_cpu_msrs();
}

static VOID finalize_cpu_topology(VOID) {
    /*
     * 1. Determine active logical processor (thread) count:
     *    MP_SERVICES (UEFI 2.x) -> ACPI MADT Local APIC count (Apple EFI 1.10 + all ACPI PCs) ->
     *    SMBIOS Type 4 (v2.5+) -> CPUID Leaf 0x1F/0x0B -> AMD 0x80000008 -> 1
     */
    UINT32 threads = 0;
    if (gHw.cpu_mp_threads > 0)          threads = gHw.cpu_mp_threads;
    else if (gHw.cpu_madt_threads > 0)   threads = gHw.cpu_madt_threads;
    else if (gHw.cpu_smbios_threads > 0) threads = gHw.cpu_smbios_threads;
    else if (g_cpuid_pkg_threads > 0)    threads = g_cpuid_pkg_threads;
    else if (g_amd_pkg_threads > 0)      threads = g_amd_pkg_threads;
    else                                 threads = 1;

    /*
     * 2. Determine physical core count:
     *    - If SMBIOS Type 4 explicitly reports cores < threads (e.g. ThinkPad P51 4C/8T or Hybrid P+E), trust it.
     *    - Else if CPUID Leaf 0x1F/0x0B/AMD gives SMT threads-per-core > 1 (e.g. MBP Early 2011 4T / 2 = 2C!),
     *      divide active threads by SMT per core.
     *    - Else fallback to SMBIOS cores (when HT is off, e.g. 4C/4T) or CPUID Leaf 0x04 (Core 2 Duo Macs 2C/2T).
     */
    UINT32 cores = 0;
    if (gHw.cpu_smbios_cores > 0 && gHw.cpu_smbios_cores < threads) {
        cores = gHw.cpu_smbios_cores;
    } else if (gHw.cpu_smbios_cores > 0 && gHw.cpu_smbios_cores == threads &&
               (gHw.cpu_smt_per_core <= 1 ||
                (g_cpuid_pkg_threads > 0 && threads <= (g_cpuid_pkg_threads / gHw.cpu_smt_per_core)))) {
        cores = gHw.cpu_smbios_cores;
    } else if (gHw.cpu_smt_per_core > 1 && threads >= gHw.cpu_smt_per_core) {
        cores = threads / gHw.cpu_smt_per_core;
    } else if (gHw.cpu_smbios_cores > 0 && gHw.cpu_smbios_cores <= threads) {
        cores = gHw.cpu_smbios_cores;
    } else if (g_cpuid_leaf4_cores > 0 && g_cpuid_leaf4_cores <= threads) {
        cores = g_cpuid_leaf4_cores;
    } else {
        cores = threads;
    }

    if (cores == 0) cores = 1;
    if (threads < cores) threads = cores;
    gHw.cpu_cores   = cores;
    gHw.cpu_threads = threads;
}

BOOLEAN hw_mp_set_enabled_threads(UINTN target_enabled, CHAR8 *err_out, UINTN max_err) {
    EFI_MP_SERVICES_PROTOCOL *mp = NULL;
    if (EFI_ERROR(efi_locate_protocol(&gEfiMpServicesProtocolGuid, (VOID **)&mp)) ||
        !mp || !mp->EnableDisableAP) {
        if (err_out) str_cpy(err_out, "UEFI MP_SERVICES->EnableDisableAP not supported.", max_err);
        return FALSE;
    }
    UINTN num_all = 0, num_en = 0;
    if (EFI_ERROR(mp->GetNumberOfProcessors(mp, &num_all, &num_en)) || num_all <= 1) {
        if (err_out) str_cpy(err_out, "Single-processor environment; no APs to toggle.", max_err);
        return FALSE;
    }
    if (target_enabled < 1) target_enabled = 1;
    if (target_enabled > num_all) target_enabled = num_all;

    for (UINTN p = 1; p < num_all; p++) {
        BOOLEAN want_en = (p < target_enabled);
        mp->EnableDisableAP(mp, p, want_en, NULL);
    }
    if (!EFI_ERROR(mp->GetNumberOfProcessors(mp, &num_all, &num_en)) && num_all > 0) {
        gHw.cpu_mp_total_threads = (UINT32)num_all;
        gHw.cpu_mp_threads       = (UINT32)(num_en > 0 ? num_en : 1);
        finalize_cpu_topology();
        if (num_en == target_enabled) gVolatileHwTweakActive = TRUE;
        return (num_en == target_enabled);
    }
    return FALSE;
}

/* Retrieve N-th (1-based) string from an SMBIOS structure's trailing string-set */
static const CHAR8 *smbios_get_string(
    const UINT8 *struct_start,
    UINTN max_rem,
    UINT8 str_idx,
    UINT64 *out_ram_addr,
    UINTN *out_maxlen
) {
    if (out_ram_addr) *out_ram_addr = 0;
    if (out_maxlen) *out_maxlen = 0;
    if (!struct_start || str_idx == 0) return "";

    UINT8 hdr_len = struct_start[1];
    if (hdr_len >= max_rem) return "";

    const CHAR8 *p = (const CHAR8 *)(struct_start + hdr_len);
    const CHAR8 *end = (const CHAR8 *)(struct_start + max_rem);
    UINT8 cur = 1;
    while (p < end && *p != '\0') {
        UINTN slen = 0;
        while ((p + slen) < end && p[slen] != '\0') slen++;
        if (cur == str_idx) {
            if (out_ram_addr) *out_ram_addr = (UINT64)(UINTN)p;
            if (out_maxlen) *out_maxlen = slen;
            return p;
        }
        p += slen + 1;
        cur++;
    }
    return "";
}

static VOID collect_smbios_info(VOID) {
    str_cpy(gHw.bios_vendor,      "Unknown", sizeof(gHw.bios_vendor));
    str_cpy(gHw.bios_version,     "Unknown", sizeof(gHw.bios_version));
    str_cpy(gHw.bios_date,        "Unknown", sizeof(gHw.bios_date));
    str_cpy(gHw.sys_manufacturer, "Standard EFI Platform", sizeof(gHw.sys_manufacturer));
    str_cpy(gHw.sys_product,      "Generic EFI System", sizeof(gHw.sys_product));
    str_cpy(gHw.sys_version,      "1.0", sizeof(gHw.sys_version));
    str_cpy(gHw.sys_serial,       "Not Specified", sizeof(gHw.sys_serial));
    str_cpy(gHw.sys_uuid,         "00000000-0000-0000-0000-000000000000", sizeof(gHw.sys_uuid));
    str_cpy(gHw.board_product,    "N/A", sizeof(gHw.board_product));
    str_cpy(gHw.board_serial,     "Not Specified", sizeof(gHw.board_serial));
    str_cpy(gHw.chassis_type,     "Standard", sizeof(gHw.chassis_type));

    if (!gST || !gST->ConfigurationTable) return;

    VOID *sm3_ptr = NULL;
    VOID *sm2_ptr = NULL;
    for (UINTN i = 0; i < gST->NumberOfTableEntries; i++) {
        if (guid_equal(&gST->ConfigurationTable[i].VendorGuid, &gEfiSmbios3TableGuid)) {
            sm3_ptr = gST->ConfigurationTable[i].VendorTable;
        } else if (guid_equal(&gST->ConfigurationTable[i].VendorGuid, &gEfiSmbiosTableGuid)) {
            sm2_ptr = gST->ConfigurationTable[i].VendorTable;
        }
    }

    UINT64 tbl_addr = 0;
    UINT32 tbl_len = 0;

    if (sm3_ptr && cpu_probe_address((UINT64)(UINTN)sm3_ptr, NULL, NULL)) {
        const SMBIOS_ENTRY_POINT_30 *ep3 = (const SMBIOS_ENTRY_POINT_30 *)sm3_ptr;
        if (memcmp(ep3->Anchor, "_SM3_", 5) == 0) {
            gHw.smbios_present = TRUE;
            gHw.smbios_is_v3   = TRUE;
            gHw.smbios_major   = ep3->MajorVersion;
            gHw.smbios_minor   = ep3->MinorVersion;
            gHw.smbios_ep_addr = (UINT64)(UINTN)sm3_ptr;
            tbl_addr           = ep3->TableAddress;
            tbl_len            = ep3->TableMaximumSize;
        }
    }
    if (!gHw.smbios_present && sm2_ptr && cpu_probe_address((UINT64)(UINTN)sm2_ptr, NULL, NULL)) {
        const SMBIOS_ENTRY_POINT_21 *ep2 = (const SMBIOS_ENTRY_POINT_21 *)sm2_ptr;
        if (memcmp(ep2->Anchor, "_SM_", 4) == 0 || memcmp(ep2->IntermediateAnchor, "_DMI_", 5) == 0) {
            gHw.smbios_present = TRUE;
            gHw.smbios_is_v3   = FALSE;
            gHw.smbios_major   = ep2->MajorVersion;
            gHw.smbios_minor   = ep2->MinorVersion;
            gHw.smbios_ep_addr = (UINT64)(UINTN)sm2_ptr;
            tbl_addr           = (UINT64)ep2->TableAddress;
            tbl_len            = (UINT32)ep2->TableLength;
        }
    }

    if (!gHw.smbios_present || tbl_addr == 0 || tbl_len < 4) return;
#if !defined(__x86_64__) && !defined(_M_X64)
    if (tbl_addr > 0xFFFFFFFFULL) return;
#endif

    BOOLEAN mapped = FALSE, writable = FALSE;
    if (!cpu_probe_address(tbl_addr, &mapped, &writable) || !mapped) return;

    gHw.smbios_table_addr = tbl_addr;
    gHw.smbios_table_size = tbl_len;
    gHw.smbios_writable   = writable;

    const UINT8 *base = (const UINT8 *)(UINTN)tbl_addr;
    UINTN off = 0;

    while (off + 4 <= tbl_len) {
        if (!cpu_probe_address(tbl_addr + off, &mapped, NULL) || !mapped) break;
        const UINT8 *s = base + off;
        UINT8 type = s[0];
        UINT8 hlen = s[1];
        if (hlen < 4 || off + hlen > tbl_len) break;

        UINTN rem = tbl_len - off;

        /* Find end of trailing double-NUL string section */
        UINTN next_off = off + hlen;
        while (next_off + 1 < tbl_len) {
            if (!cpu_probe_address(tbl_addr + next_off + 1, &mapped, NULL) || !mapped) {
                next_off = tbl_len;
                break;
            }
            if (base[next_off] == 0 && base[next_off + 1] == 0) {
                next_off += 2;
                break;
            }
            next_off++;
        }

        if (type == 127) {
            break;
        } else if (type == 0 && hlen >= 8) {
            str_cpy(gHw.bios_vendor,  smbios_get_string(s, rem, s[4], NULL, NULL), sizeof(gHw.bios_vendor));
            str_cpy(gHw.bios_version, smbios_get_string(s, rem, s[5], &gHw.bios_ver_ram_addr, &gHw.bios_ver_ram_maxlen), sizeof(gHw.bios_version));
            if (hlen >= 9) {
                str_cpy(gHw.bios_date, smbios_get_string(s, rem, s[8], NULL, NULL), sizeof(gHw.bios_date));
            }
        } else if (type == 1 && hlen >= 8) {
            str_cpy(gHw.sys_manufacturer, smbios_get_string(s, rem, s[4], NULL, NULL), sizeof(gHw.sys_manufacturer));
            str_cpy(gHw.sys_product,      smbios_get_string(s, rem, s[5], &gHw.sys_product_ram_addr, &gHw.sys_product_ram_maxlen), sizeof(gHw.sys_product));
            str_cpy(gHw.sys_version,      smbios_get_string(s, rem, s[6], NULL, NULL), sizeof(gHw.sys_version));
            str_cpy(gHw.sys_serial,       smbios_get_string(s, rem, s[7], &gHw.sys_serial_ram_addr, &gHw.sys_serial_ram_maxlen), sizeof(gHw.sys_serial));
            if (hlen >= 24) {
                const UINT8 *u = s + 8;
                UINT32 d1 = (UINT32)u[0] | ((UINT32)u[1] << 8) | ((UINT32)u[2] << 16) | ((UINT32)u[3] << 24);
                UINT16 d2 = (UINT16)u[4] | ((UINT16)u[5] << 8);
                UINT16 d3 = (UINT16)u[6] | ((UINT16)u[7] << 8);
                snprintf_ascii(gHw.sys_uuid, sizeof(gHw.sys_uuid),
                    "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    d1, d2, d3, u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
            }
            if (hlen >= 27) {
                str_cpy(gHw.sys_sku,    smbios_get_string(s, rem, s[25], NULL, NULL), sizeof(gHw.sys_sku));
                str_cpy(gHw.sys_family, smbios_get_string(s, rem, s[26], NULL, NULL), sizeof(gHw.sys_family));
            }
        } else if (type == 2 && hlen >= 8) {
            str_cpy(gHw.board_manufacturer, smbios_get_string(s, rem, s[4], NULL, NULL), sizeof(gHw.board_manufacturer));
            str_cpy(gHw.board_product,      smbios_get_string(s, rem, s[5], NULL, NULL), sizeof(gHw.board_product));
            str_cpy(gHw.board_version,      smbios_get_string(s, rem, s[6], NULL, NULL), sizeof(gHw.board_version));
            str_cpy(gHw.board_serial,       smbios_get_string(s, rem, s[7], &gHw.board_serial_ram_addr, &gHw.board_serial_ram_maxlen), sizeof(gHw.board_serial));
        } else if (type == 3 && hlen >= 9) {
            gHw.chassis_type_code = s[5] & 0x7FU;
            str_cpy(gHw.chassis_manufacturer, smbios_get_string(s, rem, s[4], NULL, NULL), sizeof(gHw.chassis_manufacturer));
            str_cpy(gHw.chassis_type,         smbios_chassis_str(s[5]), sizeof(gHw.chassis_type));
            str_cpy(gHw.chassis_serial,       smbios_get_string(s, rem, s[7], NULL, NULL), sizeof(gHw.chassis_serial));
            str_cpy(gHw.chassis_asset_tag,    smbios_get_string(s, rem, s[8], NULL, NULL), sizeof(gHw.chassis_asset_tag));
        } else if (type == 4 && hlen >= 0x18) {
            /* Processor Information (Note: SMBIOS 2.4 on 2011 Macs has hlen == 0x23!) */
            str_cpy(gHw.cpu_smbios_manufacturer, smbios_get_string(s, rem, s[7], NULL, NULL), sizeof(gHw.cpu_smbios_manufacturer));
            str_cpy(gHw.cpu_smbios_version,      smbios_get_string(s, rem, s[0x10], NULL, NULL), sizeof(gHw.cpu_smbios_version));
            trim_ascii_spaces(gHw.cpu_smbios_manufacturer);
            trim_ascii_spaces(gHw.cpu_smbios_version);
            UINT16 max_spd = (UINT16)s[0x14] | ((UINT16)s[0x15] << 8);
            UINT16 cur_spd = (UINT16)s[0x16] | ((UINT16)s[0x17] << 8);
            if (max_spd > 0) gHw.cpu_max_mhz = max_spd;
            if (cur_spd > 0) gHw.cpu_cur_mhz = cur_spd;
            if (hlen >= 0x26) {
                UINT32 c_cnt = (s[0x24] > 0 && s[0x24] != 0xFFU) ? s[0x24] : s[0x23];
                UINT32 t_cnt = s[0x25];
                if (c_cnt == 0xFFU && hlen >= 0x2EU) {
                    c_cnt = (UINT32)s[0x2C] | ((UINT32)s[0x2D] << 8);
                } else if (c_cnt == 0xFFU && hlen >= 0x2CU) {
                    c_cnt = (UINT32)s[0x2A] | ((UINT32)s[0x2B] << 8);
                }
                if (t_cnt == 0xFFU && hlen >= 0x30U) {
                    t_cnt = (UINT32)s[0x2E] | ((UINT32)s[0x2F] << 8);
                }
                if (c_cnt > 0 && c_cnt != 0xFFU) gHw.cpu_smbios_cores   += c_cnt;
                if (t_cnt > 0 && t_cnt != 0xFFU) gHw.cpu_smbios_threads += t_cnt;
            }
        } else if (type == 17 && hlen >= 0x15 && gHw.dimm_count < HW_MAX_DIMMS) {
            HW_DIMM_INFO *dm = &gHw.dimms[gHw.dimm_count++];
            memset(dm, 0, sizeof(*dm));
            UINT16 raw_sz = (UINT16)s[0x0C] | ((UINT16)s[0x0D] << 8);
            UINT32 mb = 0;
            if (raw_sz == 0 || raw_sz == 0xFFFF) {
                mb = 0;
            } else if (raw_sz == 0x7FFF && hlen >= 0x20) {
                UINT32 ext = (UINT32)s[0x1C] | ((UINT32)s[0x1D] << 8) |
                             ((UINT32)s[0x1E] << 16) | ((UINT32)s[0x1F] << 24);
                mb = ext & 0x7FFFFFFFU;
            } else if (raw_sz & 0x8000U) {
                mb = (UINT32)(raw_sz & 0x7FFFU) / 1024U;
            } else {
                mb = (UINT32)raw_sz;
            }
            dm->size_mb   = mb;
            dm->populated = (mb > 0);
            if (dm->populated) {
                gHw.dimm_populated_count++;
                gHw.smbios_ram_mb += mb;
            }
            str_cpy(dm->locator,  smbios_get_string(s, rem, s[0x10], NULL, NULL), sizeof(dm->locator));
            if (!dm->locator[0]) {
                snprintf_ascii(dm->locator, sizeof(dm->locator), "DIMM_%u", (UINT32)(gHw.dimm_count - 1));
            }
            str_cpy(dm->mem_type, smbios_mem_type_str(s[0x12]), sizeof(dm->mem_type));
            if (hlen >= 0x17) {
                dm->speed_mhz = (UINT16)s[0x15] | ((UINT16)s[0x16] << 8);
            }
            if (hlen >= 0x1B) {
                str_cpy(dm->manufacturer, smbios_get_string(s, rem, s[0x17], NULL, NULL), sizeof(dm->manufacturer));
                str_cpy(dm->serial,       smbios_get_string(s, rem, s[0x18], NULL, NULL), sizeof(dm->serial));
                str_cpy(dm->part_number,  smbios_get_string(s, rem, s[0x1A], NULL, NULL), sizeof(dm->part_number));
                trim_ascii_spaces(dm->part_number);
                trim_ascii_spaces(dm->manufacturer);
            }
        }

        if (next_off <= off) break;
        off = next_off;
    }

    if (gRT && gRT->GetVariable) {
        UINT8 mlb_buf[64];
        UINTN mlb_sz = sizeof(mlb_buf) - 1;
        if (!EFI_ERROR(gRT->GetVariable(L"MLB", &gAppleFirmwareVariableGuid, NULL, &mlb_sz, mlb_buf)) && mlb_sz > 0) {
            mlb_buf[mlb_sz] = 0;
            gHw.is_apple_mac = TRUE;
            if (!gHw.board_serial[0] || str_cmp(gHw.board_serial, "Not Specified") == 0) {
                str_cpy(gHw.board_serial, (CHAR8 *)mlb_buf, sizeof(gHw.board_serial));
            }
        }
        UINT8 ssn_buf[64];
        UINTN ssn_sz = sizeof(ssn_buf) - 1;
        if (!EFI_ERROR(gRT->GetVariable(L"SSN", &gAppleFirmwareVariableGuid, NULL, &ssn_sz, ssn_buf)) && ssn_sz > 0) {
            ssn_buf[ssn_sz] = 0;
            gHw.is_apple_mac = TRUE;
            if (!gHw.sys_serial[0] || str_cmp(gHw.sys_serial, "Not Specified") == 0) {
                str_cpy(gHw.sys_serial, (CHAR8 *)ssn_buf, sizeof(gHw.sys_serial));
            }
        }
    }

    if (str_contains_icase(gHw.fw_vendor, "Apple") ||
        str_contains_icase(gHw.sys_manufacturer, "Apple") ||
        str_contains_icase(gHw.bios_vendor, "Apple")) {
        gHw.is_apple_mac = TRUE;
    }
}

VOID hw_refresh_memory_summary(VOID) {
    if (!gBS || !gBS->GetMemoryMap) return;

    UINTN map_sz = 0, map_key = 0, desc_sz = 0;
    UINT32 desc_ver = 0;
    EFI_STATUS st = gBS->GetMemoryMap(&map_sz, NULL, &map_key, &desc_sz, &desc_ver);
    if (st != EFI_BUFFER_TOO_SMALL || map_sz == 0) return;

    map_sz += 8 * (desc_sz ? desc_sz : sizeof(EFI_MEMORY_DESCRIPTOR));
    UINT8 *buf = (UINT8 *)alloc_pool(map_sz);
    if (!buf) return;

    st = gBS->GetMemoryMap(&map_sz, (EFI_MEMORY_DESCRIPTOR *)buf, &map_key, &desc_sz, &desc_ver);
    if (!EFI_ERROR(st) && desc_sz >= sizeof(EFI_MEMORY_DESCRIPTOR)) {
        gHw.total_ram_bytes    = 0;
        gHw.usable_ram_bytes   = 0;
        gHw.acpi_ram_bytes     = 0;
        gHw.runtime_ram_bytes  = 0;
        gHw.boot_svcs_bytes    = 0;
        gHw.reserved_ram_bytes = 0;
        gHw.mmio_bytes         = 0;
        gHw.mem_desc_count     = 0;

        for (UINTN off = 0; off + desc_sz <= map_sz; off += desc_sz) {
            const EFI_MEMORY_DESCRIPTOR *d = (const EFI_MEMORY_DESCRIPTOR *)(buf + off);
            UINT64 bytes = d->NumberOfPages << 12;
            gHw.mem_desc_count++;

            switch (d->Type) {
                case EfiConventionalMemory:
                    gHw.usable_ram_bytes += bytes;
                    gHw.total_ram_bytes  += bytes;
                    break;
                case EfiLoaderCode:
                case EfiLoaderData:
                case EfiBootServicesCode:
                case EfiBootServicesData:
                    gHw.boot_svcs_bytes += bytes;
                    gHw.total_ram_bytes += bytes;
                    break;
                case EfiRuntimeServicesCode:
                case EfiRuntimeServicesData:
                case EfiPalCode:
                    gHw.runtime_ram_bytes += bytes;
                    gHw.total_ram_bytes   += bytes;
                    break;
                case EfiACPIReclaimMemory:
                case EfiACPIMemoryNVS:
                    gHw.acpi_ram_bytes  += bytes;
                    gHw.total_ram_bytes += bytes;
                    break;
                case EfiPersistentMemory:
                    gHw.total_ram_bytes += bytes;
                    break;
                case EfiMemoryMappedIO:
                case EfiMemoryMappedIOPortSpace:
                    gHw.mmio_bytes += bytes;
                    break;
                default:
                    gHw.reserved_ram_bytes += bytes;
                    break;
            }
        }
    }
    free_pool(buf);
}

static BOOLEAN verify_acpi_checksum(UINT64 addr, UINT32 len) {
    if (len == 0 || len > 0x400000U) return FALSE;
    UINT8 sum = 0;
    for (UINT32 i = 0; i < len; i++) {
        BOOLEAN mapped = FALSE;
        if (!cpu_probe_address(addr + i, &mapped, NULL) || !mapped) return FALSE;
        sum = (UINT8)(sum + *(const volatile UINT8 *)(UINTN)(addr + i));
    }
    return (sum == 0);
}

static VOID parse_madt_and_mcfg(const ACPI_SDT_HEADER *sdt, UINT64 addr) {
    const UINT8 *raw = (const UINT8 *)sdt;
    UINT32 len = sdt->Length;

    /* ACPI MADT ("APIC"): Count enabled Local APIC (Type 0) & Local x2APIC (Type 9) threads */
    if (memcmp(sdt->Signature, "APIC", 4) == 0 && len >= 44) {
        BOOLEAN mapped = FALSE;
        if (cpu_probe_address(addr + len - 1, &mapped, NULL) && mapped) {
            UINT32 count = 0;
            UINT32 off = 44;
            while (off + 2 <= len) {
                UINT8 stype = raw[off];
                UINT8 slen  = raw[off + 1];
                if (slen < 2 || off + slen > len) break;
                if (stype == 0 && slen >= 8) {
                    UINT32 flags = 0;
                    memcpy(&flags, raw + off + 4, 4);
                    if ((flags & 1U) != 0) count++;
                } else if (stype == 9 && slen >= 16) {
                    UINT32 flags = 0;
                    memcpy(&flags, raw + off + 8, 4);
                    if ((flags & 1U) != 0) count++;
                }
                off += slen;
            }
            if (count > 0) gHw.cpu_madt_threads = count;
        }
    }

    /* ACPI MCFG: Record PCIe ECAM Base Address for Extended Capabilities (ReBAR etc.) */
    if (memcmp(sdt->Signature, "MCFG", 4) == 0 && len >= 60) {
        BOOLEAN mapped = FALSE;
        if (cpu_probe_address(addr + 59, &mapped, NULL) && mapped) {
            UINT64 ecam = 0;
            memcpy(&ecam, raw + 44, 8);
            gHw.mcfg_ecam_base = ecam;
        }
    }
}

static VOID record_acpi_sdt(UINT64 addr) {
    if (addr == 0 || gHw.acpi_count >= HW_MAX_ACPI_TABLES) return;
#if !defined(__x86_64__) && !defined(_M_X64)
    if (addr > 0xFFFFFFFFULL) return;
#endif
    for (UINTN i = 0; i < gHw.acpi_count; i++) {
        if (gHw.acpi_tables[i].phys_addr == addr) return;
    }

    BOOLEAN mapped = FALSE, writable = FALSE;
    if (!cpu_probe_address(addr, &mapped, &writable) || !mapped) return;
    if (!cpu_probe_address(addr + sizeof(ACPI_SDT_HEADER) - 1, &mapped, NULL) || !mapped) return;

    const ACPI_SDT_HEADER *sdt = (const ACPI_SDT_HEADER *)(UINTN)addr;
    if (sdt->Length < sizeof(ACPI_SDT_HEADER) || sdt->Length > 0x400000U) return;

    HW_ACPI_TABLE_INFO *ti = &gHw.acpi_tables[gHw.acpi_count++];
    memset(ti, 0, sizeof(*ti));
    memcpy(ti->signature, sdt->Signature, 4);
    ti->signature[4] = '\0';
    memcpy(ti->oem_id, sdt->OemId, 6);
    ti->oem_id[6] = '\0';
    trim_ascii_spaces(ti->oem_id);
    memcpy(ti->oem_table_id, sdt->OemTableId, 8);
    ti->oem_table_id[8] = '\0';
    trim_ascii_spaces(ti->oem_table_id);

    ti->phys_addr   = addr;
    ti->length      = sdt->Length;
    ti->revision    = sdt->Revision;
    ti->writable    = writable;
    ti->checksum_ok = verify_acpi_checksum(addr, sdt->Length);

    parse_madt_and_mcfg(sdt, addr);

    if (memcmp(sdt->Signature, "FACP", 4) == 0 && sdt->Length >= 44) {
        const UINT8 *raw = (const UINT8 *)sdt;
        UINT32 facs32 = *(const UINT32 *)(raw + 36);
        UINT32 dsdt32 = *(const UINT32 *)(raw + 40);
        UINT64 dsdt64 = 0;
        if (sdt->Length >= 148) {
            dsdt64 = *(const UINT64 *)(raw + 140);
        }
        if (dsdt64 != 0) record_acpi_sdt(dsdt64);
        else if (dsdt32 != 0) record_acpi_sdt((UINT64)dsdt32);
        if (facs32 != 0 && gHw.acpi_count < HW_MAX_ACPI_TABLES) {
            if (cpu_probe_address((UINT64)facs32, &mapped, &writable) && mapped) {
                const UINT8 *f = (const UINT8 *)(UINTN)facs32;
                if (memcmp(f, "FACS", 4) == 0) {
                    HW_ACPI_TABLE_INFO *fi = &gHw.acpi_tables[gHw.acpi_count++];
                    memset(fi, 0, sizeof(*fi));
                    str_cpy(fi->signature, "FACS", sizeof(fi->signature));
                    str_cpy(fi->oem_id, "FACS", sizeof(fi->oem_id));
                    fi->phys_addr   = (UINT64)facs32;
                    fi->length      = *(const UINT32 *)(f + 4);
                    fi->writable    = writable;
                    fi->checksum_ok = TRUE;
                }
            }
        }
    }
}

static VOID collect_acpi_info(VOID) {
    if (!gST || !gST->ConfigurationTable) return;
    VOID *rsdp_ptr = NULL;
    for (UINTN i = 0; i < gST->NumberOfTableEntries; i++) {
        if (guid_equal(&gST->ConfigurationTable[i].VendorGuid, &gEfiAcpi20TableGuid)) {
            rsdp_ptr = gST->ConfigurationTable[i].VendorTable;
            break;
        }
        if (guid_equal(&gST->ConfigurationTable[i].VendorGuid, &gEfiAcpi10TableGuid)) {
            rsdp_ptr = gST->ConfigurationTable[i].VendorTable;
        }
    }
    if (!rsdp_ptr) return;

    UINT64 raddr = (UINT64)(UINTN)rsdp_ptr;
    BOOLEAN mapped = FALSE;
    if (!cpu_probe_address(raddr, &mapped, NULL) || !mapped) return;

    const ACPI_RSDP *rsdp = (const ACPI_RSDP *)rsdp_ptr;
    if (memcmp(rsdp->Signature, "RSD PTR ", 8) != 0) return;

    gHw.acpi_rsdp_addr = raddr;
    gHw.acpi_revision  = rsdp->Revision;
    memcpy(gHw.acpi_oem_id, rsdp->OemId, 6);
    gHw.acpi_oem_id[6] = '\0';
    trim_ascii_spaces(gHw.acpi_oem_id);

    if (rsdp->Revision >= 2 && rsdp->XsdtAddress != 0) {
#if defined(__x86_64__) || defined(_M_X64)
        UINT64 xaddr = rsdp->XsdtAddress;
        if (cpu_probe_address(xaddr, &mapped, NULL) && mapped) {
            record_acpi_sdt(xaddr);
            const ACPI_SDT_HEADER *xsdt = (const ACPI_SDT_HEADER *)(UINTN)xaddr;
            if (memcmp(xsdt->Signature, "XSDT", 4) == 0 && xsdt->Length >= sizeof(ACPI_SDT_HEADER)) {
                UINTN entries = (xsdt->Length - sizeof(ACPI_SDT_HEADER)) / 8;
                const UINT8 *ents = (const UINT8 *)xsdt + sizeof(ACPI_SDT_HEADER);
                for (UINTN i = 0; i < entries && gHw.acpi_count < HW_MAX_ACPI_TABLES; i++) {
                    UINT64 entry_addr = 0;
                    memcpy(&entry_addr, ents + i * 8, 8);
                    record_acpi_sdt(entry_addr);
                }
                return;
            }
        }
#endif
    }

    if (rsdp->RsdtAddress != 0) {
        UINT64 r32 = (UINT64)rsdp->RsdtAddress;
        if (cpu_probe_address(r32, &mapped, NULL) && mapped) {
            record_acpi_sdt(r32);
            const ACPI_SDT_HEADER *rsdt = (const ACPI_SDT_HEADER *)(UINTN)r32;
            if (memcmp(rsdt->Signature, "RSDT", 4) == 0 && rsdt->Length >= sizeof(ACPI_SDT_HEADER)) {
                UINTN entries = (rsdt->Length - sizeof(ACPI_SDT_HEADER)) / 4;
                const UINT8 *ents = (const UINT8 *)rsdt + sizeof(ACPI_SDT_HEADER);
                for (UINTN i = 0; i < entries && gHw.acpi_count < HW_MAX_ACPI_TABLES; i++) {
                    UINT32 entry_addr = 0;
                    memcpy(&entry_addr, ents + i * 4, 4);
                    record_acpi_sdt((UINT64)entry_addr);
                }
            }
        }
    }
}

VOID hw_refresh_acpi_status(VOID) {
    for (UINTN i = 0; i < gHw.acpi_count; i++) {
        HW_ACPI_TABLE_INFO *ti = &gHw.acpi_tables[i];
        BOOLEAN mapped = FALSE, writable = FALSE;
        cpu_probe_address(ti->phys_addr, &mapped, &writable);
        ti->writable = writable;
        if (str_cmp(ti->signature, "FACS") != 0) {
            ti->checksum_ok = verify_acpi_checksum(ti->phys_addr, ti->length);
        }
    }
}

BOOLEAN hw_acpi_fix_checksum(UINTN table_idx) {
    if (table_idx >= gHw.acpi_count) return FALSE;
    HW_ACPI_TABLE_INFO *ti = &gHw.acpi_tables[table_idx];
    if (str_cmp(ti->signature, "FACS") == 0 || ti->length < sizeof(ACPI_SDT_HEADER)) return FALSE;

    UINT8 sum = 0;
    for (UINT32 i = 0; i < ti->length; i++) {
        if (i == 9) continue;
        BOOLEAN mapped = FALSE;
        if (!cpu_probe_address(ti->phys_addr + i, &mapped, NULL) || !mapped) return FALSE;
        sum = (UINT8)(sum + *(const volatile UINT8 *)(UINTN)(ti->phys_addr + i));
    }
    UINT8 new_csum = (UINT8)(0U - (UINT32)sum);
    BOOLEAN verified = FALSE;
    if (!safe_write_byte(ti->phys_addr + 9, new_csum, &verified) || !verified) {
        return FALSE;
    }
    ti->checksum_ok = verify_acpi_checksum(ti->phys_addr, ti->length);
    return ti->checksum_ok;
}

BOOLEAN hw_patch_smbios_string_in_ram(UINT64 str_addr, UINTN max_len, const CHAR8 *new_str) {
    if (str_addr == 0 || max_len == 0 || !new_str) return FALSE;
    UINTN nlen = str_len(new_str);
    if (nlen == 0) return FALSE;
    if (nlen > max_len) nlen = max_len;

    for (UINTN i = 0; i < max_len; i++) {
        UINT8 ch = (i < nlen) ? (UINT8)new_str[i] : (UINT8)' ';
        BOOLEAN verified = FALSE;
        if (!safe_write_byte(str_addr + i, ch, &verified) || !verified) {
            return FALSE;
        }
    }
    return TRUE;
}

/* =========================================================================
 * PCI / PCIe Capability Probing, Raw BDF Access, GPU VRAM & Intel GMCH GGC
 * ========================================================================= */
static EFI_PCI_IO_PROTOCOL *find_enumerated_pci_io(UINT8 bus, UINT8 dev, UINT8 func) {
    for (UINTN i = 0; i < gHw.pci_count; i++) {
        if (gHw.pci_devs[i].seg == 0 &&
            gHw.pci_devs[i].bus == bus &&
            gHw.pci_devs[i].dev == dev &&
            gHw.pci_devs[i].func == func &&
            gHw.pci_devs[i].pci_io != NULL) {
            return gHw.pci_devs[i].pci_io;
        }
    }
    return NULL;
}

static UINT32 make_cf8_addr(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset) {
    return 0x80000000U |
           ((UINT32)bus << 16) |
           ((UINT32)(dev & 0x1FU) << 11) |
           ((UINT32)(func & 0x07U) << 8) |
           ((UINT32)offset & 0xFCU);
}

BOOLEAN hw_pci_cfg_read8_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT8 *out_val) {
    if (!out_val || dev >= 32 || func >= 8 || offset >= 0x1000U) return FALSE;
    EFI_PCI_IO_PROTOCOL *pio = find_enumerated_pci_io(bus, dev, func);
    if (pio && !EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint8, offset, 1, out_val))) {
        return TRUE;
    }
    if (gHw.mcfg_ecam_base != 0) {
        UINT64 addr = gHw.mcfg_ecam_base +
                      (((UINT64)bus << 20) | ((UINT64)dev << 15) | ((UINT64)func << 12)) + offset;
        if (safe_read_mem(addr, out_val, 1)) return TRUE;
    }
    if (offset < 0x100U) {
        io_out32(0xCF8U, make_cf8_addr(bus, dev, func, offset));
        *out_val = io_in8((UINT16)(0xCFCU + (offset & 3U)));
        return TRUE;
    }
    return FALSE;
}

BOOLEAN hw_pci_cfg_read16_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT16 *out_val) {
    if (!out_val || dev >= 32 || func >= 8 || offset >= 0xFFFU || (offset & 1U) != 0) return FALSE;
    EFI_PCI_IO_PROTOCOL *pio = find_enumerated_pci_io(bus, dev, func);
    if (pio && !EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint16, offset, 1, out_val))) {
        return TRUE;
    }
    if (gHw.mcfg_ecam_base != 0) {
        UINT64 addr = gHw.mcfg_ecam_base +
                      (((UINT64)bus << 20) | ((UINT64)dev << 15) | ((UINT64)func << 12)) + offset;
        if (safe_read_mem(addr, out_val, 2)) return TRUE;
    }
    if (offset < 0x100U) {
        io_out32(0xCF8U, make_cf8_addr(bus, dev, func, offset));
        *out_val = io_in16((UINT16)(0xCFCU + (offset & 2U)));
        return TRUE;
    }
    return FALSE;
}

BOOLEAN hw_pci_cfg_read32_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT32 *out_val) {
    if (!out_val || dev >= 32 || func >= 8 || offset >= 0xFFDU || (offset & 3U) != 0) return FALSE;
    EFI_PCI_IO_PROTOCOL *pio = find_enumerated_pci_io(bus, dev, func);
    if (pio && !EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint32, offset, 1, out_val))) {
        return TRUE;
    }
    if (gHw.mcfg_ecam_base != 0) {
        UINT64 addr = gHw.mcfg_ecam_base +
                      (((UINT64)bus << 20) | ((UINT64)dev << 15) | ((UINT64)func << 12)) + offset;
        if (safe_read_mem(addr, out_val, 4)) return TRUE;
    }
    if (offset < 0x100U) {
        io_out32(0xCF8U, make_cf8_addr(bus, dev, func, offset));
        *out_val = io_in32(0xCFCU);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN hw_pci_cfg_write8_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT8 val) {
    if (dev >= 32 || func >= 8 || offset >= 0x1000U) return FALSE;
    EFI_PCI_IO_PROTOCOL *pio = find_enumerated_pci_io(bus, dev, func);
    if (pio && !EFI_ERROR(pio->Pci.Write(pio, EfiPciIoWidthUint8, offset, 1, &val))) {
        return TRUE;
    }
    if (gHw.mcfg_ecam_base != 0) {
        UINT64 addr = gHw.mcfg_ecam_base +
                      (((UINT64)bus << 20) | ((UINT64)dev << 15) | ((UINT64)func << 12)) + offset;
        BOOLEAN mapped = FALSE, writable = FALSE;
        if (cpu_probe_address(addr, &mapped, &writable) && mapped && writable) {
            *(volatile UINT8 *)(UINTN)addr = val;
            return TRUE;
        }
    }
    if (offset < 0x100U) {
        io_out32(0xCF8U, make_cf8_addr(bus, dev, func, offset));
        io_out8((UINT16)(0xCFCU + (offset & 3U)), val);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN hw_pci_cfg_write16_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT16 val) {
    if (dev >= 32 || func >= 8 || offset >= 0xFFFU || (offset & 1U) != 0) return FALSE;
    EFI_PCI_IO_PROTOCOL *pio = find_enumerated_pci_io(bus, dev, func);
    if (pio && !EFI_ERROR(pio->Pci.Write(pio, EfiPciIoWidthUint16, offset, 1, &val))) {
        return TRUE;
    }
    if (gHw.mcfg_ecam_base != 0) {
        UINT64 addr = gHw.mcfg_ecam_base +
                      (((UINT64)bus << 20) | ((UINT64)dev << 15) | ((UINT64)func << 12)) + offset;
        BOOLEAN mapped = FALSE, writable = FALSE;
        if (cpu_probe_address(addr, &mapped, &writable) && mapped && writable) {
            *(volatile UINT16 *)(UINTN)addr = val;
            return TRUE;
        }
    }
    if (offset < 0x100U) {
        io_out32(0xCF8U, make_cf8_addr(bus, dev, func, offset));
        io_out16((UINT16)(0xCFCU + (offset & 2U)), val);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN hw_pci_cfg_write32_raw(UINT8 bus, UINT8 dev, UINT8 func, UINT16 offset, UINT32 val) {
    if (dev >= 32 || func >= 8 || offset >= 0xFFDU || (offset & 3U) != 0) return FALSE;
    EFI_PCI_IO_PROTOCOL *pio = find_enumerated_pci_io(bus, dev, func);
    if (pio && !EFI_ERROR(pio->Pci.Write(pio, EfiPciIoWidthUint32, offset, 1, &val))) {
        return TRUE;
    }
    if (gHw.mcfg_ecam_base != 0) {
        UINT64 addr = gHw.mcfg_ecam_base +
                      (((UINT64)bus << 20) | ((UINT64)dev << 15) | ((UINT64)func << 12)) + offset;
        BOOLEAN mapped = FALSE, writable = FALSE;
        if (cpu_probe_address(addr, &mapped, &writable) && mapped && writable) {
            *(volatile UINT32 *)(UINTN)addr = val;
            return TRUE;
        }
    }
    if (offset < 0x100U) {
        io_out32(0xCF8U, make_cf8_addr(bus, dev, func, offset));
        io_out32(0xCFCU, val);
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN is_gen8_plus_intel_cpu(VOID) {
    if (gHw.cpu_family != 6) return FALSE;
    /* Broadwell (0x3D, 0x47, 0x4F, 0x56) and Skylake+ (>= 0x4E) */
    if (gHw.cpu_model == 0x3DU || gHw.cpu_model == 0x47U || gHw.cpu_model >= 0x4EU) {
        return TRUE;
    }
    return FALSE;
}

VOID hw_refresh_igd_ggc(VOID) {
    gHw.igd_ggc_present = FALSE;
    if (gHw.cpu_family != 6 || gHw.cpu_model < 0x2AU) return;

    for (UINTN i = 0; i < gHw.pci_count; i++) {
        HW_PCI_DEV_INFO *pd = &gHw.pci_devs[i];
        if (pd->seg == 0 && pd->bus == 0 && pd->dev == 0 && pd->func == 0 &&
            pd->vendor_id == 0x8086U &&
            pd->device_id != 0x29C0U && pd->device_id != 0x1237U) {
            UINT16 ggc = 0xFFFFU;
            if (!EFI_ERROR(pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint16, 0x50, 1, &ggc)) &&
                ggc != 0xFFFFU) {
                gHw.igd_ggc_present  = TRUE;
                gHw.igd_host_pci_idx = i;
                gHw.igd_ggc_raw      = ggc;
                gHw.igd_ggc_locked   = ((ggc & 0x0001U) != 0);
                gHw.igd_vga_disable  = ((ggc & 0x0002U) != 0);

                if (is_gen8_plus_intel_cpu()) {
                    UINT8 ggms = (UINT8)((ggc >> 6) & 0x03U);
                    UINT8 gms  = (UINT8)((ggc >> 8) & 0xFFU);
                    gHw.igd_gtt_mb = (ggms == 0) ? 0 : (1U << ggms);
                    if (gms <= 0x40U) gHw.igd_stolen_mb = (UINT32)gms * 32U;
                    else if (gms >= 0xF0U && gms <= 0xFEU) gHw.igd_stolen_mb = (UINT32)(gms - 0xEFU) * 4U;
                    else gHw.igd_stolen_mb = 0;
                } else {
                    /* Sandy Bridge (MBP Early 2011), Ivy Bridge, Haswell */
                    UINT8 gms  = (UINT8)((ggc >> 3) & 0x1FU);
                    UINT8 ggms = (UINT8)((ggc >> 8) & 0x03U);
                    gHw.igd_gtt_mb    = (ggms <= 2) ? ggms : 2;
                    gHw.igd_stolen_mb = (gms <= 0x10U) ? ((UINT32)gms * 32U) : 0;
                }
            }
            break;
        }
    }
}

BOOLEAN hw_igd_set_stolen_vram_mb(UINT32 target_mb) {
    hw_refresh_igd_ggc();
    if (!gHw.igd_ggc_present || gHw.igd_ggc_locked) return FALSE;
    EFI_PCI_IO_PROTOCOL *pio = gHw.pci_devs[gHw.igd_host_pci_idx].pci_io;
    if (!pio) return FALSE;

    UINT16 ggc = gHw.igd_ggc_raw;
    UINT8 gms = (UINT8)(target_mb / 32U);
    if (gms > 0x10U) gms = 0x10U;

    if (is_gen8_plus_intel_cpu()) {
        ggc = (UINT16)((ggc & 0x00FFU) | ((UINT16)gms << 8));
    } else {
        ggc = (UINT16)((ggc & ~(0x1FU << 3)) | ((UINT16)(gms & 0x1FU) << 3));
    }
    if (EFI_ERROR(pio->Pci.Write(pio, EfiPciIoWidthUint16, 0x50, 1, &ggc))) return FALSE;
    hw_refresh_igd_ggc();
    return (gHw.igd_stolen_mb == (UINT32)gms * 32U);
}

BOOLEAN hw_igd_set_vga_disable(BOOLEAN disable_igd) {
    hw_refresh_igd_ggc();
    if (!gHw.igd_ggc_present || gHw.igd_ggc_locked) return FALSE;
    EFI_PCI_IO_PROTOCOL *pio = gHw.pci_devs[gHw.igd_host_pci_idx].pci_io;
    if (!pio) return FALSE;

    UINT16 ggc = disable_igd ? (UINT16)(gHw.igd_ggc_raw | 0x0002U)
                             : (UINT16)(gHw.igd_ggc_raw & ~0x0002U);
    if (EFI_ERROR(pio->Pci.Write(pio, EfiPciIoWidthUint16, 0x50, 1, &ggc))) return FALSE;
    hw_refresh_igd_ggc();
    return (gHw.igd_vga_disable == (disable_igd != FALSE));
}

VOID hw_refresh_pci_dev(UINTN pci_idx) {
    if (pci_idx >= gHw.pci_count) return;
    HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];
    EFI_PCI_IO_PROTOCOL *pio = pd->pci_io;
    if (!pio) return;

    UINT16 cmd_sts[2] = { 0, 0 };
    if (!EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint16, 0x04, 2, cmd_sts))) {
        pd->command = cmd_sts[0];
        pd->status  = cmd_sts[1];
    }

    pd->pcie_cap_off = 0;
    UINT8 hdr_type = 0;
    pio->Pci.Read(pio, EfiPciIoWidthUint8, 0x0E, 1, &hdr_type);
    if ((pd->status & 0x0010U) != 0 && (hdr_type & 0x7FU) <= 1) {
        UINT8 cap_ptr = 0;
        pio->Pci.Read(pio, EfiPciIoWidthUint8, 0x34, 1, &cap_ptr);
        cap_ptr &= 0xFCU;
        for (UINTN hops = 0; hops < 48 && cap_ptr >= 0x40U; hops++) {
            UINT8 cap_hdr[2] = { 0, 0 };
            if (EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint8, cap_ptr, 2, cap_hdr))) break;
            if (cap_hdr[0] == 0x10U) { /* PCI Express Capability */
                pd->pcie_cap_off = cap_ptr;
                UINT16 pcie_flags = 0;
                pio->Pci.Read(pio, EfiPciIoWidthUint16, cap_ptr + 0x02U, 1, &pcie_flags);
                pd->pcie_cap_ver   = (UINT8)(pcie_flags & 0x0FU);
                pd->pcie_port_type = (UINT8)((pcie_flags >> 4) & 0x0FU);

                UINT16 dev_ctl = 0;
                if (!EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint16, cap_ptr + 0x08U, 1, &dev_ctl))) {
                    pd->pcie_relaxed_ord  = ((dev_ctl & (1U << 4)) != 0);
                    pd->pcie_max_read_req = (UINT8)((dev_ctl >> 12) & 0x07U);
                }

                UINT32 lnk_cap = 0;
                if (!EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint32, cap_ptr + 0x0CU, 1, &lnk_cap))) {
                    pd->pcie_max_speed = (UINT8)(lnk_cap & 0x0FU);
                    pd->pcie_max_width = (UINT8)((lnk_cap >> 4) & 0x3FU);
                    pd->pcie_aspm_sup  = (UINT8)((lnk_cap >> 10) & 0x03U);
                }

                UINT16 lnk_ctl_sts[2] = { 0, 0 };
                if (!EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint16, cap_ptr + 0x10U, 2, lnk_ctl_sts))) {
                    pd->pcie_aspm_cur  = (UINT8)(lnk_ctl_sts[0] & 0x03U);
                    pd->pcie_cur_speed = (UINT8)(lnk_ctl_sts[1] & 0x0FU);
                    pd->pcie_cur_width = (UINT8)((lnk_ctl_sts[1] >> 4) & 0x3FU);
                }

                if (pd->pcie_cap_ver >= 2 && (UINT32)cap_ptr + 0x32U <= 0x100U) {
                    UINT16 lnk_ctl2 = 0;
                    if (!EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint16, cap_ptr + 0x30U, 1, &lnk_ctl2))) {
                        pd->pcie_target_speed = (UINT8)(lnk_ctl2 & 0x0FU);
                    }
                }
                break;
            }
            cap_ptr = (UINT8)(cap_hdr[1] & 0xFCU);
        }
    }
}

BOOLEAN hw_pci_set_aspm(UINTN pci_idx, UINT8 aspm_val) {
    if (pci_idx >= gHw.pci_count || aspm_val > 3) return FALSE;
    HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];
    if (!pd->pci_io || pd->pcie_cap_off == 0) return FALSE;
    UINT16 lctl = 0;
    if (EFI_ERROR(pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x10U, 1, &lctl)))
        return FALSE;
    lctl = (UINT16)((lctl & ~0x0003U) | (aspm_val & 0x03U));
    if (EFI_ERROR(pd->pci_io->Pci.Write(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x10U, 1, &lctl)))
        return FALSE;
    hw_refresh_pci_dev(pci_idx);
    return (pd->pcie_aspm_cur == aspm_val);
}

BOOLEAN hw_pci_set_target_speed(UINTN pci_idx, UINT8 target_gen) {
    if (pci_idx >= gHw.pci_count || target_gen < 1 || target_gen > 5) return FALSE;
    HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];
    if (!pd->pci_io || pd->pcie_cap_off == 0 || pd->pcie_cap_ver < 2) return FALSE;
    UINT16 lctl2 = 0;
    if (EFI_ERROR(pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x30U, 1, &lctl2)))
        return FALSE;
    lctl2 = (UINT16)((lctl2 & ~0x000FU) | (target_gen & 0x0FU));
    if (EFI_ERROR(pd->pci_io->Pci.Write(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x30U, 1, &lctl2)))
        return FALSE;

    /* Trigger Link Retrain (bit 5) if this is a Root Port (4) or Downstream Port (6) */
    if (pd->pcie_port_type == 4 || pd->pcie_port_type == 6) {
        UINT16 lctl = 0;
        if (!EFI_ERROR(pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x10U, 1, &lctl))) {
            lctl |= (1U << 5);
            pd->pci_io->Pci.Write(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x10U, 1, &lctl);
            if (gBS && gBS->Stall) gBS->Stall(20000);
        }
    }
    hw_refresh_pci_dev(pci_idx);
    return (pd->pcie_target_speed == target_gen);
}

BOOLEAN hw_pci_set_relaxed_ordering(UINTN pci_idx, BOOLEAN enable) {
    if (pci_idx >= gHw.pci_count) return FALSE;
    HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];
    if (!pd->pci_io || pd->pcie_cap_off == 0) return FALSE;
    UINT16 dctl = 0;
    if (EFI_ERROR(pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x08U, 1, &dctl)))
        return FALSE;
    if (enable) dctl |= (1U << 4);
    else dctl &= ~(1U << 4);
    if (EFI_ERROR(pd->pci_io->Pci.Write(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x08U, 1, &dctl)))
        return FALSE;
    hw_refresh_pci_dev(pci_idx);
    return (pd->pcie_relaxed_ord == (enable != FALSE));
}

BOOLEAN hw_pci_set_max_read_req(UINTN pci_idx, UINT8 mr_code) {
    if (pci_idx >= gHw.pci_count || mr_code > 5) return FALSE;
    HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];
    if (!pd->pci_io || pd->pcie_cap_off == 0) return FALSE;
    UINT16 dctl = 0;
    if (EFI_ERROR(pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x08U, 1, &dctl)))
        return FALSE;
    dctl = (UINT16)((dctl & ~(0x07U << 12)) | ((UINT16)(mr_code & 0x07U) << 12));
    if (EFI_ERROR(pd->pci_io->Pci.Write(pd->pci_io, EfiPciIoWidthUint16, pd->pcie_cap_off + 0x08U, 1, &dctl)))
        return FALSE;
    hw_refresh_pci_dev(pci_idx);
    return (pd->pcie_max_read_req == mr_code);
}

BOOLEAN hw_pci_set_command_bit(UINTN pci_idx, UINT16 mask, BOOLEAN enable) {
    if (pci_idx >= gHw.pci_count) return FALSE;
    HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];
    if (!pd->pci_io) return FALSE;
    UINT16 cmd = 0;
    if (EFI_ERROR(pd->pci_io->Pci.Read(pd->pci_io, EfiPciIoWidthUint16, 0x04, 1, &cmd))) return FALSE;
    if (enable) cmd |= mask;
    else cmd &= ~mask;
    if (EFI_ERROR(pd->pci_io->Pci.Write(pd->pci_io, EfiPciIoWidthUint16, 0x04, 1, &cmd))) return FALSE;
    hw_refresh_pci_dev(pci_idx);
    return (((pd->command & mask) != 0) == (enable != FALSE));
}

static VOID probe_gpu_vram_and_rebar(HW_PCI_DEV_INFO *pd) {
    EFI_PCI_IO_PROTOCOL *pio = pd->pci_io;
    if (!pio || pd->class_code != 0x03U) return;

    /* 1. Exact UEFI PCI Bus Driver BAR Resource Query (non-destructive!) */
    if (pio->GetBarAttributes != NULL) {
        PCI_GET_BAR_ATTR_FN get_bar = (PCI_GET_BAR_ATTR_FN)pio->GetBarAttributes;
        UINT64 best_pref_len = 0, best_pref_base = 0;
        UINT64 best_any_len  = 0, best_any_base  = 0;
        for (UINT8 b = 0; b < 6; b++) {
            VOID *res = NULL;
            UINT64 sup = 0;
            if (!EFI_ERROR(get_bar(pio, b, &sup, &res)) && res) {
                const ACPI_QWORD_ADDR_SPACE_DESC *q = (const ACPI_QWORD_ADDR_SPACE_DESC *)res;
                if (q->Desc == 0x8AU && q->ResType == 0 && q->AddrLen > 0) {
                    BOOLEAN pref = (((q->SpecificFlag >> 1) & 0x3U) == 0x3U);
                    if (pref && q->AddrLen > best_pref_len) {
                        best_pref_len  = q->AddrLen;
                        best_pref_base = q->AddrRangeMin;
                    }
                    if (q->AddrLen > best_any_len) {
                        best_any_len  = q->AddrLen;
                        best_any_base = q->AddrRangeMin;
                    }
                }
                free_pool(res);
            }
        }
        if (best_pref_len > 0) {
            pd->vram_bar_size = best_pref_len;
            pd->vram_bar_base = best_pref_base;
        } else if (best_any_len >= (8ULL << 20)) {
            pd->vram_bar_size = best_any_len;
            pd->vram_bar_base = best_any_base;
        }
    }

    /* 2. Fallback for EFI 1.10 (MacBook Pro Early 2011): inspect Prefetchable Memory BARs 0..5 */
    if (pd->vram_bar_base == 0) {
        UINT32 bars[6];
        memset(bars, 0, sizeof(bars));
        if (!EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint32, 0x10, 6, bars))) {
            for (UINTN b = 0; b < 6; b++) {
                UINT32 raw = bars[b];
                if (raw == 0 || (raw & 1U) != 0) continue;
                BOOLEAN is64 = (((raw >> 1) & 3U) == 2U);
                BOOLEAN pref = ((raw & 8U) != 0);
                UINT64 base  = (UINT64)(raw & ~0xFULL);
                if (is64 && b + 1 < 6) {
                    base |= ((UINT64)bars[b + 1] << 32);
                    b++;
                }
                if (pref && base != 0) {
                    pd->vram_bar_base = base;
                    /* Lower alignment bound (power-of-two) capped at 4GB */
                    UINT64 align = base & (~base + 1ULL);
                    if (align >= (16ULL << 20) && align <= (4096ULL << 20)) {
                        pd->vram_bar_size = align;
                    }
                    break;
                }
            }
        }
    }

    /* 3. Check PCIe Extended Capability 0x0015 (Resizable BAR) via ECAM if mapped */
    if (gHw.mcfg_ecam_base != 0 && pd->seg == 0) {
        UINT64 ecam_dev = gHw.mcfg_ecam_base +
                          (((UINT64)pd->bus << 20) | ((UINT64)pd->dev << 15) | ((UINT64)pd->func << 12));
        UINT16 off = 0x100U;
        for (UINTN hops = 0; hops < 48 && off >= 0x100U && off <= 0xFFCU; hops++) {
            UINT32 hdr = 0;
            if (!safe_read_mem(ecam_dev + off, &hdr, 4) || hdr == 0 || hdr == 0xFFFFFFFFU) break;
            UINT16 ext_id = (UINT16)(hdr & 0xFFFFU);
            if (ext_id == 0x0015U) {
                pd->rebar_supported = TRUE;
                UINT32 ctl0 = 0;
                UINTN num_rbars = 1;
                if (safe_read_mem(ecam_dev + off + 8U, &ctl0, 4)) {
                    num_rbars = (UINTN)((ctl0 >> 5) & 0x7U);
                    if (num_rbars == 0 || num_rbars > 6) num_rbars = 1;
                }
                UINT8 best_max_exp = 0;
                for (UINTN bi = 0; bi < num_rbars; bi++) {
                    UINT16 eoff = (UINT16)(off + 4U + bi * 8U);
                    UINT32 cap_r = 0, ctl_r = 0;
                    if (!safe_read_mem(ecam_dev + eoff, &cap_r, 4) ||
                        !safe_read_mem(ecam_dev + eoff + 4U, &ctl_r, 4)) continue;
                    UINT8 max_e = 0;
                    for (UINT8 bbit = 4; bbit < 32; bbit++) {
                        if (cap_r & (1U << bbit)) max_e = (UINT8)(bbit - 4U);
                    }
                    if (max_e >= best_max_exp && cap_r != 0) {
                        best_max_exp           = max_e;
                        pd->rebar_ext_off      = eoff;
                        pd->rebar_cap_mask     = cap_r;
                        pd->rebar_cur_size_exp = (UINT8)((ctl_r >> 8) & 0x3FU);
                        pd->rebar_max_size_exp = max_e;
                    }
                }
                break;
            }
            off = (UINT16)((hdr >> 20) & 0xFFCU);
        }
    }
}

BOOLEAN hw_pci_set_rebar_size_exp(UINTN pci_idx, UINT8 size_exp) {
    if (pci_idx >= gHw.pci_count || size_exp > 24 || gHw.mcfg_ecam_base == 0) return FALSE;
    HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pci_idx];
    if (!pd->rebar_supported || pd->rebar_ext_off < 0x104U || pd->seg != 0) return FALSE;
    if ((pd->rebar_cap_mask & (1U << (size_exp + 4U))) == 0) return FALSE;

    UINT64 ctl_addr = gHw.mcfg_ecam_base +
                      (((UINT64)pd->bus << 20) | ((UINT64)pd->dev << 15) | ((UINT64)pd->func << 12)) +
                      pd->rebar_ext_off + 4U;
    UINT32 ctl_r = 0;
    if (!safe_read_mem(ctl_addr, &ctl_r, 4)) return FALSE;
    UINT32 new_ctl = (ctl_r & ~(0x3FU << 8)) | ((UINT32)(size_exp & 0x3FU) << 8);
    for (UINTN b = 0; b < 4; b++) {
        BOOLEAN ver = FALSE;
        if (!safe_write_byte(ctl_addr + b, (UINT8)((new_ctl >> (b * 8)) & 0xFFU), &ver)) return FALSE;
    }
    UINT32 rd_back = 0;
    if (safe_read_mem(ctl_addr, &rd_back, 4)) {
        pd->rebar_cur_size_exp = (UINT8)((rd_back >> 8) & 0x3FU);
    }
    return (pd->rebar_cur_size_exp == size_exp);
}

static VOID collect_pci_info(VOID) {
    UINTN count = 0;
    EFI_HANDLE *handles = NULL;
    if (EFI_ERROR(efi_locate_handles(&gEfiPciIoProtocolGuid, &count, &handles)) || !handles) {
        return;
    }

    for (UINTN i = 0; i < count && gHw.pci_count < HW_MAX_PCI_DEVS; i++) {
        EFI_PCI_IO_PROTOCOL *pio = NULL;
        if (EFI_ERROR(gBS->HandleProtocol(handles[i], &gEfiPciIoProtocolGuid, (VOID **)&pio)) || !pio) {
            continue;
        }
        UINTN seg = 0, bus = 0, dev = 0, func = 0;
        if (EFI_ERROR(pio->GetLocation(pio, &seg, &bus, &dev, &func))) continue;

        UINT32 cfg[12];
        memset(cfg, 0, sizeof(cfg));
        if (EFI_ERROR(pio->Pci.Read(pio, EfiPciIoWidthUint32, 0, 12, cfg))) continue;

        UINT16 vid = (UINT16)(cfg[0] & 0xFFFFU);
        UINT16 did = (UINT16)((cfg[0] >> 16) & 0xFFFFU);
        if (vid == 0xFFFFU || vid == 0x0000U) continue;

        UINTN pidx = gHw.pci_count++;
        HW_PCI_DEV_INFO *pd = &gHw.pci_devs[pidx];
        memset(pd, 0, sizeof(*pd));
        pd->pci_io           = pio;
        pd->seg              = (UINT16)seg;
        pd->bus              = (UINT8)bus;
        pd->dev              = (UINT8)dev;
        pd->func             = (UINT8)func;
        pd->vendor_id        = vid;
        pd->device_id        = did;
        pd->command          = (UINT16)(cfg[1] & 0xFFFFU);
        pd->status           = (UINT16)((cfg[1] >> 16) & 0xFFFFU);
        pd->rev_id           = (UINT8)(cfg[2] & 0xFFU);
        pd->prog_if          = (UINT8)((cfg[2] >> 8) & 0xFFU);
        pd->subclass         = (UINT8)((cfg[2] >> 16) & 0xFFU);
        pd->class_code       = (UINT8)((cfg[2] >> 24) & 0xFFU);
        pd->bar0             = cfg[4];
        pd->subsys_vendor_id = (UINT16)(cfg[11] & 0xFFFFU);
        pd->subsys_id        = (UINT16)((cfg[11] >> 16) & 0xFFFFU);

        str_cpy(pd->vendor_name, pci_vendor_lookup(vid), sizeof(pd->vendor_name));
        str_cpy(pd->class_name,  pci_class_lookup(pd->class_code, pd->subclass, pd->prog_if), sizeof(pd->class_name));

        hw_refresh_pci_dev(pidx);

        if (pd->class_code == 0x03U) {
            probe_gpu_vram_and_rebar(pd);
            if (gHw.gpu_count < HW_MAX_GPUS) {
                gHw.gpu_pci_indices[gHw.gpu_count++] = pidx;
            }
        }
    }
    free_pool(handles);

    hw_refresh_igd_ggc();
}

static VOID describe_device_path(EFI_HANDLE h, CHAR8 *out, UINTN max_len) {
    out[0] = '\0';
    EFI_DEVICE_PATH_PROTOCOL *dp = NULL;
    if (EFI_ERROR(gBS->HandleProtocol(h, &gEfiDevicePathProtocolGuid, (VOID **)&dp)) || !dp) {
        return;
    }

    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dpt = NULL;
    if (!EFI_ERROR(efi_locate_protocol(&gEfiDevicePathToTextProtocolGuid, (VOID **)&dpt)) && dpt) {
        CHAR16 *txt = dpt->ConvertDevicePathToText(dp, TRUE, TRUE);
        if (txt) {
            wstr_to_ascii(out, txt, max_len);
            free_pool(txt);
            return;
        }
    }

    const EFI_DEVICE_PATH_PROTOCOL *node = dp;
    const CHAR8 *bus_type = "BlockDev";
    for (UINTN guard = 0; guard < 32; guard++) {
        UINT16 nlen = (UINT16)node->Length[0] | ((UINT16)node->Length[1] << 8);
        if (nlen < 4 || node->Type == 0x7F) break;
        if (node->Type == 0x03) {
            if (node->SubType == 0x01) bus_type = "ATAPI/IDE";
            else if (node->SubType == 0x02) bus_type = "SCSI";
            else if (node->SubType == 0x05 || node->SubType == 0x0F || node->SubType == 0x10) bus_type = "USB Drive";
            else if (node->SubType == 0x12) bus_type = "SATA Drive";
            else if (node->SubType == 0x17) bus_type = "NVMe SSD";
            else if (node->SubType == 0x1A) bus_type = "SD/eMMC";
        }
        node = (const EFI_DEVICE_PATH_PROTOCOL *)((const UINT8 *)node + nlen);
    }
    str_cpy(out, bus_type, max_len);
}

static VOID collect_disk_info(VOID) {
    UINTN count = 0;
    EFI_HANDLE *handles = NULL;
    if (EFI_ERROR(efi_locate_handles(&gEfiBlockIoProtocolGuid, &count, &handles)) || !handles) {
        return;
    }

    for (UINTN pass = 0; pass < 2; pass++) {
        for (UINTN i = 0; i < count && gHw.disk_count < HW_MAX_DISKS; i++) {
            EFI_BLOCK_IO_PROTOCOL *bio = NULL;
            if (EFI_ERROR(gBS->HandleProtocol(handles[i], &gEfiBlockIoProtocolGuid, (VOID **)&bio)) ||
                !bio || !bio->Media) {
                continue;
            }
            EFI_BLOCK_IO_MEDIA *m = bio->Media;
            if (!m->MediaPresent || m->BlockSize == 0) continue;
            if (pass == 0 && m->LogicalPartition) continue;
            if (pass == 1 && !m->LogicalPartition) continue;

            HW_DISK_INFO *dk = &gHw.disks[gHw.disk_count++];
            memset(dk, 0, sizeof(*dk));
            dk->media_id     = m->MediaId;
            dk->block_size   = m->BlockSize;
            dk->removable    = m->RemovableMedia;
            dk->read_only    = m->ReadOnly;
            dk->is_partition = m->LogicalPartition;

            UINT64 blocks = m->LastBlock + 1ULL;
            UINT64 bsz = (UINT64)m->BlockSize;
            dk->total_bytes = blocks * bsz;
            dk->size_mb     = dk->total_bytes >> 20;

            describe_device_path(handles[i], dk->label, sizeof(dk->label));
            if (!dk->label[0]) {
                snprintf_ascii(dk->label, sizeof(dk->label),
                               m->LogicalPartition ? "Partition #%u" : "Physical Drive #%u",
                               (UINT32)gHw.disk_count);
            }
        }
    }
    free_pool(handles);
}

static VOID collect_gop_info(VOID) {
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
    if (EFI_ERROR(efi_locate_protocol(&gEfiGraphicsOutputProtocolGuid, (VOID **)&gop)) ||
        !gop || !gop->Mode || !gop->Mode->Info) {
        return;
    }
    gHw.gop_present  = TRUE;
    gHw.gop_cur_mode = gop->Mode->Mode;
    gHw.gop_width    = gop->Mode->Info->HorizontalResolution;
    gHw.gop_height   = gop->Mode->Info->VerticalResolution;
    gHw.gop_fb_base  = gop->Mode->FrameBufferBase;
    gHw.gop_fb_size  = (UINT64)gop->Mode->FrameBufferSize;

    switch (gop->Mode->Info->PixelFormat) {
        case PixelRedGreenBlueReserved8BitPerColor: str_cpy(gHw.gop_format, "RGBR 32-bit", sizeof(gHw.gop_format)); break;
        case PixelBlueGreenRedReserved8BitPerColor: str_cpy(gHw.gop_format, "BGRR 32-bit", sizeof(gHw.gop_format)); break;
        case PixelBitMask:                          str_cpy(gHw.gop_format, "BitMask",     sizeof(gHw.gop_format)); break;
        case PixelBltOnly:                          str_cpy(gHw.gop_format, "BltOnly",     sizeof(gHw.gop_format)); break;
        default:                                    str_cpy(gHw.gop_format, "GOP",         sizeof(gHw.gop_format)); break;
    }

    UINT32 max_m = gop->Mode->MaxMode;
    for (UINT32 m = 0; m < max_m && gHw.gop_mode_count < HW_MAX_GOP_MODES; m++) {
        UINTN info_sz = 0;
        EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info = NULL;
        if (!EFI_ERROR(gop->QueryMode(gop, m, &info_sz, &info)) && info) {
            gHw.gop_modes[gHw.gop_mode_count].mode_num = m;
            gHw.gop_modes[gHw.gop_mode_count].width    = info->HorizontalResolution;
            gHw.gop_modes[gHw.gop_mode_count].height   = info->VerticalResolution;
            gHw.gop_mode_count++;
            free_pool(info);
        }
    }
}

BOOLEAN hw_set_gop_mode(UINT32 mode_num) {
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
    if (EFI_ERROR(efi_locate_protocol(&gEfiGraphicsOutputProtocolGuid, (VOID **)&gop)) || !gop) {
        return FALSE;
    }
    if (EFI_ERROR(gop->SetMode(gop, mode_num))) {
        return FALSE;
    }
    gHw.gop_mode_count = 0;
    collect_gop_info();
    return TRUE;
}

/* =========================================================================
 * Firmware HII String Package + IFR Question / Option Decoder
 * ========================================================================= */
#define HII_MAX_STR_IDS 32768

EFI_STATUS hw_export_raw_hii_packages(UINT8 **out_buf, UINTN *out_size) {
    if (!out_buf || !out_size) return EFI_INVALID_PARAMETER;
    *out_buf  = NULL;
    *out_size = 0;

    UINT8 *buf = NULL;
    UINTN buf_sz = 0;

    EFI_HII_DATABASE_PROTOCOL *hii = NULL;
    if (!EFI_ERROR(efi_locate_protocol(&gEfiHiiDatabaseProtocolGuid, (VOID **)&hii)) &&
        hii && hii->ExportPackageLists) {
        EFI_STATUS st = hii->ExportPackageLists(hii, NULL, &buf_sz, NULL);
        if (st == EFI_BUFFER_TOO_SMALL && buf_sz > 0 && buf_sz <= 0x2000000U) {
            buf = (UINT8 *)alloc_pool(buf_sz);
            if (buf) {
                st = hii->ExportPackageLists(hii, NULL, &buf_sz, buf);
                if (EFI_ERROR(st)) {
                    free_pool(buf);
                    buf = NULL;
                    buf_sz = 0;
                }
            } else {
                buf_sz = 0;
            }
        } else {
            buf_sz = 0;
        }
    }

    /* Also scan EFI_FIRMWARE_VOLUME2_PROTOCOL PE32 .rsrc / RAW sections for hidden Setup IFR! */
    UINTN fv_added = 0;
    unlock_append_fv_hii_packages(&buf, &buf_sz, &fv_added);
    if (fv_added > 0) {
        gHw.hii_fv_pkg_count = fv_added;
    }

    if (!buf || buf_sz == 0) {
        if (buf) free_pool(buf);
        return EFI_NOT_FOUND;
    }

    *out_buf  = buf;
    *out_size = buf_sz;
    return EFI_SUCCESS;
}

static UINTN skip_ascii_str(const UINT8 *buf, UINTN off, UINTN end) {
    while (off < end && buf[off] != 0) off++;
    return (off < end) ? (off + 1) : end;
}

static UINTN skip_ucs2_str(const UINT8 *buf, UINTN off, UINTN end) {
    while (off + 1 < end) {
        if (buf[off] == 0 && buf[off + 1] == 0) return off + 2;
        off += 2;
    }
    return end;
}

static VOID build_hii_string_map(const UINT8 *buf, UINTN pkg_off, UINTN pkg_end, UINT32 *str_map) {
    memset(str_map, 0, sizeof(UINT32) * HII_MAX_STR_IDS);
    if (pkg_off + 48 > pkg_end) return;

    UINT32 str_info_off = 0;
    memcpy(&str_info_off, buf + pkg_off + 8, 4);
    if (str_info_off < 44 || pkg_off + str_info_off >= pkg_end) return;

    UINTN cur = pkg_off + str_info_off;
    UINT32 sid = 1;

    while (cur < pkg_end && sid < HII_MAX_STR_IDS) {
        UINT8 btype = buf[cur];
        if (btype == 0x00U) break; /* EFI_HII_SIBT_END */

        if (btype == 0x10U) { /* SIBT_STRING_SCSU */
            cur++;
            if (sid < HII_MAX_STR_IDS) str_map[sid] = (UINT32)cur;
            sid++;
            cur = skip_ascii_str(buf, cur, pkg_end);
        } else if (btype == 0x11U) { /* SIBT_STRING_SCSU_FONT */
            if (cur + 2 > pkg_end) break;
            cur += 2;
            if (sid < HII_MAX_STR_IDS) str_map[sid] = (UINT32)cur;
            sid++;
            cur = skip_ascii_str(buf, cur, pkg_end);
        } else if (btype == 0x12U || btype == 0x13U) { /* SIBT_STRINGS_SCSU(_FONT) */
            UINTN hdr = (btype == 0x12U) ? 3 : 4;
            if (cur + hdr > pkg_end) break;
            UINT16 cnt = 0;
            memcpy(&cnt, buf + cur + hdr - 2, 2);
            cur += hdr;
            for (UINT16 k = 0; k < cnt && cur < pkg_end; k++) {
                if (sid < HII_MAX_STR_IDS) str_map[sid] = (UINT32)cur;
                sid++;
                cur = skip_ascii_str(buf, cur, pkg_end);
            }
        } else if (btype == 0x14U) { /* SIBT_STRING_UCS2 */
            cur++;
            if (sid < HII_MAX_STR_IDS) str_map[sid] = 0x80000000U | (UINT32)cur;
            sid++;
            cur = skip_ucs2_str(buf, cur, pkg_end);
        } else if (btype == 0x15U) { /* SIBT_STRING_UCS2_FONT */
            if (cur + 2 > pkg_end) break;
            cur += 2;
            if (sid < HII_MAX_STR_IDS) str_map[sid] = 0x80000000U | (UINT32)cur;
            sid++;
            cur = skip_ucs2_str(buf, cur, pkg_end);
        } else if (btype == 0x16U || btype == 0x17U) { /* SIBT_STRINGS_UCS2(_FONT) */
            UINTN hdr = (btype == 0x16U) ? 3 : 4;
            if (cur + hdr > pkg_end) break;
            UINT16 cnt = 0;
            memcpy(&cnt, buf + cur + hdr - 2, 2);
            cur += hdr;
            for (UINT16 k = 0; k < cnt && cur < pkg_end; k++) {
                if (sid < HII_MAX_STR_IDS) str_map[sid] = 0x80000000U | (UINT32)cur;
                sid++;
                cur = skip_ucs2_str(buf, cur, pkg_end);
            }
        } else if (btype == 0x20U) { /* SIBT_DUPLICATE */
            if (cur + 3 > pkg_end) break;
            UINT16 dup_id = 0;
            memcpy(&dup_id, buf + cur + 1, 2);
            if (dup_id < HII_MAX_STR_IDS && sid < HII_MAX_STR_IDS) {
                str_map[sid] = str_map[dup_id];
            }
            sid++;
            cur += 3;
        } else if (btype == 0x21U) { /* SIBT_SKIP2 */
            if (cur + 3 > pkg_end) break;
            UINT16 sk = 0;
            memcpy(&sk, buf + cur + 1, 2);
            sid += sk;
            cur += 3;
        } else if (btype == 0x22U) { /* SIBT_SKIP1 */
            if (cur + 2 > pkg_end) break;
            sid += buf[cur + 1];
            cur += 2;
        } else if (btype == 0x30U) { /* SIBT_EXT1 */
            if (cur + 2 > pkg_end || buf[cur + 1] < 2) break;
            cur += buf[cur + 1];
        } else if (btype == 0x31U) { /* SIBT_EXT2 */
            if (cur + 4 > pkg_end) break;
            UINT16 elen = 0;
            memcpy(&elen, buf + cur + 2, 2);
            if (elen < 4) break;
            cur += elen;
        } else if (btype == 0x32U) { /* SIBT_EXT4 */
            if (cur + 6 > pkg_end) break;
            UINT32 elen = 0;
            memcpy(&elen, buf + cur + 2, 4);
            if (elen < 6) break;
            cur += elen;
        } else if (btype == 0x40U) { /* SIBT_FONT */
            if (cur + 5 > pkg_end) break;
            cur = skip_ucs2_str(buf, cur + 5, pkg_end);
        } else {
            break;
        }
    }
}

static VOID lookup_hii_str(
    const UINT8 *buf,
    UINTN buf_sz,
    const UINT32 *str_map,
    UINT16 sid,
    CHAR8 *out,
    UINTN max_len
) {
    if (!out || max_len == 0) return;
    out[0] = '\0';
    if (!str_map || sid == 0 || sid >= HII_MAX_STR_IDS) return;

    UINT32 entry = str_map[sid];
    if (entry == 0) return;
    BOOLEAN is_ucs2 = ((entry & 0x80000000U) != 0);
    UINTN off = (UINTN)(entry & 0x7FFFFFFFU);
    if (off >= buf_sz) return;

    UINTN oi = 0;
    if (is_ucs2) {
        while (off + 1 < buf_sz && oi + 1 < max_len) {
            UINT16 wc = (UINT16)buf[off] | ((UINT16)buf[off + 1] << 8);
            if (wc == 0) break;
            if (wc == L'\r' || wc == L'\n') out[oi++] = ' ';
            else if (wc >= 0x20U && wc <= 0x7EU) out[oi++] = (CHAR8)wc;
            off += 2;
        }
    } else {
        while (off < buf_sz && oi + 1 < max_len) {
            UINT8 c = buf[off++];
            if (c == 0) break;
            if (c == '\r' || c == '\n') out[oi++] = ' ';
            else if (c >= 0x20U && c <= 0x7EU) out[oi++] = (CHAR8)c;
        }
    }
    out[oi] = '\0';
    trim_ascii_spaces(out);
}

static UINT64 read_le_val(const UINT8 *p, UINTN width) {
    UINT64 v = 0;
    if (width > 8) width = 8;
    for (UINTN i = 0; i < width; i++) {
        v |= ((UINT64)p[i] << (i * 8));
    }
    return v;
}

static VOID collect_hii_info(VOID) {
    UINT8 *buf = NULL;
    UINTN buf_sz = 0;
    if (EFI_ERROR(hw_export_raw_hii_packages(&buf, &buf_sz)) || !buf) {
        return;
    }

    gHw.hii_present   = TRUE;
    gHw.hii_raw_bytes = buf_sz;

    if (!gHw.hii_questions) {
        gHw.hii_questions = (HW_HII_QUESTION *)alloc_zero_pool(sizeof(HW_HII_QUESTION) * HW_MAX_HII_QUESTIONS);
        if (gHw.hii_questions) {
            gHw.hii_question_cap = HW_MAX_HII_QUESTIONS;
        } else {
            gHw.hii_questions = (HW_HII_QUESTION *)alloc_zero_pool(sizeof(HW_HII_QUESTION) * 512U);
            if (gHw.hii_questions) gHw.hii_question_cap = 512U;
        }
    }
    UINT32 *str_map = (UINT32 *)alloc_zero_pool(sizeof(UINT32) * HII_MAX_STR_IDS);

    UINTN list_off = 0;
    while (list_off + sizeof(EFI_HII_PACKAGE_LIST_HEADER) <= buf_sz) {
        const EFI_HII_PACKAGE_LIST_HEADER *plh = (const EFI_HII_PACKAGE_LIST_HEADER *)(buf + list_off);
        if (plh->PackageLength < sizeof(EFI_HII_PACKAGE_LIST_HEADER) ||
            list_off + plh->PackageLength > buf_sz) {
            break;
        }
        gHw.hii_pkg_list_count++;
        UINTN list_end = list_off + plh->PackageLength;

        /* Pass 1: Locate English (or first) String Package in this PackageList */
        UINTN best_str_off = 0, best_str_end = 0;
        UINTN pkg_off = list_off + sizeof(EFI_HII_PACKAGE_LIST_HEADER);
        while (pkg_off + 4 <= list_end) {
            UINT32 hdr_raw = 0;
            memcpy(&hdr_raw, buf + pkg_off, 4);
            UINT32 plen = hdr_raw & 0x00FFFFFFU;
            UINT8  ptyp = (UINT8)((hdr_raw >> 24) & 0xFFU);
            if (plen < 4 || pkg_off + plen > list_end || ptyp == EFI_HII_PACKAGE_END) break;

            if (ptyp == EFI_HII_PACKAGE_STRINGS && plen >= 50) {
                const CHAR8 *lang = (const CHAR8 *)(buf + pkg_off + 46);
                if (best_str_off == 0 ||
                    ((lang[0] == 'e' || lang[0] == 'E') && (lang[1] == 'n' || lang[1] == 'N'))) {
                    best_str_off = pkg_off;
                    best_str_end = pkg_off + plen;
                    if ((lang[0] == 'e' || lang[0] == 'E') && (lang[1] == 'n' || lang[1] == 'N')) {
                        break;
                    }
                }
            }
            pkg_off += plen;
        }

        if (str_map) {
            if (best_str_off != 0) build_hii_string_map(buf, best_str_off, best_str_end, str_map);
            else memset(str_map, 0, sizeof(UINT32) * HII_MAX_STR_IDS);
        }

        /* Pass 2: Parse Forms Package(s) in this PackageList */
        UINTN vs_start_idx = gHw.hii_varstore_count;
        UINTN q_start_idx  = gHw.hii_question_count;
        pkg_off = list_off + sizeof(EFI_HII_PACKAGE_LIST_HEADER);

        while (pkg_off + 4 <= list_end) {
            UINT32 hdr_raw = 0;
            memcpy(&hdr_raw, buf + pkg_off, 4);
            UINT32 plen = hdr_raw & 0x00FFFFFFU;
            UINT8  ptyp = (UINT8)((hdr_raw >> 24) & 0xFFU);
            if (plen < 4 || pkg_off + plen > list_end || ptyp == EFI_HII_PACKAGE_END) break;

            if (ptyp == EFI_HII_PACKAGE_FORMS) {
                CHAR8 cur_formset[32];
                str_cpy(cur_formset, "BIOS Setup", sizeof(cur_formset));
                INTN  scope_q[64];
                UINT8 scope_op[64];
                UINTN depth = 0;
                UINTN fs_vs_start = vs_start_idx;
                UINTN fs_q_start  = gHw.hii_question_count;

                UINTN ioff = pkg_off + 4;
                UINTN iend = pkg_off + plen;
                while (ioff + 2 <= iend) {
                    UINT8 op        = buf[ioff];
                    UINT8 len       = buf[ioff + 1] & 0x7FU;
                    BOOLEAN has_scp = ((buf[ioff + 1] & 0x80U) != 0);
                    if (len < 2 || ioff + len > iend) break;

                    INTN pushed_q = -1;

                    if (op == 0x29U) { /* EFI_IFR_END_OP */
                        if (depth > 0) depth--;
                        ioff += len;
                        continue;
                    } else if (op == 0x0EU) { /* EFI_IFR_FORM_SET_OP */
                        /* Link any previous FormSet's questions before starting a new FormSet */
                        if (gHw.hii_questions && gHw.hii_question_count > fs_q_start) {
                            for (UINTN qi = fs_q_start; qi < gHw.hii_question_count; qi++) {
                                HW_HII_QUESTION *pq = &gHw.hii_questions[qi];
                                for (UINTN vi = fs_vs_start; vi < gHw.hii_varstore_count; vi++) {
                                    if (gHw.hii_varstores[vi].varstore_id == pq->varstore_id) {
                                        pq->varstore_idx = (INT16)vi;
                                        break;
                                    }
                                }
                            }
                        }
                        fs_vs_start = gHw.hii_varstore_count;
                        fs_q_start  = gHw.hii_question_count;
                        gHw.hii_formset_count++;
                        if (len >= 20) {
                            UINT16 fs_sid = 0;
                            memcpy(&fs_sid, buf + ioff + 18, 2);
                            CHAR8 tmp_fs[32];
                            lookup_hii_str(buf, buf_sz, str_map, fs_sid, tmp_fs, sizeof(tmp_fs));
                            if (tmp_fs[0]) str_cpy(cur_formset, tmp_fs, sizeof(cur_formset));
                        }
                    } else if ((op == 0x24U && len > 22) || (op == 0x26U && len > 25)) {
                        HW_HII_VARSTORE_INFO tmp_vs;
                        memset(&tmp_vs, 0, sizeof(tmp_vs));
                        if (op == 0x24U) {
                            memcpy(&tmp_vs.guid, buf + ioff + 2, sizeof(EFI_GUID));
                            memcpy(&tmp_vs.varstore_id, buf + ioff + 18, 2);
                            memcpy(&tmp_vs.size, buf + ioff + 20, 2);
                            tmp_vs.is_efi_varstore = FALSE;
                            UINTN max_n = len - 22;
                            if (max_n >= sizeof(tmp_vs.name)) max_n = sizeof(tmp_vs.name) - 1;
                            memcpy(tmp_vs.name, buf + ioff + 22, max_n);
                        } else {
                            memcpy(&tmp_vs.varstore_id, buf + ioff + 2, 2);
                            memcpy(&tmp_vs.guid, buf + ioff + 4, sizeof(EFI_GUID));
                            tmp_vs.is_efi_varstore = TRUE;
                            UINTN name_off = 24;
                            if (len > 26 &&
                                (gHw.uefi_major > 2 || (gHw.uefi_major == 2 && gHw.uefi_minor >= 30) ||
                                 buf[ioff + 24] < 0x20U || buf[ioff + 25] < 0x20U) &&
                                buf[ioff + 26] >= 0x20U && buf[ioff + 26] <= 0x7EU) {
                                memcpy(&tmp_vs.size, buf + ioff + 24, 2);
                                name_off = 26;
                            }
                            UINTN max_n = len - name_off;
                            if (max_n >= sizeof(tmp_vs.name)) max_n = sizeof(tmp_vs.name) - 1;
                            memcpy(tmp_vs.name, buf + ioff + name_off, max_n);
                        }
                        if (gHw.hii_varstore_count < HW_MAX_HII_STORES && tmp_vs.name[0]) {
                            gHw.hii_varstores[gHw.hii_varstore_count++] = tmp_vs;
                        }
                    } else if (op == 0x5FU && len >= 18 && has_scp) {
                        /* EFI_IFR_GUID_OP: Check for EDKII_IFR_BIT_VARSTORE_GUID (AMD CBS / Intel RC bitfields!) */
                        EFI_GUID gop_guid;
                        memcpy(&gop_guid, buf + ioff + 2, sizeof(EFI_GUID));
                        if (guid_equal(&gop_guid, &gEdkiiIfrBitVarstoreGuid)) {
                            op = 0xFEU; /* Sentinel scope op marking Bitfield Question Scope */
                        }
                    } else if ((op == 0x05U || op == 0x06U || op == 0x07U) &&
                               len >= 14 && gHw.hii_questions &&
                               gHw.hii_question_count < gHw.hii_question_cap) {
                        UINT16 prompt_sid = 0, help_sid = 0, qid = 0, vsid = 0, voff = 0;
                        memcpy(&prompt_sid, buf + ioff + 2, 2);
                        memcpy(&help_sid,   buf + ioff + 4, 2);
                        memcpy(&qid,        buf + ioff + 6, 2);
                        memcpy(&vsid,       buf + ioff + 8, 2);
                        memcpy(&voff,       buf + ioff + 10, 2);
                        UINT8 qflags = buf[ioff + 12];

                        CHAR8 prompt_txt[52];
                        lookup_hii_str(buf, buf_sz, str_map, prompt_sid, prompt_txt, sizeof(prompt_txt));

                        if (vsid != 0 && prompt_txt[0] != '\0') {
                            BOOLEAN in_suppress = FALSE;
                            BOOLEAN in_grayout  = FALSE;
                            BOOLEAN in_bitfield = FALSE;
                            for (UINTN sd = 0; sd < depth; sd++) {
                                if (scope_op[sd] == 0x0AU) in_suppress = TRUE; /* SUPPRESS_IF */
                                if (scope_op[sd] == 0x19U || scope_op[sd] == 0x1EU) in_grayout = TRUE;
                                if (scope_op[sd] == 0xFEU) in_bitfield = TRUE; /* EDKII Bit-VarStore */
                            }

                            UINTN q_idx = gHw.hii_question_count++;
                            HW_HII_QUESTION *q = &gHw.hii_questions[q_idx];
                            memset(q, 0, sizeof(*q));
                            q->qtype         = op;
                            q->read_only     = ((qflags & 0x01U) != 0);
                            q->is_suppressed = in_suppress;
                            q->is_grayout    = in_grayout;
                            q->is_bitfield   = in_bitfield;
                            q->question_id   = qid;
                            q->varstore_id   = vsid;
                            q->var_offset    = voff;
                            q->varstore_idx  = -1;
                            if (in_suppress) gHw.hii_hidden_count++;
                            str_cpy(q->formset_title, cur_formset, sizeof(q->formset_title));
                            str_cpy(q->prompt, prompt_txt, sizeof(q->prompt));
                            lookup_hii_str(buf, buf_sz, str_map, help_sid, q->help, sizeof(q->help));

                            if (op == 0x06U) { /* CHECKBOX */
                                q->width     = 1;
                                q->bit_width = 1;
                                q->opt_count = 2;
                                str_cpy(q->opts[0].label, "Disabled", sizeof(q->opts[0].label));
                                q->opts[0].value = 0;
                                str_cpy(q->opts[1].label, "Enabled", sizeof(q->opts[1].label));
                                q->opts[1].value = 1;
                            } else if (in_bitfield) {
                                UINT8 bw = buf[ioff + 13] & 0x3FU;
                                if (bw == 0 || bw > 32) bw = 8;
                                q->bit_width = bw;
                                UINTN vb = (bw <= 8) ? 1U : (bw <= 16) ? 2U : 4U;
                                q->width = (UINT8)vb;
                                if (op == 0x07U && (UINTN)len >= 14U + 3U * vb) {
                                    q->min_val  = read_le_val(buf + ioff + 14, vb);
                                    q->max_val  = read_le_val(buf + ioff + 14 + vb, vb);
                                    q->step_val = read_le_val(buf + ioff + 14 + 2U * vb, vb);
                                }
                            } else {
                                UINT8 sz_c = buf[ioff + 13] & 0x03U;
                                q->width = (sz_c == 0) ? 1 : (sz_c == 1) ? 2 : (sz_c == 2) ? 4 : 8;
                                q->bit_width = (UINT8)(q->width * 8U);
                                if (op == 0x07U && (UINTN)len >= 14U + 3U * q->width) {
                                    q->min_val  = read_le_val(buf + ioff + 14, q->width);
                                    q->max_val  = read_le_val(buf + ioff + 14 + q->width, q->width);
                                    q->step_val = read_le_val(buf + ioff + 14 + 2U * q->width, q->width);
                                }
                            }
                            pushed_q = (INTN)q_idx;
                        }
                    } else if (op == 0x09U && len >= 7 && gHw.hii_questions) { /* ONE_OF_OPTION */
                        INTN owner_q = -1;
                        for (INTN d = (INTN)depth - 1; d >= 0; d--) {
                            if (scope_q[d] >= 0) { owner_q = scope_q[d]; break; }
                        }
                        if (owner_q >= 0) {
                            HW_HII_QUESTION *q = &gHw.hii_questions[owner_q];
                            if (q->opt_count < HW_MAX_HII_Q_OPTS) {
                                UINT16 opt_sid = 0;
                                memcpy(&opt_sid, buf + ioff + 2, 2);
                                UINT8 otype = buf[ioff + 5] & 0x0FU;
                                UINTN ow = (otype == 0) ? 1 : (otype == 1) ? 2 : (otype == 2) ? 4 :
                                           (otype == 3) ? 8 : 1;
                                if (6U + ow <= len) {
                                    HW_HII_OPTION *op_item = &q->opts[q->opt_count];
                                    lookup_hii_str(buf, buf_sz, str_map, opt_sid,
                                                   op_item->label, sizeof(op_item->label));
                                    op_item->value = read_le_val(buf + ioff + 6, ow);
                                    if (!op_item->label[0]) {
                                        snprintf_ascii(op_item->label, sizeof(op_item->label),
                                                       "0x%lX", op_item->value);
                                    }
                                    q->opt_count++;
                                }
                            }
                        }
                    }

                    if (has_scp && depth < 64) {
                        scope_q[depth]  = pushed_q;
                        scope_op[depth] = op;
                        depth++;
                    }
                    ioff += len;
                }

                /* Link last FormSet in this Forms Package */
                if (gHw.hii_questions && gHw.hii_question_count > fs_q_start) {
                    for (UINTN qi = fs_q_start; qi < gHw.hii_question_count; qi++) {
                        HW_HII_QUESTION *pq = &gHw.hii_questions[qi];
                        if (pq->varstore_idx >= 0) continue;
                        for (UINTN vi = fs_vs_start; vi < gHw.hii_varstore_count; vi++) {
                            if (gHw.hii_varstores[vi].varstore_id == pq->varstore_id) {
                                pq->varstore_idx = (INT16)vi;
                                break;
                            }
                        }
                    }
                }
            }
            pkg_off += plen;
        }

        /* Fallback link for any remaining questions in this PackageList */
        if (gHw.hii_questions) {
            for (UINTN qi = q_start_idx; qi < gHw.hii_question_count; qi++) {
                HW_HII_QUESTION *q = &gHw.hii_questions[qi];
                if (q->varstore_idx >= 0) continue;
                for (UINTN vi = vs_start_idx; vi < gHw.hii_varstore_count; vi++) {
                    if (gHw.hii_varstores[vi].varstore_id == q->varstore_id) {
                        q->varstore_idx = (INT16)vi;
                        break;
                    }
                }
            }
        }

        list_off += plh->PackageLength;
    }

    free_pool(str_map);
    free_pool(buf);
}

BOOLEAN hw_locate_varstore_nvram(
    const HW_HII_VARSTORE_INFO *vs,
    UINTN min_req_size,
    CHAR16 *out_wname,
    UINTN max_wchars,
    EFI_GUID *out_guid,
    UINTN *out_size
) {
    if (!vs || !vs->name[0] || !out_wname || !out_guid) return FALSE;
    if (min_req_size == 0) min_req_size = 1;

    ascii_to_wstr(out_wname, vs->name, max_wchars);
    *out_guid = vs->guid;

    /* 1. Try exact (Name, IFR GUID) first — only accept if large enough (avoids dummy 4-byte Setup!) */
    UINTN sz = 0;
    if (!EFI_ERROR(nvram_read_var(out_wname, out_guid, NULL, &sz, NULL)) && sz >= min_req_size) {
        if (out_size) *out_size = sz;
        return TRUE;
    }

    /*
     * 2. setup_var_3 Fallback: Dell, Lenovo & AMI firmwares frequently expose a tiny dummy
     *    "Setup" variable (4..16 bytes) alongside the real "Setup" VarStore (1500..6000 bytes)
     *    under a different GUID. Select the LARGEST matching variable >= min_req_size!
     */
    INTN  best_idx = -1;
    UINTN best_sz  = 0;
    for (UINTN i = 0; i < gVarCount; i++) {
        if (str_icmp(gVarList[i].name, vs->name) == 0 &&
            gVarList[i].data_size >= min_req_size &&
            gVarList[i].data_size >= best_sz) {
            best_sz  = gVarList[i].data_size;
            best_idx = (INTN)i;
        }
    }
    if (best_idx >= 0) {
        wstr_cpy(out_wname, gVarList[best_idx].name_w, max_wchars);
        *out_guid = gVarList[best_idx].guid;
        if (out_size) *out_size = best_sz;
        return TRUE;
    }
    return FALSE;
}

static VOID compute_question_byte_span(const HW_HII_QUESTION *q, UINTN *out_byte_off, UINTN *out_span_bytes) {
    if (q->is_bitfield) {
        UINTN boff  = (UINTN)q->var_offset / 8U;
        UINTN shift = (UINTN)q->var_offset % 8U;
        UINTN bw    = (q->bit_width > 0 && q->bit_width <= 32) ? q->bit_width : 8U;
        UINTN span  = (shift + bw + 7U) / 8U;
        if (span < 1U) span = 1U;
        if (span > 8U) span = 8U;
        *out_byte_off   = boff;
        *out_span_bytes = span;
    } else {
        *out_byte_off   = (UINTN)q->var_offset;
        *out_span_bytes = (q->width >= 1 && q->width <= 8) ? q->width : 1U;
    }
}

static UINT64 extract_question_from_buf(const HW_HII_QUESTION *q, const UINT8 *data) {
    UINTN boff = 0, span = 1;
    compute_question_byte_span(q, &boff, &span);
    UINT64 raw = read_le_val(data + boff, span);
    if (q->is_bitfield) {
        UINTN shift = (UINTN)q->var_offset % 8U;
        UINTN bw    = (q->bit_width > 0 && q->bit_width <= 32) ? q->bit_width : 8U;
        UINT64 mask = (bw >= 64U) ? ~0ULL : ((1ULL << bw) - 1ULL);
        return (raw >> shift) & mask;
    }
    return raw;
}

static VOID insert_question_into_buf(const HW_HII_QUESTION *q, UINT8 *data, UINT64 new_val) {
    UINTN boff = 0, span = 1;
    compute_question_byte_span(q, &boff, &span);
    if (q->is_bitfield) {
        UINTN shift = (UINTN)q->var_offset % 8U;
        UINTN bw    = (q->bit_width > 0 && q->bit_width <= 32) ? q->bit_width : 8U;
        UINT64 mask = (bw >= 64U) ? ~0ULL : ((1ULL << bw) - 1ULL);
        UINT64 raw  = read_le_val(data + boff, span);
        raw = (raw & ~(mask << shift)) | ((new_val & mask) << shift);
        for (UINTN b = 0; b < span; b++) {
            data[boff + b] = (UINT8)((raw >> (b * 8U)) & 0xFFULL);
        }
    } else {
        for (UINTN b = 0; b < span; b++) {
            data[boff + b] = (UINT8)((new_val >> (b * 8U)) & 0xFFULL);
        }
    }
}

static VOID append_hex_byte_w(CHAR16 *dst, UINTN *io_pos, UINTN max_w, UINT8 byte_val) {
    static const CHAR16 kHexL[16] = {
        L'0',L'1',L'2',L'3',L'4',L'5',L'6',L'7',L'8',L'9',L'a',L'b',L'c',L'd',L'e',L'f'
    };
    if (*io_pos + 2 >= max_w) return;
    dst[(*io_pos)++] = kHexL[(byte_val >> 4) & 0x0FU];
    dst[(*io_pos)++] = kHexL[byte_val & 0x0FU];
    dst[*io_pos]     = 0;
}

/*
 * Sync updated VarStore slice via UEFI HII Config Routing Protocol (RouteConfig).
 * Crucial on Lenovo ThinkPads (recalculates Setup checksum), AMD Ryzen boards
 * (flushes CBS/PBS changes to AGESA APCB), and BufferVarStore-backed BIOS drivers!
 */
static BOOLEAN try_hii_config_routing_sync(
    const EFI_GUID *vs_guid,
    const CHAR8 *vs_name,
    const UINT8 *full_block,
    UINTN full_block_sz,
    UINTN byte_off,
    UINTN byte_width
) {
    if (!gBS || !vs_guid || !vs_name || !vs_name[0] || !full_block || byte_off + byte_width > full_block_sz)
        return FALSE;

    EFI_HII_CONFIG_ROUTING_PROTOCOL *cr = NULL;
    if (EFI_ERROR(efi_locate_protocol(&gEfiHiiConfigRoutingProtocolGuid, (VOID **)&cr)) ||
        !cr || !cr->ExtractConfig || !cr->BlockToConfig || !cr->RouteConfig) {
        return FALSE;
    }

    UINTN h_cnt = 0;
    EFI_HANDLE *handles = NULL;
    if (EFI_ERROR(efi_locate_handles(&gEfiHiiConfigAccessProtocolGuid, &h_cnt, &handles)) || !handles) {
        return FALSE;
    }

    CHAR16 *req_buf = (CHAR16 *)alloc_pool(1024 * sizeof(CHAR16));
    if (!req_buf) {
        free_pool(handles);
        return FALSE;
    }

    BOOLEAN routed_any = FALSE;
    const UINT8 *gbytes = (const UINT8 *)vs_guid;

    for (UINTN i = 0; i < h_cnt; i++) {
        EFI_DEVICE_PATH_PROTOCOL *dp = NULL;
        if (EFI_ERROR(gBS->HandleProtocol(handles[i], &gEfiDevicePathProtocolGuid, (VOID **)&dp)) || !dp) {
            continue;
        }

        /* Measure DevicePath total byte length including 4-byte EndNode (0x7F, 0xFF) */
        UINTN dp_bytes = 0;
        const EFI_DEVICE_PATH_PROTOCOL *n = dp;
        for (UINTN guard = 0; guard < 48; guard++) {
            UINT16 nl = (UINT16)n->Length[0] | ((UINT16)n->Length[1] << 8);
            if (nl < 4 || dp_bytes + nl > 320) { dp_bytes = 0; break; }
            dp_bytes += nl;
            if (n->Type == 0x7FU) break;
            n = (const EFI_DEVICE_PATH_PROTOCOL *)((const UINT8 *)n + nl);
        }
        if (dp_bytes < 4) continue;

        /* Build UEFI <ConfigRequest>: GUID=<32hex>&NAME=<4hex*chars>&PATH=<dphex>&OFFSET=%x&WIDTH=%x */
        UINTN p = 0;
        req_buf[0] = 0;
        wstr_cat(req_buf, L"GUID=", 1024);
        p = wstr_len(req_buf);
        for (UINTN b = 0; b < 16; b++) append_hex_byte_w(req_buf, &p, 1024, gbytes[b]);

        wstr_cat(req_buf, L"&NAME=", 1024);
        p = wstr_len(req_buf);
        for (UINTN c = 0; vs_name[c] != '\0'; c++) {
            append_hex_byte_w(req_buf, &p, 1024, 0x00U);
            append_hex_byte_w(req_buf, &p, 1024, (UINT8)vs_name[c]);
        }

        wstr_cat(req_buf, L"&PATH=", 1024);
        p = wstr_len(req_buf);
        const UINT8 *dp_raw = (const UINT8 *)dp;
        for (UINTN b = 0; b < dp_bytes; b++) append_hex_byte_w(req_buf, &p, 1024, dp_raw[b]);

        CHAR16 tail[64];
        wsnprintf(tail, 64, "&OFFSET=%04x&WIDTH=%04x", (UINT32)byte_off, (UINT32)byte_width);
        wstr_cat(req_buf, tail, 1024);

        CHAR16 *prog = NULL;
        CHAR16 *ext_res = NULL;
        if (!EFI_ERROR(cr->ExtractConfig(cr, req_buf, &prog, &ext_res)) && ext_res) {
            free_pool(ext_res);
            CHAR16 *cfg_resp = NULL;
            CHAR16 *bprog = NULL;
            if (!EFI_ERROR(cr->BlockToConfig(cr, req_buf, full_block, full_block_sz, &cfg_resp, &bprog)) && cfg_resp) {
                CHAR16 *rprog = NULL;
                if (!EFI_ERROR(cr->RouteConfig(cr, cfg_resp, &rprog))) {
                    routed_any = TRUE;
                }
                free_pool(cfg_resp);
            }
        }
    }

    free_pool(req_buf);
    free_pool(handles);
    return routed_any;
}

BOOLEAN hw_hii_read_question_val(UINTN q_idx, UINT64 *out_val, BOOLEAN *out_in_nvram) {
    if (out_val) *out_val = 0;
    if (out_in_nvram) *out_in_nvram = FALSE;
    if (!gHw.hii_questions || q_idx >= gHw.hii_question_count) return FALSE;

    const HW_HII_QUESTION *q = &gHw.hii_questions[q_idx];
    if (q->varstore_idx < 0 || (UINTN)q->varstore_idx >= gHw.hii_varstore_count) return FALSE;

    UINTN boff = 0, span = 1;
    compute_question_byte_span(q, &boff, &span);
    UINTN req_sz = boff + span;

    CHAR16 wname[64];
    EFI_GUID vguid;
    if (!hw_locate_varstore_nvram(&gHw.hii_varstores[q->varstore_idx], req_sz, wname, 64, &vguid, NULL)) {
        return FALSE;
    }

    UINTN sz = 0;
    UINT8 *data = NULL;
    if (EFI_ERROR(nvram_read_var(wname, &vguid, NULL, &sz, &data)) || !data) {
        return FALSE;
    }
    if (req_sz > sz) {
        free_pool(data);
        return FALSE;
    }
    UINT64 v = extract_question_from_buf(q, data);
    free_pool(data);
    if (out_val) *out_val = v;
    if (out_in_nvram) *out_in_nvram = TRUE;
    return TRUE;
}

BOOLEAN hw_hii_write_question_val(UINTN q_idx, UINT64 new_val, CHAR8 *err_out, UINTN max_err) {
    if (!gHw.hii_questions || q_idx >= gHw.hii_question_count) return FALSE;
    const HW_HII_QUESTION *q = &gHw.hii_questions[q_idx];
    if (q->varstore_idx < 0 || (UINTN)q->varstore_idx >= gHw.hii_varstore_count) {
        if (err_out) str_cpy(err_out, "Question has no linked NVRAM VarStore.", max_err);
        return FALSE;
    }

    const HW_HII_VARSTORE_INFO *vs = &gHw.hii_varstores[q->varstore_idx];
    UINTN boff = 0, span = 1;
    compute_question_byte_span(q, &boff, &span);
    UINTN req_sz = boff + span;

    CHAR16 wname[64];
    EFI_GUID vguid;
    if (!hw_locate_varstore_nvram(vs, req_sz, wname, 64, &vguid, NULL)) {
        if (err_out) str_cpy(err_out, "Backing VarStore (or offset range) is not exposed in NVRAM.", max_err);
        return FALSE;
    }

    UINT32 attrs = 0;
    UINTN sz = 0;
    UINT8 *data = NULL;
    EFI_STATUS st = nvram_read_var(wname, &vguid, &attrs, &sz, &data);
    if (EFI_ERROR(st) || !data) {
        if (err_out) str_cpy(err_out, "Failed to read backing NVRAM VarStore.", max_err);
        return FALSE;
    }
    if (req_sz > sz) {
        free_pool(data);
        if (err_out) str_cpy(err_out, "VarOffset exceeds NVRAM variable size.", max_err);
        return FALSE;
    }

    insert_question_into_buf(q, data, new_val);

    if (attrs == 0) {
        attrs = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
    }

    /* 1. Notify BIOS HII ConfigAccess driver via RouteConfig (ThinkPad CRC / AMD APCB / BufferVarStore) */
    try_hii_config_routing_sync(&vguid, vs->name, data, sz, boff, span);
    if (!guid_equal(&vguid, &vs->guid)) {
        try_hii_config_routing_sync(&vs->guid, vs->name, data, sz, boff, span);
    }

    /* 2. Commit primary NVRAM variable */
    st = nvram_write_var(wname, &vguid, attrs, sz, data);
    free_pool(data);
    if (EFI_ERROR(st)) {
        if (st == EFI_WRITE_PROTECTED || st == EFI_SECURITY_VIOLATION) {
            if (err_out) snprintf_ascii(err_out, max_err,
                "SetVariable rejected (%s) - BIOS Lock / NVRAM Write-Protection active!", efi_status_str(st));
        } else {
            if (err_out) snprintf_ascii(err_out, max_err, "SetVariable rejected write: %s", efi_status_str(st));
        }
        return FALSE;
    }

    /*
     * 3. setup_var2 & Multi-GUID Shadow Variable Sync:
     *    InsydeH2O firmwares mirror "Setup" <-> "Custom", and AMI/Gigabyte/ASUS firmwares often
     *    keep secondary GUID instances of "Setup" / "AmdSetup" / "CbsSetup" >= 0x10 bytes.
     *    Sync matching shadow stores so firmware does not overwrite our edit on reboot!
     */
    BOOLEAN is_setup_store = (str_icmp(vs->name, "Setup") == 0);
    for (UINTN i = 0; i < gVarCount; i++) {
        if (gVarList[i].data_size < 0x10U || gVarList[i].data_size < req_sz) continue;
        BOOLEAN same_name   = (str_icmp(gVarList[i].name, vs->name) == 0);
        BOOLEAN insyde_cust = (is_setup_store && str_icmp(gVarList[i].name, "Custom") == 0 &&
                               gVarList[i].data_size == sz);
        if (!same_name && !insyde_cust) continue;
        if (same_name && guid_equal(&gVarList[i].guid, &vguid)) continue;

        UINT32 s_attr = 0;
        UINTN  s_sz   = 0;
        UINT8 *s_data = NULL;
        if (!EFI_ERROR(nvram_read_var(gVarList[i].name_w, &gVarList[i].guid, &s_attr, &s_sz, &s_data)) &&
            s_data && s_sz >= req_sz) {
            insert_question_into_buf(q, s_data, new_val);
            if (s_attr == 0) s_attr = attrs;
            nvram_write_var(gVarList[i].name_w, &gVarList[i].guid, s_attr, s_sz, s_data);
            free_pool(s_data);
        }
    }

    /* 4. Immediate Post-Write GetVariable Read-Back Verification (catches silent SMM write drops!) */
    UINTN  rb_sz   = 0;
    UINT8 *rb_data = NULL;
    if (!EFI_ERROR(nvram_read_var(wname, &vguid, NULL, &rb_sz, &rb_data)) && rb_data && rb_sz >= req_sz) {
        UINT64 rb_val = extract_question_from_buf(q, rb_data);
        UINT64 mask   = (q->is_bitfield && q->bit_width < 64U) ? ((1ULL << q->bit_width) - 1ULL) :
                        (q->width < 8U) ? ((1ULL << (q->width * 8U)) - 1ULL) : ~0ULL;
        free_pool(rb_data);
        if ((rb_val & mask) != (new_val & mask)) {
            nvram_enumerate_all();
            if (err_out) {
                snprintf_ascii(err_out, max_err,
                    "SMM firmware silently ignored write to \"%s\" (read-back still 0x%lX)! Unlock BIOS Lock / SPI first.",
                    vs->name, rb_val);
            }
            return FALSE;
        }
    } else if (rb_data) {
        free_pool(rb_data);
    }

    nvram_enumerate_all();
    return TRUE;
}

INTN hw_hii_find_question_icase(const CHAR8 *kw1, const CHAR8 *kw2) {
    if (!gHw.hii_questions || gHw.hii_question_count == 0 || !kw1 || !kw1[0]) return -1;
    /* Pass 1: Exact case-insensitive prompt match on kw1 */
    for (UINTN i = 0; i < gHw.hii_question_count; i++) {
        if (str_icmp(gHw.hii_questions[i].prompt, kw1) == 0) return (INTN)i;
    }
    /* Pass 2: Substring match on kw1 (and kw2 if provided) */
    for (UINTN i = 0; i < gHw.hii_question_count; i++) {
        if (str_contains_icase(gHw.hii_questions[i].prompt, kw1) &&
            (!kw2 || !kw2[0] || str_contains_icase(gHw.hii_questions[i].prompt, kw2))) {
            return (INTN)i;
        }
    }
    return -1;
}

VOID hw_refresh_smbios_and_acpi_only(VOID) {
    gHw.smbios_present    = FALSE;
    gHw.dimm_count        = 0;
    gHw.dimm_populated_count = 0;
    gHw.smbios_ram_mb     = 0;
    gHw.cpu_smbios_cores  = 0;
    gHw.cpu_smbios_threads = 0;
    memset(gHw.dimms, 0, sizeof(gHw.dimms));

    gHw.acpi_count = 0;
    memset(gHw.acpi_tables, 0, sizeof(gHw.acpi_tables));

    collect_smbios_info();
    collect_acpi_info();
    finalize_cpu_topology();
}

VOID hw_collect_all(VOID) {
    HW_HII_QUESTION *prev_q = gHw.hii_questions;
    UINTN prev_cap          = gHw.hii_question_cap;
    memset(&gHw, 0, sizeof(gHw));
    gHw.hii_questions    = prev_q;
    gHw.hii_question_cap = prev_cap;
    if (gHw.hii_questions && gHw.hii_question_cap > 0) {
        memset(gHw.hii_questions, 0, sizeof(HW_HII_QUESTION) * gHw.hii_question_cap);
    }

    if (gST) {
        if (gST->FirmwareVendor) {
            wstr_to_ascii(gHw.fw_vendor, gST->FirmwareVendor, sizeof(gHw.fw_vendor));
        } else {
            str_cpy(gHw.fw_vendor, "Unknown EFI Vendor", sizeof(gHw.fw_vendor));
        }
        gHw.fw_revision = gST->FirmwareRevision;
        gHw.uefi_major  = (UINT16)((gST->Hdr.Revision >> 16) & 0xFFFFU);
        gHw.uefi_minor  = (UINT16)(gST->Hdr.Revision & 0xFFFFU);
    }

    if (gBS && gImageHandle) {
        EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
        if (!EFI_ERROR(gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&li)) && li) {
            gHw.image_base = (UINT64)(UINTN)li->ImageBase;
            gHw.image_size = li->ImageSize;
        }
    }

    /*
     * Order matters:
     * 1) CPUID + MP Services + MSRs
     * 2) SMBIOS (Type 4 core/thread counts)
     * 3) ACPI (MADT Local APIC thread count + MCFG ECAM base)
     * 4) Finalize CPU core/thread topology accurately!
     * 5) Memory, PCI/PCIe/GPU/GGC, Disks, GOP, HII/IFR
     */
    collect_cpu_cpuid_and_mp();
    collect_smbios_info();
    collect_acpi_info();
    finalize_cpu_topology();

    hw_refresh_memory_summary();
    collect_pci_info();
    collect_disk_info();
    collect_gop_info();
    collect_hii_info();
}
