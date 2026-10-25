# Oh my EFI!

**Oh my EFI!** is a full classic BIOS Setup Utility and hardware unlocker packed into a single freestanding `.efi` file (`SetupX64.efi` / `SetupIA32.efi`).

Most laptop and prebuilt motherboard vendors (Dell, Lenovo, HP, OEM boards) hide half of your BIOS menus behind `SUPPRESS_IF` rules, lock out CPU undervolting after Plundervolt (`Overclocking Lock` / `CFG Lock`), hide Intel ME / AMD PSP toggles, or lock down UMA/DVMT VRAM size, Above 4G Decoding, and Resizable BAR. Instead of extracting BIOS `.exe` updates on another PC, running `UEFITool` + `ifrextractor`, and typing blind `setup_var_3` commands in a GRUB shell, you can drop **Oh my EFI!** onto a FAT32 USB stick, boot it, and inspect or unlock everything from a keyboard-only classic blue/gray BIOS Setup screen.

It runs on Intel and AMD UEFI PCs, laptops (Dell XPS/Inspiron/Latitude/Precision, ThinkPads, gaming laptops, desktop boards), virtual machines (QEMU/OVMF, VMware, Proxmox), and Intel Macs.

> [!CAUTION]
> **Warning — Read Before Changing Anything!**
>
> This tool talks directly to real hardware registers (Ring-0 CPU MSRs, Intel FIVR `MSR 0x150`, Intel ME HECI1 MMIO, SPI `BIOS_CNTL`, PCI/PCIe config space, physical RAM) and writes directly into your motherboard's raw NVRAM `VarStore`s (`Setup`, `CpuSetup`, `SaSetup`, `PchSetup`, `MeSetup`, AMD CBS/PBS, etc.) without vendor safety rails.
>
> **Randomly flipping settings or typing wrong VarStore offsets CAN brick your machine** (black screen on boot, boot loops, unstable CPU/RAM clocks or undervolts, or corrupt NVRAM/SPI state requiring a CMOS battery pull — or an external CH341A SPI flash programmer on laptops where NVRAM lives on the BIOS chip).
> - Always press **`F12` (EFI Dump)** first so you have a full backup of your original NVRAM `.bin` variables, HII/IFR tables, ACPI, and SMBIOS on your USB drive.
> - Never blindly apply hex offsets meant for a different laptop model or BIOS version — let Oh my EFI!'s live IFR cross-check verify what an offset actually controls on *your* firmware.
> - Only change one thing at a time, and know how to clear CMOS / reset NVRAM on your specific device before experimenting. Use at your own risk!

---

## What It Can Do

- **Unlock Hub: Undervolting, Dortania `MSR 0xE2` (`CFG Lock`), `grub-mod-setup_var`, Intel ME / AMD PSP & SMN**
  - **Dortania `MSR 0xE2` (`CFG Lock`) All-Core Verifier & Unlocker (`VerifyMsrE2` / `ControlMsrE2`)**: Modeled after [Dortania's `MSR 0xE2` guide](https://dortania.github.io/OpenCore-Post-Install/misc/msr-lock.html), audits `MSR 0xE2` (`PMG_CST_CONFIG_CONTROL` bit 15) across the BSP and every AP thread via `EFI_MP_SERVICES_PROTOCOL`, flags inconsistent per-core BIOS lock bugs, prints the exact `setup_var_cv <Store> 0x<Offset> 0x01 0x00` command found in your firmware's IFR, and unlocks both NVRAM and live `MSR 0xE2` in one click.
  - **Full [`datasone/grub-mod-setup_var`](https://github.com/datasone/grub-mod-setup_var) Engine (`setup_var`, `setup_var2`, `setup_var_3`, `setup_var_vs`, `setup_var_cv`)**: Type exact CLI commands (`setup_var_cv CpuSetup 0x3E 0x01 0x00`, `setup_var_3 0xDE 0x00`, `setup_var2 ...`) or use the guided interactive VarStore browser with 1/2/4/8-byte widths, automatic `<0x10B` decoy skipping on Dell/Lenovo laptops ([`Dell-unlock-undervolting`](https://github.com/tadghh/Dell-unlock-undervolting) workflow), InsydeH2O `Custom` store sync, and live IFR cross-check before writing.
  - **Persistent NVRAM Write Sync & `Startup Auto-Patch` (`OhMyEfiAutoPatch`)**: Properly decodes and writes **EDK2 Bit-VarStores** (`EDKII_IFR_BIT_VARSTORE_GUID` bit-packed AMD CBS/PBS & Intel RC options), routes updates through **`EFI_HII_CONFIG_ROUTING_PROTOCOL->RouteConfig`** (so ThinkPad `Setup` checksum drivers and AMD AGESA APCB flash sync accept your edits instead of reverting on reset), syncs multi-GUID shadow copies, verifies every write via immediate `GetVariable` read-back, and lets you save live CPU/MSR/FIVR/AMD P0 tweaks into **`OhMyEfiAutoPatch`** to re-apply automatically every boot.
  - **Live Intel FIVR Undervolting (`MSR 0x150` `OC_MAILBOX`)**: Read and apply signed millivolt offsets (`-250 mV` to `+150 mV`) across **CPU Core**, **CPU Cache / Ring**, **Intel iGPU**, **System Agent**, and **Analog I/O** right in UEFI — then chainload Windows 11 / Linux directly without resetting so your undervolt stays active even under Windows VBS / Hyper-V.
  - **Intel ME / CSME & Intel Boot Guard Control**: Probes `PCI 00:16.0` (even when hidden from UEFI PCI enumeration), decodes `HFSTS1`–`HFSTS6` (Working State, Manufacturing Mode, HAP / Soft Temp Disable, Boot Guard Verified/Measured/FPF Fuse status), queries firmware version over HECI1 MMIO, can send pre-EOP **`MKHI_HMRFPO_ENABLE`** flash protection overrides, and surfaces `ME State` / `HAP` / `AltMeDisable` / `ME FW Image Re-Flash` / `End of Post` / `AMT` NVRAM switches.
  - **AMD Ryzen SMN (`00:00.0` `0xB8`/`0xBC`), MP1 SMU, Zen `Tctl` & PSP / IOMMU**: Reads AMD's System Management Network (`SMN`) on Ryzen / Threadripper / EPYC boards (live Zen `THM_TCON_CUR_TMP` CPU die temperature, MP1 SMU firmware version, interactive 16-byte SMN register inspector), detects AMD `IOMMU` (`00:00.2`) and `PSP` / `CCP`, and surfaces `fTPM`, `PSP`, `TSME`, `IOMMU`, and `Curve Optimizer` HII controls.
  - **SPI Controller & BIOS Flash Write-Protection (`BIOS_CNTL` / `HSFSTS` / `FRAP` / `FPRR`)**: Inspects Intel PCH SPI (`00:1F.5`), ICH9/LPC (`00:1F.0` + `RCBA`), and AMD FCH SPI (`00:14.3`) registers (`BIOSWE`, `BLE`, `EISS`/`SMM_BWP`, `FLOCKDN`, `FDOPSS` override strap, `FRAP` region permissions, `FPR0`–`FPR4` protected ranges), toggles live `BIOSWE` when unlocked, and finds `BIOS Lock` / `FPRR` / `BIOS Guard` in NVRAM.
- **Temporary Device & Vendor Spoofer (`Security` Tab)**
  - Rebuilds and relocates full **SMBIOS 2.1 (`_SM_`) & 3.0 (`_SM3_`)** tables into `<4GB` `EfiACPIMemoryNVS` via `InstallConfigurationTable` — removing in-place string-length limits and fixing shared `"Default string"` slot collisions on boards like Gigabyte X570/B550.
  - Spoof **System Vendor/Manufacturer**, **Product Name/Model**, **System Version/SKU/Family**, **System Serial**, **16-Byte Hardware UUID**, **BIOS Vendor/Version/Date**, **Baseboard Vendor/Model/Serial**, **Chassis Vendor/Type/Serial/Asset Tag**, **CPU Brand/Vendor** (SMBIOS Type 4), **RAM DIMM Vendor/Part/Serials** (Type 17), **ACPI RSDP/XSDT/FADT OEM IDs**, and **PCI Subsystem Vendor/Device IDs** (`0x2C`/`0x4C`), with one-click OEM Vendor Presets, Randomize All, and Factory Restore.
  > [!IMPORTANT]
  > **Device & Vendor Spoofs Are Temporary (RAM / Config-Table Only):** Any hardware reset (`Save & Reset`, `Warm Reset`, `Ctrl+Alt+Del`) wipes all spoofs back to factory firmware values. After spoofing, **you MUST boot your OS directly from the Security page (`>> Boot OS From This Page <<`)** — otherwise the spoof will not apply!
- **Reveal & Edit Hidden BIOS Settings (`HII / IFR Browser` + `FV2` Flash Scanner)**
  Reads both `EFI_HII_DATABASE_PROTOCOL` AND scans `EFI_FIRMWARE_VOLUME2_PROTOCOL` PE32 `.rsrc` / RAW sections directly from BIOS flash — so hidden `Setup` FormSets that laptops normally keep unloaded during fast boot are extracted and decoded automatically (`[H]`).
- **CPU Clocks, Power Limits & Lock Bits**
  - **Intel**: Target multiplier (`0x199`), all-core Turbo ratio (`0x1AD`), `CFG Lock` (`0xE2`) & `OC Lock` / Flex Ratio (`0x194`), RAPL `PL1`/`PL2` wattage (`0x610`), SpeedStep, Turbo Boost, `BD PROCHOT` throttle bypass, `C1E`, and `VT-x`.
  - **AMD**: Live all-core Hardware `P0` frequency in MHz (`0xC0010064`), SVI2 core voltage (`VID` in mV), active P-state, Core Performance Boost (`CPB`), and `SVM` (`AMD-V`), plus AMD PBO / CBS HII menus.
  - **Live Thread Control**: Enable or disable logical CPU threads on the fly through `EFI_MP_SERVICES_PROTOCOL`.
- **GPU, VRAM, Resizable BAR & PCIe Gen1–Gen5**
  - Live PCIe **Resizable BAR (`ReBAR` / SAM)** aperture switching via ECAM (`0x0015`) and Above 4G Decoding.
  - Intel GMCH stolen VRAM (`GGC`) & motherboard HII UMA/DVMT frame buffer settings, plus UEFI GOP resolution switching.
  - Per-device PCIe **ASPM (`L0s`/`L1`)**, **Target Link Speed (`Gen1`–`Gen5`)**, Relaxed Ordering, Max Read Request Size, Bus Master DMA, and raw 256-byte PCI config hex editing.
  - On Intel Macs, Apple-specific NVRAM controls (`boot-args`, SIP, chime volume, dual-GPU `gpu-power-prefs` mux) appear automatically — and stay completely hidden on non-Apple PCs.
- **Boot Entry Manager & Zero-Reset OS Chainloader**
  Add new `Boot####` entries by browsing `.efi` files on disk, delete dead boot entries, reorder `BootOrder`, set `BootNext`, or directly chainload any `Boot####` entry or `.efi` bootloader (`bootmgfw.efi`, `grubx64.efi`, `systemd-boot`, OpenCore, etc.) via `LoadImage` + `StartImage` with **zero hardware reset** so temporary spoofs and live MSR/FIVR tweaks stay active into the OS.
- **Live Memory Scanner, Debug Inspector & One-Key `EFI Dump` (`F12`)**
  Page-table–safe (`CR3`) physical RAM scanner, live ACPI `.aml` & SMBIOS string patcher in RAM, raw NVRAM hex editor, and `F12` **EFI Dump** (`OhMyEFI_Report.txt` + `OhMyEFI_Dump/` with `HII_IFR_Packages.bin`, `HII_Decoded_Options.txt` including `[EDK2 Bit-VarStore]` & `setup_var_cv` offsets, `SMBIOS_Table.bin`, ACPI `.aml` tables, and NVRAM `.bin` backups).

---

## How to Run

### Quick USB Boot (Any PC / Laptop / Mac)
1. Format a USB drive as **FAT32**.
2. Copy `SetupX64.efi` to `/EFI/BOOT/BOOTX64.EFI` (or `SetupIA32.efi` to `/EFI/BOOT/BOOTIA32.EFI` on 32-bit EFI hardware), or extract `EFI-Setup-ESP.zip` onto the root of the USB drive.
3. Boot from the USB drive via your boot menu (make sure **Secure Boot** is disabled, or sign the `.efi` binary with your own MOK/db key).

### Keys (Keyboard Only — No Mouse)
| Key | Action |
| :--- | :--- |
| `Left` / `Right` (or `[` / `]`) | Switch top tabs (`Main`, `Advanced`, `MemScan`, `Security`, `Boot`, `Debug`, `Exit`) |
| `Up` / `Down`, `PgUp` / `PgDn` | Move selection / scroll |
| `Enter` or `+` / `-` | View available options and change value |
| `Insert` / `Delete` (in `Boot`) | Add or remove a UEFI `Boot####` entry |
| `/` (in `HII` / `Debug`) | Filter / search settings or variables |
| `F1` | Help |
| `F9` | Load defaults |
| `F10` | Save staged NVRAM/RTC changes and exit |
| `F12` | Run **EFI Dump** to the boot directory |
| `ESC` | Go back / exit without saving |

---

## Building from Source

Requires `clang`, `lld` (`lld-link`), and `python3` (zero external libraries or EDK2 tree needed):

```bash
make
```

Outputs:
- `SetupX64.efi` — 64-bit UEFI binary
- `SetupIA32.efi` — 32-bit EFI binary
- `build/EFI-Setup-USB.img` — 40 MiB bootable GPT + FAT32 disk image for QEMU or `dd`

---

## Downloads

Prebuilt binaries and USB images: **`https://dl.blueskychan.dev/efi-setup/`**

---

Copyright (C) 2026 **blueskychan-dev**
