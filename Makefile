CC       := clang
LD       := lld-link
PYTHON   := python3

SRCS     := src/main.c src/util.c src/ui.c src/hwinfo.c src/nvram.c src/memscan.c src/debug.c src/dump.c src/unlock.c src/spoof.c
HDRS     := src/efi.h src/util.h src/ui.h src/hwinfo.h src/nvram.h src/memscan.h src/debug.h src/dump.h src/unlock.h src/spoof.h

COMMON_CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror \
                 -ffreestanding -fno-stack-protector -fno-strict-aliasing \
                 -fshort-wchar -Xclang -mno-stack-arg-probe -Isrc

X64_CFLAGS    := -target x86_64-unknown-windows -mno-red-zone $(COMMON_CFLAGS)
IA32_CFLAGS   := -target i686-unknown-windows -mno-sse $(COMMON_CFLAGS)

LDFLAGS       := /subsystem:efi_application /entry:efi_main /nodefaultlib /Brepro

BUILD_DIR     := build
X64_OBJS      := $(patsubst src/%.c,$(BUILD_DIR)/x64/%.o,$(SRCS))
IA32_OBJS     := $(patsubst src/%.c,$(BUILD_DIR)/ia32/%.o,$(SRCS))

X64_EFI       := $(BUILD_DIR)/SetupX64.efi
IA32_EFI      := $(BUILD_DIR)/SetupIA32.efi
ESP_DIR       := $(BUILD_DIR)/esp
USB_IMG       := $(BUILD_DIR)/EFI-Setup-USB.img
PUBLISH_DIR   ?= /srv/dl/efi-setup

OVMF_CODE     := /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS_SRC := /usr/share/OVMF/OVMF_VARS_4M.fd
OVMF_VARS_RW  := $(BUILD_DIR)/OVMF_VARS_RW.fd

.PHONY: all clean esp img publish run run-mac

all: $(X64_EFI) $(IA32_EFI) esp img
	cp $(X64_EFI) SetupX64.efi
	cp $(IA32_EFI) SetupIA32.efi

$(BUILD_DIR)/x64/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(X64_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ia32/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(IA32_CFLAGS) -c $< -o $@

$(X64_EFI): $(X64_OBJS)
	$(LD) $(LDFLAGS) $(X64_OBJS) /out:$@

$(IA32_EFI): $(IA32_OBJS)
	$(LD) $(LDFLAGS) $(IA32_OBJS) /out:$@

esp: $(X64_EFI) $(IA32_EFI)
	@mkdir -p $(ESP_DIR)/EFI/BOOT
	cp $(X64_EFI) $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
	cp $(IA32_EFI) $(ESP_DIR)/EFI/BOOT/BOOTIA32.EFI
	cp $(X64_EFI) $(ESP_DIR)/SetupX64.efi
	cp $(IA32_EFI) $(ESP_DIR)/SetupIA32.efi

img: $(USB_IMG)

$(USB_IMG): $(X64_EFI) $(IA32_EFI) scripts/mkfat32.py
	$(PYTHON) scripts/mkfat32.py $(USB_IMG) $(X64_EFI) $(IA32_EFI)

$(OVMF_VARS_RW):
	@mkdir -p $(BUILD_DIR)
	cp $(OVMF_VARS_SRC) $(OVMF_VARS_RW)

run: all $(OVMF_VARS_RW)
	qemu-system-x86_64 \
		-machine q35 -m 512M -smp 4 \
		-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,format=raw,file=$(OVMF_VARS_RW) \
		-drive format=raw,file=$(USB_IMG) \
		-smbios type=0,vendor="American Megatrends Inc.",version="2.14.1219",date="10/25/2011" \
		-smbios type=1,manufacturer="ASUS",product="P8Z68-V PRO",version="Rev 1.xx",serial="B9M0AC123456" \
		-smbios type=2,manufacturer="ASUSTeK Computer INC.",product="P8Z68-V PRO",serial="MB-1234567890" \
		-net none

run-mac: all $(OVMF_VARS_RW)
	qemu-system-x86_64 \
		-machine q35 -m 512M -smp 4 \
		-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,format=raw,file=$(OVMF_VARS_RW) \
		-drive format=raw,file=$(USB_IMG) \
		-smbios type=0,vendor="Apple Inc.",version="IM121.88Z.0047.B1F.1110171115",date="10/17/2011" \
		-smbios type=1,manufacturer="Apple Inc.",product="iMac12,,2",version="1.0",serial="C02GH123DHJQ" \
		-smbios type=2,manufacturer="Apple Inc.",product="Mac-942B59F58194171B",serial="C0214030123DMT31M" \
		-smbios type=3,manufacturer="Apple Inc.",serial="C02GH123DHJQ" \
		-net none

publish: all
	@mkdir -p $(PUBLISH_DIR)
	install -m 0644 $(X64_EFI) $(PUBLISH_DIR)/SetupX64.efi
	install -m 0644 $(IA32_EFI) $(PUBLISH_DIR)/SetupIA32.efi
	install -m 0644 $(X64_EFI) $(PUBLISH_DIR)/BOOTX64.EFI
	install -m 0644 $(IA32_EFI) $(PUBLISH_DIR)/BOOTIA32.EFI
	install -m 0644 $(USB_IMG) $(PUBLISH_DIR)/EFI-Setup-USB.img
	install -m 0644 README.md $(PUBLISH_DIR)/README.md
	rm -f $(PUBLISH_DIR)/EFI-Setup-ESP.zip $(PUBLISH_DIR)/EFI-Setup-USB.img.zip
	cd $(ESP_DIR) && zip -r -9 $(abspath $(PUBLISH_DIR))/EFI-Setup-ESP.zip EFI SetupX64.efi SetupIA32.efi
	zip -j -9 $(PUBLISH_DIR)/EFI-Setup-USB.img.zip $(USB_IMG)
	chmod 0644 $(PUBLISH_DIR)/EFI-Setup-ESP.zip $(PUBLISH_DIR)/EFI-Setup-USB.img.zip
	cd $(PUBLISH_DIR) && sha256sum SetupX64.efi SetupIA32.efi BOOTX64.EFI BOOTIA32.EFI EFI-Setup-ESP.zip EFI-Setup-USB.img EFI-Setup-USB.img.zip README.md > SHA256SUMS.txt
	chmod 0644 $(PUBLISH_DIR)/SHA256SUMS.txt
	@echo "[OK] Published to $(PUBLISH_DIR) (https://dl.blueskychan.dev/efi-setup/)"

clean:
	rm -rf $(BUILD_DIR) SetupX64.efi SetupIA32.efi
