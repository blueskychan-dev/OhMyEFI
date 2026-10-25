#!/usr/bin/env python3
"""
Builds a spec-compliant GPT + FAT32 EFI System Partition disk image (.img)
without requiring root privileges, loop devices, or mtools.
Compatible with Intel iMac/MacBook Startup Manager, QEMU/OVMF, VMware,
VirtualBox, and real UEFI PCs.
"""

import os
import struct
import sys
import uuid
import zlib


SECTOR_SIZE = 512
TOTAL_SECTORS = 81920  # 40 MiB (> 65,525 clusters at 1 sec/cluster => genuine FAT32)
PART_START_LBA = 2048
PART_END_LBA = TOTAL_SECTORS - 64
PART_SECTORS = PART_END_LBA - PART_START_LBA + 1

EFI_SYSTEM_PARTITION_GUID = uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")


def guid_to_mixed_endian(u: uuid.UUID) -> bytes:
    return u.bytes_le


def build_fat32_volume(num_sectors: int, files_spec: list) -> bytearray:
    """
    files_spec: list of (tuple_of_dir_parts, filename_str, raw_bytes)
    Supports 8.3 uppercase names cleanly (plus simple subdirs like EFI/BOOT).
    """
    vol = bytearray(num_sectors * SECTOR_SIZE)
    reserved_sectors = 32
    num_fats = 2
    sec_per_clus = 1

    # Solve fat_sz_32: data_sectors = num_sectors - reserved - 2 * fat_sz
    # Each FAT sector holds 128 32-bit entries
    fat_sz = ((num_sectors - reserved_sectors) + 255) // 128 + 8
    first_data_sec = reserved_sectors + num_fats * fat_sz
    total_clusters = (num_sectors - first_data_sec) // sec_per_clus
    assert total_clusters >= 65525, f"FAT32 needs >=65525 clusters, got {total_clusters}"

    # Boot Sector (BPB) at sector 0
    bpb = bytearray(SECTOR_SIZE)
    bpb[0:3] = b"\xEB\x58\x90"
    bpb[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", bpb, 11, SECTOR_SIZE)       # BytsPerSec
    bpb[13] = sec_per_clus                             # SecPerClus
    struct.pack_into("<H", bpb, 14, reserved_sectors)  # RsvdSecCnt
    bpb[16] = num_fats                                 # NumFATs
    struct.pack_into("<H", bpb, 17, 0)                 # RootEntCnt (0 for FAT32)
    struct.pack_into("<H", bpb, 19, 0)                 # TotSec16
    bpb[21] = 0xF8                                     # Media
    struct.pack_into("<H", bpb, 22, 0)                 # FATSz16
    struct.pack_into("<H", bpb, 24, 63)                # SecPerTrk
    struct.pack_into("<H", bpb, 26, 255)               # NumHeads
    struct.pack_into("<I", bpb, 28, PART_START_LBA)    # HiddSec
    struct.pack_into("<I", bpb, 32, num_sectors)       # TotSec32
    struct.pack_into("<I", bpb, 36, fat_sz)            # FATSz32
    struct.pack_into("<H", bpb, 40, 0)                 # ExtFlags
    struct.pack_into("<H", bpb, 42, 0)                 # FSVer
    struct.pack_into("<I", bpb, 44, 2)                 # RootClus = 2
    struct.pack_into("<H", bpb, 48, 1)                 # FSInfo = 1
    struct.pack_into("<H", bpb, 50, 6)                 # BkBootSec = 6
    bpb[64] = 0x80                                     # DrvNum
    bpb[66] = 0x29                                     # BootSig
    struct.pack_into("<I", bpb, 67, 0x2011EF15)        # VolID
    bpb[71:82] = b"EFI_SETUP  "                        # VolLab (11 chars)
    bpb[82:90] = b"FAT32   "                           # FilSysType
    bpb[510:512] = b"\x55\xAA"

    vol[0:SECTOR_SIZE] = bpb
    vol[6 * SECTOR_SIZE : 7 * SECTOR_SIZE] = bpb  # Backup boot sector

    # FSInfo at sector 1 (and backup at 7)
    fsinfo = bytearray(SECTOR_SIZE)
    struct.pack_into("<I", fsinfo, 0, 0x41615252)
    struct.pack_into("<I", fsinfo, 484, 0x61417272)
    struct.pack_into("<I", fsinfo, 488, 0xFFFFFFFF)
    struct.pack_into("<I", fsinfo, 492, 0xFFFFFFFF)
    fsinfo[510:512] = b"\x55\xAA"
    vol[1 * SECTOR_SIZE : 2 * SECTOR_SIZE] = fsinfo
    vol[7 * SECTOR_SIZE : 8 * SECTOR_SIZE] = fsinfo

    fat = [0] * (total_clusters + 2)
    fat[0] = 0x0FFFFFF8
    fat[1] = 0x0FFFFFFF
    fat[2] = 0x0FFFFFFF  # Root directory starts at cluster 2

    next_free_clus = 3

    def alloc_clusters(count: int) -> int:
        nonlocal next_free_clus
        start = next_free_clus
        for i in range(count):
            c = start + i
            fat[c] = (c + 1) if (i + 1 < count) else 0x0FFFFFFF
        next_free_clus += count
        return start

    def clus_offset(clus: int) -> int:
        return (first_data_sec + (clus - 2) * sec_per_clus) * SECTOR_SIZE

    def make_short_name(name: str) -> bytes:
        up = name.upper()
        if "." in up:
            stem, ext = up.rsplit(".", 1)
        else:
            stem, ext = up, ""
        stem = (stem[:8]).ljust(8, " ")
        ext = (ext[:3]).ljust(3, " ")
        return (stem + ext).encode("ascii")

    def make_dirent(name11: bytes, attr: int, first_clus: int, size: int) -> bytes:
        ent = bytearray(32)
        ent[0:11] = name11
        ent[11] = attr
        # Date: 2011-10-25, Time: 12:00:00
        time_val = (12 << 11) | (0 << 5) | 0
        date_val = ((2011 - 1980) << 9) | (10 << 5) | 25
        struct.pack_into("<H", ent, 14, time_val)
        struct.pack_into("<H", ent, 16, date_val)
        struct.pack_into("<H", ent, 18, date_val)
        struct.pack_into("<H", ent, 20, (first_clus >> 16) & 0xFFFF)
        struct.pack_into("<H", ent, 22, time_val)
        struct.pack_into("<H", ent, 24, date_val)
        struct.pack_into("<H", ent, 26, first_clus & 0xFFFF)
        struct.pack_into("<I", ent, 28, size)
        return bytes(ent)

    # Directory tree in memory: path_tuple -> list of 32-byte entries + assigned cluster
    dir_clusters = {(): 2}
    dir_entries = {(): [make_dirent(b"EFI_SETUP  ", 0x08, 0, 0)]}  # Volume label

    def ensure_dir(path_tuple: tuple):
        if path_tuple in dir_clusters:
            return
        parent = path_tuple[:-1]
        ensure_dir(parent)
        c = alloc_clusters(2)  # 1 KB for directory entries
        dir_clusters[path_tuple] = c
        parent_c = dir_clusters[parent]
        dot_parent_c = 0 if parent == () else parent_c
        dir_entries[path_tuple] = [
            make_dirent(b".          ", 0x10, c, 0),
            make_dirent(b"..         ", 0x10, dot_parent_c, 0),
        ]
        dir_entries[parent].append(
            make_dirent(make_short_name(path_tuple[-1]), 0x10, c, 0)
        )

    for dir_parts, fname, data in files_spec:
        ensure_dir(dir_parts)
        n_clus = max(1, (len(data) + SECTOR_SIZE - 1) // SECTOR_SIZE)
        fc = alloc_clusters(n_clus)
        off = clus_offset(fc)
        vol[off : off + len(data)] = data
        dir_entries[dir_parts].append(
            make_dirent(make_short_name(fname), 0x20, fc, len(data))
        )

    # Write directory entries into clusters
    for path_tuple, ents in dir_entries.items():
        c = dir_clusters[path_tuple]
        raw = b"".join(ents)
        off = clus_offset(c)
        vol[off : off + len(raw)] = raw

    # Serialize FATs
    fat_bytes = bytearray(fat_sz * SECTOR_SIZE)
    for i, val in enumerate(fat):
        if i * 4 + 4 <= len(fat_bytes):
            struct.pack_into("<I", fat_bytes, i * 4, val & 0x0FFFFFFF)
    for f in range(num_fats):
        f_off = (reserved_sectors + f * fat_sz) * SECTOR_SIZE
        vol[f_off : f_off + len(fat_bytes)] = fat_bytes

    return vol


def build_gpt_disk(out_path: str, x64_efi: str, ia32_efi: str):
    files = []
    with open(x64_efi, "rb") as f:
        x64_data = f.read()
    files.append((("EFI", "BOOT"), "BOOTX64.EFI", x64_data))
    files.append(((), "SETUPX64.EFI", x64_data))

    if ia32_efi and os.path.exists(ia32_efi):
        with open(ia32_efi, "rb") as f:
            ia32_data = f.read()
        files.append((("EFI", "BOOT"), "BOOTIA32.EFI", ia32_data))
        files.append(((), "SETUPIA3.EFI", ia32_data))

    fat_vol = build_fat32_volume(PART_SECTORS, files)
    disk = bytearray(TOTAL_SECTORS * SECTOR_SIZE)

    # Copy FAT32 ESP at PART_START_LBA
    disk[PART_START_LBA * SECTOR_SIZE : (PART_START_LBA + PART_SECTORS) * SECTOR_SIZE] = fat_vol

    # Protective MBR at LBA 0
    mbr = bytearray(SECTOR_SIZE)
    # Partition 1 entry at offset 446: Protective GPT (type 0xEE)
    mbr[446 + 0] = 0x00
    mbr[446 + 1 : 446 + 4] = b"\x00\x02\x00"
    mbr[446 + 4] = 0xEE
    mbr[446 + 5 : 446 + 8] = b"\xFF\xFF\xFF"
    struct.pack_into("<I", mbr, 446 + 8, 1)
    struct.pack_into("<I", mbr, 446 + 12, TOTAL_SECTORS - 1)
    mbr[510:512] = b"\x55\xAA"
    disk[0:SECTOR_SIZE] = mbr

    # GPT Partition Entries (128 entries * 128 bytes = 16384 bytes = 32 sectors)
    entries = bytearray(128 * 128)
    part_guid = uuid.UUID("2011EF15-0001-4E75-A211-5E70CF602011")
    name_utf16 = "EFI System Partition".encode("utf-16le").ljust(72, b"\x00")[:72]
    struct.pack_into(
        "<16s16sQQQ72s",
        entries,
        0,
        guid_to_mixed_endian(EFI_SYSTEM_PARTITION_GUID),
        guid_to_mixed_endian(part_guid),
        PART_START_LBA,
        PART_END_LBA,
        0,
        name_utf16,
    )
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF

    disk_guid = uuid.UUID("2011EF15-0000-4E75-A211-5E70CF602011")

    def make_gpt_header(my_lba: int, alt_lba: int, part_entry_lba: int) -> bytes:
        hdr = bytearray(SECTOR_SIZE)
        struct.pack_into(
            "<8sIIIIQQQQ16sQIII",
            hdr,
            0,
            b"EFI PART",
            0x00010000,
            92,
            0,  # CRC32 placeholder
            0,
            my_lba,
            alt_lba,
            34,
            TOTAL_SECTORS - 34,
            guid_to_mixed_endian(disk_guid),
            part_entry_lba,
            128,
            128,
            entries_crc,
        )
        hdr_crc = zlib.crc32(hdr[:92]) & 0xFFFFFFFF
        struct.pack_into("<I", hdr, 16, hdr_crc)
        return bytes(hdr)

    # Primary GPT (Header at LBA 1, Entries at LBA 2..33)
    disk[1 * SECTOR_SIZE : 2 * SECTOR_SIZE] = make_gpt_header(1, TOTAL_SECTORS - 1, 2)
    disk[2 * SECTOR_SIZE : 34 * SECTOR_SIZE] = entries

    # Backup GPT (Entries at TOTAL_SECTORS-33..TOTAL_SECTORS-2, Header at TOTAL_SECTORS-1)
    b_ent_lba = TOTAL_SECTORS - 33
    disk[b_ent_lba * SECTOR_SIZE : (b_ent_lba + 32) * SECTOR_SIZE] = entries
    disk[(TOTAL_SECTORS - 1) * SECTOR_SIZE : TOTAL_SECTORS * SECTOR_SIZE] = make_gpt_header(
        TOTAL_SECTORS - 1, 1, b_ent_lba
    )

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(disk)
    print(f"[OK] Built bootable GPT+FAT32 UEFI image: {out_path} ({len(disk) // (1024*1024)} MiB)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: mkfat32.py <output.img> <SetupX64.efi> [SetupIA32.efi]")
        sys.exit(1)
    out_img = sys.argv[1]
    x64 = sys.argv[2]
    ia32 = sys.argv[3] if len(sys.argv) > 3 else None
    build_gpt_disk(out_img, x64, ia32)
