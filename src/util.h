#ifndef EFI_SETUP_UTIL_H
#define EFI_SETUP_UTIL_H

#include "efi.h"

/* Freestanding standard memory ops */
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
void *memmove(void *dst, const void *src, size_t n);
int   memcmp(const void *a, const void *b, size_t n);

/* UEFI Pool helpers */
VOID *alloc_pool(UINTN size);
VOID *alloc_zero_pool(UINTN size);
VOID  free_pool(VOID *buf);

/* 64-bit division safe on both IA32 and X64 */
UINT64 u64_divmod(UINT64 num, UINT32 den, UINT32 *rem_out);

/* Narrow (ASCII) string helpers */
UINTN   str_len(const CHAR8 *s);
INTN    str_cmp(const CHAR8 *a, const CHAR8 *b);
INTN    str_ncmp(const CHAR8 *a, const CHAR8 *b, UINTN n);
INTN    str_icmp(const CHAR8 *a, const CHAR8 *b);
VOID    str_cpy(CHAR8 *dst, const CHAR8 *src, UINTN max_len);
BOOLEAN str_contains_icase(const CHAR8 *haystack, const CHAR8 *needle);

/* Wide (UTF-16LE CHAR16) string helpers */
UINTN   wstr_len(const CHAR16 *s);
INTN    wstr_cmp(const CHAR16 *a, const CHAR16 *b);
INTN    wstr_icmp(const CHAR16 *a, const CHAR16 *b);
VOID    wstr_cpy(CHAR16 *dst, const CHAR16 *src, UINTN max_chars);
VOID    wstr_cat(CHAR16 *dst, const CHAR16 *src, UINTN max_chars);
BOOLEAN wstr_contains_icase(const CHAR16 *haystack, const CHAR16 *needle);
VOID    ascii_to_wstr(CHAR16 *dst, const CHAR8 *src, UINTN max_chars);
VOID    wstr_to_ascii(CHAR8 *dst, const CHAR16 *src, UINTN max_chars);

/* Formatted string builder (UTF-16LE and ASCII)
 * Supported specifiers:
 *   %s  -> const CHAR8*
 *   %S  -> const CHAR16*
 *   %c  -> char / CHAR16
 *   %d  -> INT32
 *   %u  -> UINT32
 *   %lu -> UINT64
 *   %x, %X   -> UINT32 hex
 *   %lx, %lX -> UINT64 hex
 *   %p  -> pointer hex
 *   Width & flags: '-', '0', numeric width (e.g. %02u, %08X, %016lX, %-20s)
 */
INTN wvsnprintf(CHAR16 *buf, UINTN max_chars, const CHAR8 *fmt, va_list ap);
INTN wsnprintf(CHAR16 *buf, UINTN max_chars, const CHAR8 *fmt, ...);
INTN snprintf_ascii(CHAR8 *buf, UINTN max_chars, const CHAR8 *fmt, ...);

/* Parsing helpers */
BOOLEAN parse_hex_u64(const CHAR8 *s, UINT64 *out);
BOOLEAN parse_dec_u64(const CHAR8 *s, UINT64 *out);
UINTN   parse_hex_bytes(const CHAR8 *s, UINT8 *out_bytes, UINTN max_bytes);

/* GUID helpers */
BOOLEAN      guid_equal(const EFI_GUID *a, const EFI_GUID *b);
const CHAR8 *guid_friendly_name(const EFI_GUID *g);
VOID         guid_to_str(const EFI_GUID *g, CHAR8 *out, UINTN max_len);
BOOLEAN      parse_guid_str(const CHAR8 *s, EFI_GUID *out);

/* EFI status & memory type names */
const CHAR8 *efi_status_str(EFI_STATUS st);
const CHAR8 *efi_mem_type_short(UINT32 type);
const CHAR8 *efi_mem_type_full(UINT32 type);

/* Protocol compatibility helpers (UEFI 2.x + Apple EFI 1.10) */
EFI_STATUS efi_locate_protocol(EFI_GUID *protocol, VOID **interface);
EFI_STATUS efi_locate_handles(EFI_GUID *protocol, UINTN *count_out, EFI_HANDLE **handles_out);

/* CPU, Port I/O, Safe MSR & Safe Page-Table Memory Probe */
VOID    cpu_cpuid(UINT32 leaf, UINT32 subleaf, UINT32 *eax, UINT32 *ebx, UINT32 *ecx, UINT32 *edx);
VOID    io_out8(UINT16 port, UINT8 val);
UINT8   io_in8(UINT16 port);
VOID    io_out16(UINT16 port, UINT16 val);
UINT16  io_in16(UINT16 port);
VOID    io_out32(UINT16 port, UINT32 val);
UINT32  io_in32(UINT16 port);
BOOLEAN cpu_safe_rdmsr(UINT32 msr, UINT64 *out_val);
BOOLEAN cpu_safe_wrmsr(UINT32 msr, UINT64 val);
VOID    cpu_invalidate_probe_cache(VOID);
BOOLEAN cpu_probe_address(UINT64 phys_addr, BOOLEAN *out_mapped, BOOLEAN *out_writable);
BOOLEAN safe_read_mem(UINT64 phys_addr, VOID *dst, UINTN len);
BOOLEAN safe_write_byte(UINT64 phys_addr, UINT8 val, BOOLEAN *out_verified);

/* Keyboard input helpers (strictly keyboard-only, no mouse) */
BOOLEAN wait_key_timeout_ms(EFI_INPUT_KEY *out_key, UINTN timeout_ms);
VOID    wait_key_blocking(EFI_INPUT_KEY *out_key);
VOID    drain_keys(VOID);

#endif /* EFI_SETUP_UTIL_H */
