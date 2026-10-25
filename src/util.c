#include "util.h"

/* Global UEFI Pointers */
EFI_HANDLE           gImageHandle = NULL;
EFI_SYSTEM_TABLE    *gST = NULL;
EFI_BOOT_SERVICES   *gBS = NULL;
EFI_RUNTIME_SERVICES *gRT = NULL;

/* Standard & Vendor GUIDs */
EFI_GUID gEfiGlobalVariableGuid =
    { 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } };
EFI_GUID gEfiImageSecurityDatabaseGuid =
    { 0xD719B2CB, 0x3D3A, 0x4596, { 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F } };
EFI_GUID gEfiSmbiosTableGuid =
    { 0xEB9D2D31, 0x2D88, 0x11D3, { 0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } };
EFI_GUID gEfiSmbios3TableGuid =
    { 0xF2FD1544, 0x9794, 0x4A2C, { 0x99, 0x2E, 0xE5, 0xBB, 0xCF, 0x20, 0xE3, 0x94 } };
EFI_GUID gEfiAcpi20TableGuid =
    { 0x8868E871, 0xE4F1, 0x11D3, { 0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81 } };
EFI_GUID gEfiAcpi10TableGuid =
    { 0xEB9D2D30, 0x2D88, 0x11D3, { 0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } };
EFI_GUID gEfiConsoleControlProtocolGuid =
    { 0xF42F7782, 0x012E, 0x4C12, { 0x99, 0x56, 0x49, 0xF9, 0x43, 0x04, 0xF7, 0x21 } };
EFI_GUID gEfiLoadedImageProtocolGuid =
    { 0x5B1B31A1, 0x9562, 0x11D2, { 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };
EFI_GUID gEfiSimpleFileSystemProtocolGuid =
    { 0x964E5B22, 0x6459, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };
EFI_GUID gEfiFileInfoGuid =
    { 0x09576E92, 0x6D3F, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };
EFI_GUID gEfiFileSystemInfoGuid =
    { 0x09576E93, 0x6D3F, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };
EFI_GUID gEfiBlockIoProtocolGuid =
    { 0x964E5B21, 0x6459, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };
EFI_GUID gEfiDevicePathProtocolGuid =
    { 0x09576E91, 0x6D3F, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };
EFI_GUID gEfiDevicePathToTextProtocolGuid =
    { 0x8B843E20, 0x8132, 0x4852, { 0x90, 0xCC, 0x55, 0x1A, 0x4E, 0x4A, 0x7F, 0x1C } };
EFI_GUID gEfiPciIoProtocolGuid =
    { 0x4CF5B200, 0x68B8, 0x4CA5, { 0x9E, 0xEC, 0xB2, 0x3E, 0x3F, 0x50, 0x02, 0x9A } };
EFI_GUID gEfiGraphicsOutputProtocolGuid =
    { 0x9042A9DE, 0x23DC, 0x4A38, { 0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A } };
EFI_GUID gEfiHiiDatabaseProtocolGuid =
    { 0xEF9FC172, 0xA1B2, 0x4693, { 0xB3, 0x27, 0x6D, 0x32, 0xFC, 0x41, 0x60, 0x42 } };
EFI_GUID gEfiHiiConfigRoutingProtocolGuid =
    { 0x587E72D7, 0xCC50, 0x4F79, { 0x82, 0x09, 0xCA, 0x29, 0x1F, 0xC1, 0xA1, 0x0F } };
EFI_GUID gEfiHiiConfigAccessProtocolGuid =
    { 0x330D4706, 0xF2A0, 0x4E4F, { 0xA3, 0x69, 0xB6, 0x6F, 0xA8, 0xD5, 0x43, 0x85 } };
EFI_GUID gEdkiiIfrBitVarstoreGuid =
    { 0x82DDD68B, 0x9163, 0x4187, { 0x9B, 0x27, 0x20, 0xA8, 0xFD, 0x60, 0xA7, 0x1D } };
EFI_GUID gEfiFirmwareVolume2ProtocolGuid =
    { 0x220E73B6, 0x6BDB, 0x4413, { 0x84, 0x05, 0xB9, 0x74, 0xB1, 0x08, 0x61, 0x9A } };
EFI_GUID gEfiMpServicesProtocolGuid =
    { 0x3FDDA605, 0xA76E, 0x4F46, { 0xAD, 0x29, 0x12, 0xF4, 0x53, 0x1B, 0x3D, 0x08 } };
EFI_GUID gAppleBootVariableGuid =
    { 0x7C436110, 0xAB2A, 0x4BBB, { 0xA8, 0x80, 0xFE, 0x41, 0x99, 0x5C, 0x9F, 0x82 } };
EFI_GUID gAppleFirmwareVariableGuid =
    { 0x4D1EDE05, 0x38C7, 0x4A6A, { 0x9C, 0xC6, 0x4B, 0xCC, 0xA8, 0xB3, 0x8C, 0x14 } };
EFI_GUID gAppleGpuPowerPrefsGuid =
    { 0xFA4CE28D, 0xB62F, 0x4C99, { 0x9C, 0xC3, 0x68, 0x15, 0x68, 0x6E, 0x30, 0xF9 } };
EFI_GUID gSetupUtilityConfigGuid =
    { 0x2011B105, 0xEF15, 0x4E75, { 0xA2, 0x11, 0x5E, 0x70, 0xCF, 0x60, 0x20, 0x11 } };
EFI_GUID gOhMyEfiAutoPatchGuid =
    { 0x2026B105, 0xAE70, 0x4A99, { 0xB8, 0x55, 0x91, 0xC4, 0x01, 0x50, 0x20, 0x26 } };

/* Additional recognizable GUIDs for Debug/Config Table display */
static const struct {
    EFI_GUID     guid;
    const CHAR8 *name;
} kKnownGuids[] = {
    { { 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } }, "EfiGlobalVar" },
    { { 0xD719B2CB, 0x3D3A, 0x4596, { 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F } }, "EfiImageSecDB" },
    { { 0x7C436110, 0xAB2A, 0x4BBB, { 0xA8, 0x80, 0xFE, 0x41, 0x99, 0x5C, 0x9F, 0x82 } }, "AppleBoot" },
    { { 0x4D1EDE05, 0x38C7, 0x4A6A, { 0x9C, 0xC6, 0x4B, 0xCC, 0xA8, 0xB3, 0x8C, 0x14 } }, "AppleFirmware" },
    { { 0x4D1FDA02, 0x38C7, 0x4A6A, { 0x9C, 0xC6, 0x4B, 0xCC, 0xA8, 0xB3, 0x8C, 0x14 } }, "AppleRTC/SMC" },
    { { 0xFA4CE28D, 0xB62F, 0x4C99, { 0x9C, 0xC3, 0x68, 0x15, 0x68, 0x6E, 0x30, 0xF9 } }, "AppleGpuPrefs" },
    { { 0xEC87D643, 0xEBA4, 0x4BB5, { 0xA1, 0xE5, 0x3F, 0x3E, 0x36, 0xB2, 0x0D, 0xA9 } }, "AmiSetup" },
    { { 0xA04A27F4, 0xDF00, 0x4D42, { 0xB5, 0x52, 0x39, 0x51, 0x13, 0x02, 0x11, 0x3D } }, "InsydeSetup" },
    { { 0xEB9D2D31, 0x2D88, 0x11D3, { 0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } }, "SMBIOS_2.x" },
    { { 0xF2FD1544, 0x9794, 0x4A2C, { 0x99, 0x2E, 0xE5, 0xBB, 0xCF, 0x20, 0xE3, 0x94 } }, "SMBIOS_3.0" },
    { { 0x8868E871, 0xE4F1, 0x11D3, { 0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81 } }, "ACPI_2.0_RSDP" },
    { { 0xEB9D2D30, 0x2D88, 0x11D3, { 0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } }, "ACPI_1.0_RSDP" },
    { { 0xEB9D2D2F, 0x2D88, 0x11D3, { 0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } }, "MPS_Table" },
    { { 0x05AD34BA, 0x6F02, 0x4214, { 0x95, 0x2E, 0x4D, 0xA0, 0x39, 0x8E, 0x2B, 0xB9 } }, "DXE_Services" },
    { { 0x7739F24C, 0x93D7, 0x11D4, { 0x9A, 0x3A, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } }, "HOB_List" },
    { { 0xDCFA911D, 0x26EB, 0x469F, { 0xA2, 0x20, 0x38, 0xB7, 0xDC, 0x46, 0x12, 0x20 } }, "MemAttrTable" },
    { { 0xB122A263, 0x3661, 0x4F68, { 0x99, 0x29, 0x78, 0xF8, 0xB0, 0xD6, 0x21, 0x80 } }, "ESRT_Firmware" },
    { { 0xEE4E5898, 0x3914, 0x4259, { 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF } }, "LZMA_Compress" },
    { { 0x4C19049F, 0x4137, 0x4DD3, { 0x9C, 0x10, 0x8B, 0x97, 0xA8, 0x3F, 0xFD, 0xFA } }, "MemoryTypeInfo" },
    { { 0x49152E77, 0x1ADA, 0x4764, { 0xB7, 0xA2, 0x7A, 0xFE, 0xFE, 0xD9, 0x5E, 0x8B } }, "DebugImageInfo" },
    { { 0x0053D9D6, 0x2659, 0x4599, { 0xA2, 0x6B, 0xEF, 0x45, 0x36, 0xE6, 0x31, 0xA9 } }, "OvmfPlatform" },
    { { 0x59324945, 0xEC44, 0x4C0D, { 0xB1, 0xCD, 0x9D, 0xB1, 0x39, 0xDF, 0x07, 0x0C } }, "OvmfPlatformCfg" },
    { { 0x158DEF5A, 0xF656, 0x419C, { 0xB0, 0x27, 0x7A, 0x31, 0x92, 0xC0, 0x79, 0xD2 } }, "EfiShellEnv" },
    { { 0x605DAB50, 0xE046, 0x4300, { 0xAB, 0xB6, 0x3D, 0xD8, 0x10, 0xDD, 0x8B, 0x23 } }, "ShimLock" },
    { { 0x2011B105, 0xEF15, 0x4E75, { 0xA2, 0x11, 0x5E, 0x70, 0xCF, 0x60, 0x20, 0x11 } }, "SetupUtilCfg" },
};

/* Freestanding standard memory operations */
void *memcpy(void *dst, const void *src, size_t n) {
    UINT8 *d = (UINT8 *)dst;
    const UINT8 *s = (const UINT8 *)src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    UINT8 *d = (UINT8 *)dst;
    UINT8 v = (UINT8)c;
    while (n--) {
        *d++ = v;
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    UINT8 *d = (UINT8 *)dst;
    const UINT8 *s = (const UINT8 *)src;
    if (d == s || n == 0) {
        return dst;
    }
    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    } else {
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const UINT8 *pa = (const UINT8 *)a;
    const UINT8 *pb = (const UINT8 *)b;
    while (n--) {
        if (*pa != *pb) {
            return (int)*pa - (int)*pb;
        }
        pa++;
        pb++;
    }
    return 0;
}

VOID *alloc_pool(UINTN size) {
    VOID *buf = NULL;
    if (!gBS || size == 0) return NULL;
    if (EFI_ERROR(gBS->AllocatePool(EfiLoaderData, size, &buf))) {
        return NULL;
    }
    return buf;
}

VOID *alloc_zero_pool(UINTN size) {
    VOID *buf = alloc_pool(size);
    if (buf) {
        memset(buf, 0, size);
    }
    return buf;
}

VOID free_pool(VOID *buf) {
    if (gBS && buf) {
        gBS->FreePool(buf);
    }
}

UINT64 u64_divmod(UINT64 num, UINT32 den, UINT32 *rem_out) {
    UINT64 quot = 0;
    UINT64 rem = 0;
    int i;
    if (den == 0) {
        if (rem_out) *rem_out = 0;
        return 0;
    }
    for (i = 63; i >= 0; i--) {
        rem = (rem << 1) | ((num >> i) & 1ULL);
        if (rem >= (UINT64)den) {
            rem -= (UINT64)den;
            quot |= (1ULL << i);
        }
    }
    if (rem_out) {
        *rem_out = (UINT32)rem;
    }
    return quot;
}

static CHAR8 ascii_tolower(CHAR8 c) {
    if (c >= 'A' && c <= 'Z') return (CHAR8)(c + ('a' - 'A'));
    return c;
}

static CHAR16 wchr_tolower(CHAR16 c) {
    if (c >= L'A' && c <= L'Z') return (CHAR16)(c + (L'a' - L'A'));
    return c;
}

UINTN str_len(const CHAR8 *s) {
    UINTN n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

INTN str_cmp(const CHAR8 *a, const CHAR8 *b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (INTN)(UINT8)*a - (INTN)(UINT8)*b;
}

INTN str_ncmp(const CHAR8 *a, const CHAR8 *b, UINTN n) {
    if (n == 0) return 0;
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (n-- > 0) {
        if (*a != *b) return (INTN)(UINT8)*a - (INTN)(UINT8)*b;
        if (*a == 0) return 0;
        a++;
        b++;
    }
    return 0;
}

INTN str_icmp(const CHAR8 *a, const CHAR8 *b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (*a && (ascii_tolower(*a) == ascii_tolower(*b))) {
        a++;
        b++;
    }
    return (INTN)(UINT8)ascii_tolower(*a) - (INTN)(UINT8)ascii_tolower(*b);
}

VOID str_cpy(CHAR8 *dst, const CHAR8 *src, UINTN max_len) {
    UINTN i = 0;
    if (!dst || max_len == 0) return;
    if (src) {
        while (i + 1 < max_len && src[i]) {
            dst[i] = src[i];
            i++;
        }
    }
    dst[i] = '\0';
}

BOOLEAN str_contains_icase(const CHAR8 *haystack, const CHAR8 *needle) {
    UINTN hlen, nlen, i, j;
    if (!needle || !needle[0]) return TRUE;
    if (!haystack) return FALSE;
    hlen = str_len(haystack);
    nlen = str_len(needle);
    if (nlen > hlen) return FALSE;
    for (i = 0; i + nlen <= hlen; i++) {
        BOOLEAN ok = TRUE;
        for (j = 0; j < nlen; j++) {
            if (ascii_tolower(haystack[i + j]) != ascii_tolower(needle[j])) {
                ok = FALSE;
                break;
            }
        }
        if (ok) return TRUE;
    }
    return FALSE;
}

UINTN wstr_len(const CHAR16 *s) {
    UINTN n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

INTN wstr_cmp(const CHAR16 *a, const CHAR16 *b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (INTN)*a - (INTN)*b;
}

INTN wstr_icmp(const CHAR16 *a, const CHAR16 *b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (*a && (wchr_tolower(*a) == wchr_tolower(*b))) {
        a++;
        b++;
    }
    return (INTN)wchr_tolower(*a) - (INTN)wchr_tolower(*b);
}

VOID wstr_cpy(CHAR16 *dst, const CHAR16 *src, UINTN max_chars) {
    UINTN i = 0;
    if (!dst || max_chars == 0) return;
    if (src) {
        while (i + 1 < max_chars && src[i]) {
            dst[i] = src[i];
            i++;
        }
    }
    dst[i] = 0;
}

VOID wstr_cat(CHAR16 *dst, const CHAR16 *src, UINTN max_chars) {
    UINTN dlen;
    if (!dst || max_chars == 0) return;
    dlen = wstr_len(dst);
    if (dlen + 1 >= max_chars) return;
    wstr_cpy(dst + dlen, src, max_chars - dlen);
}

BOOLEAN wstr_contains_icase(const CHAR16 *haystack, const CHAR16 *needle) {
    UINTN hlen, nlen, i, j;
    if (!needle || !needle[0]) return TRUE;
    if (!haystack) return FALSE;
    hlen = wstr_len(haystack);
    nlen = wstr_len(needle);
    if (nlen > hlen) return FALSE;
    for (i = 0; i + nlen <= hlen; i++) {
        BOOLEAN ok = TRUE;
        for (j = 0; j < nlen; j++) {
            if (wchr_tolower(haystack[i + j]) != wchr_tolower(needle[j])) {
                ok = FALSE;
                break;
            }
        }
        if (ok) return TRUE;
    }
    return FALSE;
}

VOID ascii_to_wstr(CHAR16 *dst, const CHAR8 *src, UINTN max_chars) {
    UINTN i = 0;
    if (!dst || max_chars == 0) return;
    if (src) {
        while (i + 1 < max_chars && src[i]) {
            UINT8 ch = (UINT8)src[i];
            dst[i] = (ch >= 0x20 && ch <= 0x7E) ? (CHAR16)ch : L'?';
            i++;
        }
    }
    dst[i] = 0;
}

VOID wstr_to_ascii(CHAR8 *dst, const CHAR16 *src, UINTN max_chars) {
    UINTN i = 0;
    if (!dst || max_chars == 0) return;
    if (src) {
        while (i + 1 < max_chars && src[i]) {
            CHAR16 ch = src[i];
            dst[i] = (ch >= 0x20 && ch <= 0x7E) ? (CHAR8)ch : '?';
            i++;
        }
    }
    dst[i] = '\0';
}

static VOID emit_wchar(CHAR16 *buf, UINTN max_chars, UINTN *pos, CHAR16 c) {
    if (*pos + 1 < max_chars) {
        buf[*pos] = c;
    }
    (*pos)++;
}

INTN wvsnprintf(CHAR16 *buf, UINTN max_chars, const CHAR8 *fmt, va_list ap) {
    UINTN pos = 0;
    if (!buf || max_chars == 0) return 0;
    if (!fmt) {
        buf[0] = 0;
        return 0;
    }

    while (*fmt) {
        if (*fmt != '%') {
            emit_wchar(buf, max_chars, &pos, (CHAR16)(UINT8)*fmt++);
            continue;
        }
        fmt++; /* skip '%' */
        if (*fmt == '%') {
            emit_wchar(buf, max_chars, &pos, L'%');
            fmt++;
            continue;
        }

        BOOLEAN left_align = FALSE;
        BOOLEAN zero_pad = FALSE;
        UINTN width = 0;
        INTN precision = -1;
        BOOLEAN is_long = FALSE;

        while (*fmt == '-' || *fmt == '0') {
            if (*fmt == '-') left_align = TRUE;
            if (*fmt == '0') zero_pad = TRUE;
            fmt++;
        }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (UINTN)(*fmt - '0');
            fmt++;
        }
        if (*fmt == '.') {
            fmt++;
            precision = 0;
            while (*fmt >= '0' && *fmt <= '9') {
                precision = precision * 10 + (INTN)(*fmt - '0');
                fmt++;
            }
        }
        if (*fmt == 'l') {
            is_long = TRUE;
            fmt++;
            if (*fmt == 'l') fmt++;
        }

        CHAR8 spec = *fmt ? *fmt++ : '\0';
        if (spec == 'c') {
            CHAR16 ch = (CHAR16)va_arg(ap, int);
            if (!left_align) {
                while (width > 1) { emit_wchar(buf, max_chars, &pos, L' '); width--; }
            }
            emit_wchar(buf, max_chars, &pos, ch);
            if (left_align) {
                while (width > 1) { emit_wchar(buf, max_chars, &pos, L' '); width--; }
            }
        } else if (spec == 's') {
            const CHAR8 *s = va_arg(ap, const CHAR8 *);
            if (!s) s = "(null)";
            UINTN slen = str_len(s);
            if (precision >= 0 && (UINTN)precision < slen) slen = (UINTN)precision;
            if (!left_align) {
                while (width > slen) { emit_wchar(buf, max_chars, &pos, L' '); width--; }
            }
            for (UINTN i = 0; i < slen; i++) {
                emit_wchar(buf, max_chars, &pos, (CHAR16)(UINT8)s[i]);
            }
            if (left_align) {
                while (width > slen) { emit_wchar(buf, max_chars, &pos, L' '); width--; }
            }
        } else if (spec == 'S') {
            const CHAR16 *ws = va_arg(ap, const CHAR16 *);
            if (!ws) ws = L"(null)";
            UINTN slen = wstr_len(ws);
            if (precision >= 0 && (UINTN)precision < slen) slen = (UINTN)precision;
            if (!left_align) {
                while (width > slen) { emit_wchar(buf, max_chars, &pos, L' '); width--; }
            }
            for (UINTN i = 0; i < slen; i++) {
                emit_wchar(buf, max_chars, &pos, ws[i]);
            }
            if (left_align) {
                while (width > slen) { emit_wchar(buf, max_chars, &pos, L' '); width--; }
            }
        } else if (spec == 'd' || spec == 'u' || spec == 'x' || spec == 'X' || spec == 'p') {
            CHAR16 tmp[32];
            UINTN tlen = 0;
            BOOLEAN neg = FALSE;
            UINT64 uval = 0;
            UINT32 base = 10;
            BOOLEAN upper = (spec == 'X');

            if (spec == 'p') {
                uval = (UINT64)(UINTN)va_arg(ap, void *);
                base = 16;
                upper = TRUE;
                if (width == 0) width = sizeof(VOID *) * 2;
                zero_pad = TRUE;
            } else if (spec == 'd') {
                INT64 sval = is_long ? va_arg(ap, INT64) : (INT64)va_arg(ap, INT32);
                if (sval < 0) {
                    neg = TRUE;
                    uval = (UINT64)(-(sval + 1)) + 1ULL;
                } else {
                    uval = (UINT64)sval;
                }
            } else {
                uval = is_long ? va_arg(ap, UINT64) : (UINT64)va_arg(ap, UINT32);
                if (spec == 'x' || spec == 'X') base = 16;
            }

            if (uval == 0) {
                tmp[tlen++] = L'0';
            } else {
                while (uval != 0 && tlen < 30) {
                    UINT32 rem = 0;
                    uval = u64_divmod(uval, base, &rem);
                    if (rem < 10) tmp[tlen++] = (CHAR16)(L'0' + rem);
                    else tmp[tlen++] = (CHAR16)((upper ? L'A' : L'a') + (rem - 10));
                }
            }
            UINTN total = tlen + (neg ? 1 : 0);
            CHAR16 padc = (zero_pad && !left_align) ? L'0' : L' ';

            if (neg && padc == L'0') {
                emit_wchar(buf, max_chars, &pos, L'-');
            }
            if (!left_align) {
                while (width > total) { emit_wchar(buf, max_chars, &pos, padc); width--; }
            }
            if (neg && padc != L'0') {
                emit_wchar(buf, max_chars, &pos, L'-');
            }
            while (tlen > 0) {
                emit_wchar(buf, max_chars, &pos, tmp[--tlen]);
            }
            if (left_align) {
                while (width > total) { emit_wchar(buf, max_chars, &pos, L' '); width--; }
            }
        }
    }

    if (pos < max_chars) buf[pos] = 0;
    else buf[max_chars - 1] = 0;
    return (INTN)pos;
}

INTN wsnprintf(CHAR16 *buf, UINTN max_chars, const CHAR8 *fmt, ...) {
    va_list ap;
    INTN ret;
    va_start(ap, fmt);
    ret = wvsnprintf(buf, max_chars, fmt, ap);
    va_end(ap);
    return ret;
}

INTN snprintf_ascii(CHAR8 *buf, UINTN max_chars, const CHAR8 *fmt, ...) {
    CHAR16 wbuf[512];
    va_list ap;
    INTN ret;
    if (!buf || max_chars == 0) return 0;
    va_start(ap, fmt);
    ret = wvsnprintf(wbuf, 512, fmt, ap);
    va_end(ap);
    UINTN i = 0;
    while (i + 1 < max_chars && wbuf[i]) {
        CHAR16 ch = wbuf[i];
        if ((ch >= 0x20 && ch <= 0x7E) || ch == L'\n' || ch == L'\r' || ch == L'\t') {
            buf[i] = (CHAR8)ch;
        } else {
            buf[i] = '?';
        }
        i++;
    }
    buf[i] = '\0';
    return ret;
}

static INT32 hex_digit(CHAR8 c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

BOOLEAN parse_hex_u64(const CHAR8 *s, UINT64 *out) {
    UINT64 val = 0;
    BOOLEAN any = FALSE;
    if (!s || !out) return FALSE;
    while (*s == ' ') s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (*s && *s != ' ') {
        INT32 d = hex_digit(*s);
        if (d < 0) return FALSE;
        val = (val << 4) | (UINT64)d;
        any = TRUE;
        s++;
    }
    if (!any) return FALSE;
    *out = val;
    return TRUE;
}

BOOLEAN parse_dec_u64(const CHAR8 *s, UINT64 *out) {
    UINT64 val = 0;
    BOOLEAN any = FALSE;
    if (!s || !out) return FALSE;
    while (*s == ' ') s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return parse_hex_u64(s, out);
    }
    while (*s && *s != ' ') {
        if (*s < '0' || *s > '9') return FALSE;
        val = val * 10 + (UINT64)(*s - '0');
        any = TRUE;
        s++;
    }
    if (!any) return FALSE;
    *out = val;
    return TRUE;
}

UINTN parse_hex_bytes(const CHAR8 *s, UINT8 *out_bytes, UINTN max_bytes) {
    UINTN count = 0;
    if (!s || !out_bytes) return 0;
    while (*s && count < max_bytes) {
        while (*s == ' ' || *s == ',' || *s == ':' || *s == '-') s++;
        if (!*s) break;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
        INT32 hi = hex_digit(*s);
        if (hi < 0) break;
        s++;
        INT32 lo = hex_digit(*s);
        if (lo >= 0) {
            s++;
            out_bytes[count++] = (UINT8)((hi << 4) | lo);
        } else {
            out_bytes[count++] = (UINT8)hi;
        }
    }
    return count;
}

BOOLEAN guid_equal(const EFI_GUID *a, const EFI_GUID *b) {
    if (!a || !b) return FALSE;
    return memcmp(a, b, sizeof(EFI_GUID)) == 0;
}

const CHAR8 *guid_friendly_name(const EFI_GUID *g) {
    UINTN i;
    if (!g) return "Unknown";
    for (i = 0; i < sizeof(kKnownGuids) / sizeof(kKnownGuids[0]); i++) {
        if (guid_equal(g, &kKnownGuids[i].guid)) {
            return kKnownGuids[i].name;
        }
    }
    return NULL;
}

VOID guid_to_str(const EFI_GUID *g, CHAR8 *out, UINTN max_len) {
    if (!g || !out || max_len == 0) return;
    snprintf_ascii(out, max_len, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g->Data1, g->Data2, g->Data3,
        g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
        g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

static BOOLEAN read_hex_exact(const CHAR8 **ps, UINTN digits, UINT32 *out) {
    UINT32 v = 0;
    for (UINTN i = 0; i < digits; i++) {
        INT32 d = hex_digit(**ps);
        if (d < 0) return FALSE;
        v = (v << 4) | (UINT32)d;
        (*ps)++;
    }
    *out = v;
    return TRUE;
}

BOOLEAN parse_guid_str(const CHAR8 *s, EFI_GUID *out) {
    UINT32 v = 0;
    if (!s || !out) return FALSE;
    while (*s == ' ') s++;
    if (!read_hex_exact(&s, 8, &out->Data1) || *s++ != '-') return FALSE;
    if (!read_hex_exact(&s, 4, &v) || *s++ != '-') return FALSE;
    out->Data2 = (UINT16)v;
    if (!read_hex_exact(&s, 4, &v) || *s++ != '-') return FALSE;
    out->Data3 = (UINT16)v;
    if (!read_hex_exact(&s, 2, &v)) return FALSE;
    out->Data4[0] = (UINT8)v;
    if (!read_hex_exact(&s, 2, &v) || *s++ != '-') return FALSE;
    out->Data4[1] = (UINT8)v;
    for (int i = 2; i < 8; i++) {
        if (!read_hex_exact(&s, 2, &v)) return FALSE;
        out->Data4[i] = (UINT8)v;
    }
    return TRUE;
}

const CHAR8 *efi_status_str(EFI_STATUS st) {
    switch (st) {
        case EFI_SUCCESS:            return "EFI_SUCCESS";
        case EFI_LOAD_ERROR:         return "EFI_LOAD_ERROR";
        case EFI_INVALID_PARAMETER:  return "EFI_INVALID_PARAMETER";
        case EFI_UNSUPPORTED:        return "EFI_UNSUPPORTED";
        case EFI_BAD_BUFFER_SIZE:    return "EFI_BAD_BUFFER_SIZE";
        case EFI_BUFFER_TOO_SMALL:   return "EFI_BUFFER_TOO_SMALL";
        case EFI_NOT_READY:          return "EFI_NOT_READY";
        case EFI_DEVICE_ERROR:       return "EFI_DEVICE_ERROR";
        case EFI_WRITE_PROTECTED:    return "EFI_WRITE_PROTECTED";
        case EFI_OUT_OF_RESOURCES:   return "EFI_OUT_OF_RESOURCES";
        case EFI_NOT_FOUND:          return "EFI_NOT_FOUND";
        case EFI_ACCESS_DENIED:      return "EFI_ACCESS_DENIED";
        case EFI_SECURITY_VIOLATION: return "EFI_SECURITY_VIOLATION";
        default:                     return "EFI_ERROR";
    }
}

const CHAR8 *efi_mem_type_short(UINT32 type) {
    switch (type) {
        case EfiReservedMemoryType:      return "Reserved";
        case EfiLoaderCode:              return "LdrCode ";
        case EfiLoaderData:              return "LdrData ";
        case EfiBootServicesCode:        return "BS_Code ";
        case EfiBootServicesData:        return "BS_Data ";
        case EfiRuntimeServicesCode:     return "RT_Code ";
        case EfiRuntimeServicesData:     return "RT_Data ";
        case EfiConventionalMemory:      return "Convent.";
        case EfiUnusableMemory:          return "Unusable";
        case EfiACPIReclaimMemory:       return "ACPI_Rec";
        case EfiACPIMemoryNVS:           return "ACPI_NVS";
        case EfiMemoryMappedIO:          return "MMIO    ";
        case EfiMemoryMappedIOPortSpace: return "MMIO_Prt";
        case EfiPalCode:                 return "PAL_Code";
        case EfiPersistentMemory:        return "Persist.";
        default:                         return "OEM/Unk ";
    }
}

const CHAR8 *efi_mem_type_full(UINT32 type) {
    switch (type) {
        case EfiReservedMemoryType:      return "EfiReservedMemoryType";
        case EfiLoaderCode:              return "EfiLoaderCode";
        case EfiLoaderData:              return "EfiLoaderData";
        case EfiBootServicesCode:        return "EfiBootServicesCode";
        case EfiBootServicesData:        return "EfiBootServicesData";
        case EfiRuntimeServicesCode:     return "EfiRuntimeServicesCode";
        case EfiRuntimeServicesData:     return "EfiRuntimeServicesData";
        case EfiConventionalMemory:      return "EfiConventionalMemory";
        case EfiUnusableMemory:          return "EfiUnusableMemory";
        case EfiACPIReclaimMemory:       return "EfiACPIReclaimMemory";
        case EfiACPIMemoryNVS:           return "EfiACPIMemoryNVS";
        case EfiMemoryMappedIO:          return "EfiMemoryMappedIO";
        case EfiMemoryMappedIOPortSpace: return "EfiMemoryMappedIOPortSpace";
        case EfiPalCode:                 return "EfiPalCode";
        case EfiPersistentMemory:        return "EfiPersistentMemory";
        default:                         return "OEM / Custom Memory Type";
    }
}

EFI_STATUS efi_locate_handles(EFI_GUID *protocol, UINTN *count_out, EFI_HANDLE **handles_out) {
    if (!gBS || !count_out || !handles_out) return EFI_INVALID_PARAMETER;
    *count_out = 0;
    *handles_out = NULL;

    if (gBS->LocateHandleBuffer) {
        return gBS->LocateHandleBuffer(
            protocol ? ByProtocol : AllHandles,
            protocol, NULL, count_out, handles_out);
    }

    /* Fallback for strict EFI 1.02 / early 1.10 */
    UINTN buf_sz = 0;
    EFI_STATUS st = gBS->LocateHandle(
        protocol ? ByProtocol : AllHandles, protocol, NULL, &buf_sz, NULL);
    if (st != EFI_BUFFER_TOO_SMALL || buf_sz == 0) return st;

    EFI_HANDLE *buf = (EFI_HANDLE *)alloc_pool(buf_sz);
    if (!buf) return EFI_OUT_OF_RESOURCES;
    st = gBS->LocateHandle(
        protocol ? ByProtocol : AllHandles, protocol, NULL, &buf_sz, buf);
    if (EFI_ERROR(st)) {
        free_pool(buf);
        return st;
    }
    *count_out = buf_sz / sizeof(EFI_HANDLE);
    *handles_out = buf;
    return EFI_SUCCESS;
}

EFI_STATUS efi_locate_protocol(EFI_GUID *protocol, VOID **interface) {
    if (!gBS || !protocol || !interface) return EFI_INVALID_PARAMETER;
    *interface = NULL;

    if (gBS->LocateProtocol) {
        return gBS->LocateProtocol(protocol, NULL, interface);
    }

    UINTN count = 0;
    EFI_HANDLE *handles = NULL;
    EFI_STATUS st = efi_locate_handles(protocol, &count, &handles);
    if (EFI_ERROR(st) || count == 0) return EFI_NOT_FOUND;

    st = gBS->HandleProtocol(handles[0], protocol, interface);
    free_pool(handles);
    return st;
}

/* x86 / x86_64 CPUID */
VOID cpu_cpuid(UINT32 leaf, UINT32 subleaf, UINT32 *eax, UINT32 *ebx, UINT32 *ecx, UINT32 *edx) {
    UINT32 a = 0, b = 0, c = 0, d = 0;
    __asm__ __volatile__(
        "cpuid"
        : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
        : "a"(leaf), "c"(subleaf)
    );
    if (eax) *eax = a;
    if (ebx) *ebx = b;
    if (ecx) *ecx = c;
    if (edx) *edx = d;
}

VOID io_out8(UINT16 port, UINT8 val) {
    __asm__ __volatile__("outb %b0, %w1" : : "a"(val), "Nd"(port));
}

UINT8 io_in8(UINT16 port) {
    UINT8 val = 0;
    __asm__ __volatile__("inb %w1, %b0" : "=a"(val) : "Nd"(port));
    return val;
}

VOID io_out16(UINT16 port, UINT16 val) {
    __asm__ __volatile__("outw %w0, %w1" : : "a"(val), "Nd"(port));
}

UINT16 io_in16(UINT16 port) {
    UINT16 val = 0;
    __asm__ __volatile__("inw %w1, %w0" : "=a"(val) : "Nd"(port));
    return val;
}

VOID io_out32(UINT16 port, UINT32 val) {
    __asm__ __volatile__("outl %0, %w1" : : "a"(val), "Nd"(port));
}

UINT32 io_in32(UINT16 port) {
    UINT32 val = 0;
    __asm__ __volatile__("inl %w1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

/* #GP-Guarded Ring-0 MSR Read / Write (x86_64) */
#if defined(__x86_64__) || defined(_M_X64)
typedef struct {
    UINT16 offset_low;
    UINT16 selector;
    UINT8  ist;
    UINT8  type_attr;
    UINT16 offset_mid;
    UINT32 offset_high;
    UINT32 reserved;
} PACKED X64_IDT_GATE;

typedef struct {
    UINT16 limit;
    UINT64 base;
} PACKED X64_IDTR;

extern void msr_gp_fault_isr(void);
__asm__(
    ".text\n"
    ".globl msr_gp_fault_isr\n"
    "msr_gp_fault_isr:\n"
    "  movl $1, %r9d\n"
    "  addq $2, 8(%rsp)\n"
    "  addq $8, %rsp\n"
    "  iretq\n"
);

static X64_IDT_GATE g_msr_temp_idt[32] __attribute__((aligned(16)));

static VOID msr_prepare_temp_idt(X64_IDTR *out_orig, X64_IDTR *out_tmp) {
    UINT16 cs_sel = 0;
    __asm__ __volatile__("sidt %0" : "=m"(*out_orig));
    __asm__ __volatile__("mov %%cs, %0" : "=r"(cs_sel));

    memset(g_msr_temp_idt, 0, sizeof(g_msr_temp_idt));
    if (out_orig->base != 0 && out_orig->limit >= 15) {
        UINTN copy_len = (UINTN)out_orig->limit + 1;
        if (copy_len > sizeof(g_msr_temp_idt)) copy_len = sizeof(g_msr_temp_idt);
        safe_read_mem(out_orig->base, g_msr_temp_idt, copy_len);
    }

    UINT64 isr = (UINT64)(UINTN)&msr_gp_fault_isr;
    g_msr_temp_idt[13].offset_low  = (UINT16)(isr & 0xFFFFULL);
    g_msr_temp_idt[13].selector    = cs_sel;
    g_msr_temp_idt[13].ist         = 0;
    g_msr_temp_idt[13].type_attr   = 0x8E; /* Present, Ring-0 64-bit Interrupt Gate */
    g_msr_temp_idt[13].offset_mid  = (UINT16)((isr >> 16) & 0xFFFFULL);
    g_msr_temp_idt[13].offset_high = (UINT32)((isr >> 32) & 0xFFFFFFFFULL);
    g_msr_temp_idt[13].reserved    = 0;

    out_tmp->limit = (UINT16)(sizeof(g_msr_temp_idt) - 1);
    out_tmp->base  = (UINT64)(UINTN)&g_msr_temp_idt[0];
}

BOOLEAN cpu_safe_rdmsr(UINT32 msr, UINT64 *out_val) {
    if (!out_val) return FALSE;
    UINT64 rflags = 0;
    X64_IDTR orig_idtr, tmp_idtr;

    __asm__ __volatile__(
        "pushfq\n\t"
        "popq %0\n\t"
        "cli\n\t"
        : "=r"(rflags)
        :
        : "memory"
    );

    msr_prepare_temp_idt(&orig_idtr, &tmp_idtr);
    __asm__ __volatile__("lidt %0" : : "m"(tmp_idtr) : "memory");

    UINT32 lo = 0, hi = 0, faulted = 0;
    __asm__ __volatile__(
        "xorl %%eax, %%eax\n\t"
        "xorl %%edx, %%edx\n\t"
        "xorl %%r9d, %%r9d\n\t"
        ".byte 0x0f, 0x32\n\t"
        "movl %%r9d, %2\n\t"
        : "=&a"(lo), "=&d"(hi), "=r"(faulted)
        : "c"(msr)
        : "r9", "cc", "memory"
    );

    __asm__ __volatile__("lidt %0" : : "m"(orig_idtr) : "memory");
    __asm__ __volatile__(
        "pushq %0\n\t"
        "popfq\n\t"
        :
        : "r"(rflags)
        : "cc", "memory"
    );

    if (faulted != 0) {
        *out_val = 0;
        return FALSE;
    }
    *out_val = ((UINT64)hi << 32) | (UINT64)lo;
    return TRUE;
}

BOOLEAN cpu_safe_wrmsr(UINT32 msr, UINT64 val) {
    UINT64 rflags = 0;
    X64_IDTR orig_idtr, tmp_idtr;

    __asm__ __volatile__(
        "pushfq\n\t"
        "popq %0\n\t"
        "cli\n\t"
        : "=r"(rflags)
        :
        : "memory"
    );

    msr_prepare_temp_idt(&orig_idtr, &tmp_idtr);
    __asm__ __volatile__("lidt %0" : : "m"(tmp_idtr) : "memory");

    UINT32 lo = (UINT32)(val & 0xFFFFFFFFULL);
    UINT32 hi = (UINT32)(val >> 32);
    UINT32 faulted = 0;
    __asm__ __volatile__(
        "xorl %%r9d, %%r9d\n\t"
        ".byte 0x0f, 0x30\n\t"
        "movl %%r9d, %0\n\t"
        : "=r"(faulted)
        : "c"(msr), "a"(lo), "d"(hi)
        : "r9", "cc", "memory"
    );

    __asm__ __volatile__("lidt %0" : : "m"(orig_idtr) : "memory");
    __asm__ __volatile__(
        "pushq %0\n\t"
        "popfq\n\t"
        :
        : "r"(rflags)
        : "cc", "memory"
    );

    return (faulted == 0);
}
#else
BOOLEAN cpu_safe_rdmsr(UINT32 msr, UINT64 *out_val) {
    (VOID)msr;
    if (out_val) *out_val = 0;
    return FALSE;
}

BOOLEAN cpu_safe_wrmsr(UINT32 msr, UINT64 val) {
    (VOID)msr;
    (VOID)val;
    return FALSE;
}
#endif

/* Ring-0 Page Table Prober with 4KB VPN cache */
static BOOLEAN g_probe_cache_valid = FALSE;
static UINT64  g_probe_cache_vpn = 0;
static BOOLEAN g_probe_cache_mapped = FALSE;
static BOOLEAN g_probe_cache_writable = FALSE;

VOID cpu_invalidate_probe_cache(VOID) {
    g_probe_cache_valid = FALSE;
}

BOOLEAN cpu_probe_address(UINT64 phys_addr, BOOLEAN *out_mapped, BOOLEAN *out_writable) {
    UINT64 vpn = phys_addr >> 12;
    if (g_probe_cache_valid && g_probe_cache_vpn == vpn) {
        if (out_mapped) *out_mapped = g_probe_cache_mapped;
        if (out_writable) *out_writable = g_probe_cache_writable;
        return g_probe_cache_mapped;
    }

    BOOLEAN mapped = FALSE;
    BOOLEAN writable = FALSE;

    /* Avoid dereferencing page 0 (NULL guard page in UEFI) */
    if (phys_addr < 0x1000ULL) {
        if (out_mapped) *out_mapped = FALSE;
        if (out_writable) *out_writable = FALSE;
        return FALSE;
    }

#if defined(__x86_64__) || defined(_M_X64)
    UINT64 cr0 = 0, cr3 = 0, cr4 = 0;
    __asm__ __volatile__("mov %%cr0, %0" : "=r"(cr0));
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(cr3));
    __asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4));

    if ((cr0 & 0x80000000ULL) == 0) {
        mapped = TRUE;
        writable = TRUE;
    } else {
        const UINT64 phys_mask = 0x000FFFFFFFFFF000ULL;
        BOOLEAN cr0_wp = ((cr0 & (1ULL << 16)) != 0);
        BOOLEAN rw_chain = TRUE;
        UINT64 table_base = cr3 & phys_mask;
        BOOLEAN ok = (table_base != 0);

        /* 5-level paging (LA57) check */
        if (ok && (cr4 & (1ULL << 12)) != 0) {
            const volatile UINT64 *pml5 = (const volatile UINT64 *)(UINTN)table_base;
            UINT64 e5 = pml5[(phys_addr >> 48) & 0x1FFULL];
            if ((e5 & 1ULL) == 0) ok = FALSE;
            else {
                if ((e5 & 2ULL) == 0) rw_chain = FALSE;
                table_base = e5 & phys_mask;
            }
        }

        if (ok && table_base != 0) {
            const volatile UINT64 *pml4 = (const volatile UINT64 *)(UINTN)table_base;
            UINT64 e4 = pml4[(phys_addr >> 39) & 0x1FFULL];
            if ((e4 & 1ULL) != 0) {
                if ((e4 & 2ULL) == 0) rw_chain = FALSE;
                UINT64 pdpt_base = e4 & phys_mask;
                if (pdpt_base != 0) {
                    const volatile UINT64 *pdpt = (const volatile UINT64 *)(UINTN)pdpt_base;
                    UINT64 e3 = pdpt[(phys_addr >> 30) & 0x1FFULL];
                    if ((e3 & 1ULL) != 0) {
                        if ((e3 & 2ULL) == 0) rw_chain = FALSE;
                        if ((e3 & 0x80ULL) != 0) {
                            /* 1GB huge page */
                            mapped = TRUE;
                            writable = cr0_wp ? rw_chain : TRUE;
                        } else {
                            UINT64 pd_base = e3 & phys_mask;
                            if (pd_base != 0) {
                                const volatile UINT64 *pd = (const volatile UINT64 *)(UINTN)pd_base;
                                UINT64 e2 = pd[(phys_addr >> 21) & 0x1FFULL];
                                if ((e2 & 1ULL) != 0) {
                                    if ((e2 & 2ULL) == 0) rw_chain = FALSE;
                                    if ((e2 & 0x80ULL) != 0) {
                                        /* 2MB large page */
                                        mapped = TRUE;
                                        writable = cr0_wp ? rw_chain : TRUE;
                                    } else {
                                        UINT64 pt_base = e2 & phys_mask;
                                        if (pt_base != 0) {
                                            const volatile UINT64 *pt = (const volatile UINT64 *)(UINTN)pt_base;
                                            UINT64 e1 = pt[(phys_addr >> 12) & 0x1FFULL];
                                            if ((e1 & 1ULL) != 0) {
                                                if ((e1 & 2ULL) == 0) rw_chain = FALSE;
                                                mapped = TRUE;
                                                writable = cr0_wp ? rw_chain : TRUE;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
#else
    /* 32-bit IA32 EFI */
    if (phys_addr <= 0xFFFFFFFFULL) {
        UINT32 cr0 = 0, cr3 = 0, cr4 = 0;
        __asm__ __volatile__("mov %%cr0, %0" : "=r"(cr0));
        __asm__ __volatile__("mov %%cr3, %0" : "=r"(cr3));
        __asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4));
        if ((cr0 & 0x80000000U) == 0) {
            mapped = TRUE;
            writable = TRUE;
        } else {
            BOOLEAN cr0_wp = ((cr0 & (1U << 16)) != 0);
            if ((cr4 & (1U << 5)) != 0) {
                /* PAE 32-bit */
                const volatile UINT64 *pdpt = (const volatile UINT64 *)(UINTN)(cr3 & 0xFFFFFFE0U);
                UINT64 e3 = pdpt[(phys_addr >> 30) & 3ULL];
                if ((e3 & 1ULL) != 0 && (e3 & 0xFFFFF000ULL) <= 0xFFFFF000ULL) {
                    const volatile UINT64 *pd = (const volatile UINT64 *)(UINTN)(e3 & 0xFFFFF000ULL);
                    UINT64 e2 = pd[(phys_addr >> 21) & 0x1FFULL];
                    if ((e2 & 1ULL) != 0) {
                        BOOLEAN rw = ((e2 & 2ULL) != 0);
                        if ((e2 & 0x80ULL) != 0) {
                            mapped = TRUE;
                            writable = cr0_wp ? rw : TRUE;
                        } else if ((e2 & 0xFFFFF000ULL) <= 0xFFFFF000ULL) {
                            const volatile UINT64 *pt = (const volatile UINT64 *)(UINTN)(e2 & 0xFFFFF000ULL);
                            UINT64 e1 = pt[(phys_addr >> 12) & 0x1FFULL];
                            if ((e1 & 1ULL) != 0) {
                                rw = rw && ((e1 & 2ULL) != 0);
                                mapped = TRUE;
                                writable = cr0_wp ? rw : TRUE;
                            }
                        }
                    }
                }
            } else {
                /* 2-level 32-bit */
                const volatile UINT32 *pd = (const volatile UINT32 *)(UINTN)(cr3 & 0xFFFFF000U);
                UINT32 e2 = pd[(phys_addr >> 22) & 0x3FFU];
                if ((e2 & 1U) != 0) {
                    BOOLEAN rw = ((e2 & 2U) != 0);
                    if ((e2 & 0x80U) != 0) {
                        mapped = TRUE;
                        writable = cr0_wp ? rw : TRUE;
                    } else {
                        const volatile UINT32 *pt = (const volatile UINT32 *)(UINTN)(e2 & 0xFFFFF000U);
                        UINT32 e1 = pt[(phys_addr >> 12) & 0x3FFU];
                        if ((e1 & 1U) != 0) {
                            rw = rw && ((e1 & 2U) != 0);
                            mapped = TRUE;
                            writable = cr0_wp ? rw : TRUE;
                        }
                    }
                }
            }
        }
    }
#endif

    g_probe_cache_valid = TRUE;
    g_probe_cache_vpn = vpn;
    g_probe_cache_mapped = mapped;
    g_probe_cache_writable = writable;

    if (out_mapped) *out_mapped = mapped;
    if (out_writable) *out_writable = writable;
    return mapped;
}

BOOLEAN safe_read_mem(UINT64 phys_addr, VOID *dst, UINTN len) {
    UINT8 *out = (UINT8 *)dst;
    if (!out) return FALSE;
    for (UINTN i = 0; i < len; i++) {
        UINT64 cur = phys_addr + i;
        BOOLEAN mapped = FALSE;
        if (!cpu_probe_address(cur, &mapped, NULL) || !mapped) {
            return FALSE;
        }
        out[i] = *(const volatile UINT8 *)(UINTN)cur;
    }
    return TRUE;
}

BOOLEAN safe_write_byte(UINT64 phys_addr, UINT8 val, BOOLEAN *out_verified) {
    BOOLEAN mapped = FALSE, writable = FALSE;
    if (out_verified) *out_verified = FALSE;
    if (!cpu_probe_address(phys_addr, &mapped, &writable) || !mapped || !writable) {
        return FALSE;
    }
    volatile UINT8 *ptr = (volatile UINT8 *)(UINTN)phys_addr;
    *ptr = val;
    UINT8 readback = *ptr;
    if (out_verified) {
        *out_verified = (readback == val);
    }
    return TRUE;
}

BOOLEAN wait_key_timeout_ms(EFI_INPUT_KEY *out_key, UINTN timeout_ms) {
    if (!gST || !gST->ConIn || !out_key) return FALSE;

    if (gST->ConIn->ReadKeyStroke(gST->ConIn, out_key) == EFI_SUCCESS) {
        return TRUE;
    }
    if (timeout_ms == 0) return FALSE;

    if (gBS && gBS->CreateEvent && gBS->SetTimer && gBS->WaitForEvent && gBS->CloseEvent &&
        gST->ConIn->WaitForKey != NULL) {
        EFI_EVENT timer_ev = NULL;
        EFI_STATUS st = gBS->CreateEvent(EVT_TIMER, TPL_APPLICATION, NULL, NULL, &timer_ev);
        if (!EFI_ERROR(st) && timer_ev != NULL) {
            /* 10,000 * 100ns = 1ms */
            st = gBS->SetTimer(timer_ev, TimerRelative, (UINT64)timeout_ms * 10000ULL);
            if (!EFI_ERROR(st)) {
                EFI_EVENT evs[2];
                UINTN idx = 0;
                evs[0] = gST->ConIn->WaitForKey;
                evs[1] = timer_ev;
                st = gBS->WaitForEvent(2, evs, &idx);
                gBS->CloseEvent(timer_ev);
                if (!EFI_ERROR(st) && idx == 0) {
                    if (gST->ConIn->ReadKeyStroke(gST->ConIn, out_key) == EFI_SUCCESS) {
                        return TRUE;
                    }
                }
                return FALSE;
            }
            gBS->CloseEvent(timer_ev);
        }
    }

    /* Fallback polling loop with Stall */
    UINTN loops = (timeout_ms + 9) / 10;
    for (UINTN i = 0; i < loops; i++) {
        if (gST->ConIn->ReadKeyStroke(gST->ConIn, out_key) == EFI_SUCCESS) {
            return TRUE;
        }
        if (gBS && gBS->Stall) {
            gBS->Stall(10000);
        }
    }
    return FALSE;
}

VOID wait_key_blocking(EFI_INPUT_KEY *out_key) {
    while (!wait_key_timeout_ms(out_key, 1000)) {
        /* Wait indefinitely for keyboard input */
    }
}

VOID drain_keys(VOID) {
    EFI_INPUT_KEY k;
    if (!gST || !gST->ConIn) return;
    while (gST->ConIn->ReadKeyStroke(gST->ConIn, &k) == EFI_SUCCESS) {
        /* discard */
    }
}
