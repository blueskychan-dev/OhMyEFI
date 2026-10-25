#ifndef EFI_SETUP_EFI_H
#define EFI_SETUP_EFI_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

/* Basic UEFI Data Types */
typedef uint8_t   BOOLEAN;
typedef int8_t    INT8;
typedef uint8_t   UINT8;
typedef int16_t   INT16;
typedef uint16_t  UINT16;
typedef int32_t   INT32;
typedef uint32_t  UINT32;
typedef int64_t   INT64;
typedef uint64_t  UINT64;
typedef uint16_t  CHAR16;
typedef char      CHAR8;
typedef void      VOID;

#if defined(__x86_64__) || defined(_M_X64)
typedef uint64_t  UINTN;
typedef int64_t   INTN;
#define EFI_ARCH_NAME L"X64 (64-bit)"
#define EFI_ERROR_BIT 0x8000000000000000ULL
#else
typedef uint32_t  UINTN;
typedef int32_t   INTN;
#define EFI_ARCH_NAME L"IA32 (32-bit)"
#define EFI_ERROR_BIT 0x80000000UL
#endif

#if defined(__GNUC__) || defined(__clang__)
  #if defined(__x86_64__)
    #define EFIAPI __attribute__((ms_abi))
  #else
    #define EFIAPI __attribute__((cdecl))
  #endif
  #define PACKED __attribute__((packed))
#else
  #define EFIAPI
  #define PACKED
#endif

#ifndef TRUE
#define TRUE  ((BOOLEAN)1)
#define FALSE ((BOOLEAN)0)
#endif

typedef UINTN  EFI_STATUS;
typedef VOID*  EFI_HANDLE;
typedef VOID*  EFI_EVENT;
typedef UINT64 EFI_PHYSICAL_ADDRESS;
typedef UINT64 EFI_VIRTUAL_ADDRESS;
typedef UINTN  EFI_TPL;

#define EFI_ERROR(s) (((s) & EFI_ERROR_BIT) != 0)
#define EFIERR(a)    (EFI_ERROR_BIT | (UINTN)(a))

#define EFI_SUCCESS               ((EFI_STATUS)0)
#define EFI_LOAD_ERROR            EFIERR(1)
#define EFI_INVALID_PARAMETER     EFIERR(2)
#define EFI_UNSUPPORTED           EFIERR(3)
#define EFI_BAD_BUFFER_SIZE       EFIERR(4)
#define EFI_BUFFER_TOO_SMALL      EFIERR(5)
#define EFI_NOT_READY             EFIERR(6)
#define EFI_DEVICE_ERROR          EFIERR(7)
#define EFI_WRITE_PROTECTED       EFIERR(8)
#define EFI_OUT_OF_RESOURCES      EFIERR(9)
#define EFI_VOLUME_CORRUPTED      EFIERR(10)
#define EFI_VOLUME_FULL           EFIERR(11)
#define EFI_NO_MEDIA              EFIERR(12)
#define EFI_MEDIA_CHANGED         EFIERR(13)
#define EFI_NOT_FOUND             EFIERR(14)
#define EFI_ACCESS_DENIED         EFIERR(15)
#define EFI_TIMEOUT               EFIERR(18)
#define EFI_ABORTED               EFIERR(21)
#define EFI_SECURITY_VIOLATION    EFIERR(26)

typedef struct {
    UINT32 Data1;
    UINT16 Data2;
    UINT16 Data3;
    UINT8  Data4[8];
} EFI_GUID;

typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
} EFI_TABLE_HEADER;

/* Console Text Attributes (Standard VGA / UEFI ConOut) */
#define EFI_BLACK                 0x00
#define EFI_BLUE                  0x01
#define EFI_GREEN                 0x02
#define EFI_CYAN                  0x03
#define EFI_RED                   0x04
#define EFI_MAGENTA               0x05
#define EFI_BROWN                 0x06
#define EFI_LIGHTGRAY             0x07
#define EFI_DARKGRAY              0x08
#define EFI_LIGHTBLUE             0x09
#define EFI_LIGHTGREEN            0x0A
#define EFI_LIGHTCYAN             0x0B
#define EFI_LIGHTRED              0x0C
#define EFI_LIGHTMAGENTA          0x0D
#define EFI_YELLOW                0x0E
#define EFI_WHITE                 0x0F

#define EFI_BACKGROUND_BLACK      0x00
#define EFI_BACKGROUND_BLUE       0x10
#define EFI_BACKGROUND_GREEN      0x20
#define EFI_BACKGROUND_CYAN       0x30
#define EFI_BACKGROUND_RED        0x40
#define EFI_BACKGROUND_MAGENTA    0x50
#define EFI_BACKGROUND_BROWN      0x60
#define EFI_BACKGROUND_LIGHTGRAY  0x70

#define EFI_TEXT_ATTR(fg, bg)     ((UINT8)((fg) | (bg)))

/* Scan Codes for EFI_SIMPLE_TEXT_INPUT_PROTOCOL */
#define SCAN_NULL       0x0000
#define SCAN_UP         0x0001
#define SCAN_DOWN       0x0002
#define SCAN_RIGHT      0x0003
#define SCAN_LEFT       0x0004
#define SCAN_HOME       0x0005
#define SCAN_END        0x0006
#define SCAN_INSERT     0x0007
#define SCAN_DELETE     0x0008
#define SCAN_PAGE_UP    0x0009
#define SCAN_PAGE_DOWN  0x000A
#define SCAN_F1         0x000B
#define SCAN_F2         0x000C
#define SCAN_F3         0x000D
#define SCAN_F4         0x000E
#define SCAN_F5         0x000F
#define SCAN_F6         0x0010
#define SCAN_F7         0x0011
#define SCAN_F8         0x0012
#define SCAN_F9         0x0013
#define SCAN_F10        0x0014
#define SCAN_F11        0x0015
#define SCAN_F12        0x0016
#define SCAN_ESC        0x0017

typedef struct {
    UINT16 ScanCode;
    CHAR16 UnicodeChar;
} EFI_INPUT_KEY;

struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_INPUT_RESET)(
    struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
    BOOLEAN ExtendedVerification
);
typedef EFI_STATUS (EFIAPI *EFI_INPUT_READ_KEY)(
    struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
    EFI_INPUT_KEY *Key
);

typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    EFI_INPUT_RESET    Reset;
    EFI_INPUT_READ_KEY ReadKeyStroke;
    EFI_EVENT          WaitForKey;
} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;

typedef struct {
    INT32   MaxMode;
    INT32   Mode;
    INT32   Attribute;
    INT32   CursorColumn;
    INT32   CursorRow;
    BOOLEAN CursorVisible;
} SIMPLE_TEXT_OUTPUT_MODE;

struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_TEXT_RESET)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    BOOLEAN ExtendedVerification
);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_STRING)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    CHAR16 *String
);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_TEST_STRING)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    CHAR16 *String
);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_QUERY_MODE)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    UINTN ModeNumber,
    UINTN *Columns,
    UINTN *Rows
);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_SET_MODE)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    UINTN ModeNumber
);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_SET_ATTRIBUTE)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    UINTN Attribute
);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_CLEAR_SCREEN)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This
);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_SET_CURSOR_POSITION)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    UINTN Column,
    UINTN Row
);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_ENABLE_CURSOR)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    BOOLEAN Visible
);

typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    EFI_TEXT_RESET               Reset;
    EFI_TEXT_STRING              OutputString;
    EFI_TEXT_TEST_STRING         TestString;
    EFI_TEXT_QUERY_MODE          QueryMode;
    EFI_TEXT_SET_MODE            SetMode;
    EFI_TEXT_SET_ATTRIBUTE       SetAttribute;
    EFI_TEXT_CLEAR_SCREEN        ClearScreen;
    EFI_TEXT_SET_CURSOR_POSITION SetCursorPosition;
    EFI_TEXT_ENABLE_CURSOR       EnableCursor;
    SIMPLE_TEXT_OUTPUT_MODE      *Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

/* Apple / Tiano Console Control Protocol (Needed on Intel iMac / MacBook) */
typedef enum {
    EfiConsoleControlScreenText = 0,
    EfiConsoleControlScreenGraphics = 1,
    EfiConsoleControlScreenMaxValue = 2
} EFI_CONSOLE_CONTROL_SCREEN_MODE;

struct _EFI_CONSOLE_CONTROL_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_CONSOLE_CONTROL_GET_MODE)(
    struct _EFI_CONSOLE_CONTROL_PROTOCOL *This,
    EFI_CONSOLE_CONTROL_SCREEN_MODE *Mode,
    BOOLEAN *GopUgaExists,
    BOOLEAN *StdInLocked
);
typedef EFI_STATUS (EFIAPI *EFI_CONSOLE_CONTROL_SET_MODE)(
    struct _EFI_CONSOLE_CONTROL_PROTOCOL *This,
    EFI_CONSOLE_CONTROL_SCREEN_MODE Mode
);
typedef EFI_STATUS (EFIAPI *EFI_CONSOLE_CONTROL_LOCK_STD_IN)(
    struct _EFI_CONSOLE_CONTROL_PROTOCOL *This,
    CHAR16 *Password
);

typedef struct _EFI_CONSOLE_CONTROL_PROTOCOL {
    EFI_CONSOLE_CONTROL_GET_MODE    GetMode;
    EFI_CONSOLE_CONTROL_SET_MODE    SetMode;
    EFI_CONSOLE_CONTROL_LOCK_STD_IN LockStdIn;
} EFI_CONSOLE_CONTROL_PROTOCOL;

/* Memory Types & Descriptors */
typedef enum {
    EfiReservedMemoryType = 0,
    EfiLoaderCode = 1,
    EfiLoaderData = 2,
    EfiBootServicesCode = 3,
    EfiBootServicesData = 4,
    EfiRuntimeServicesCode = 5,
    EfiRuntimeServicesData = 6,
    EfiConventionalMemory = 7,
    EfiUnusableMemory = 8,
    EfiACPIReclaimMemory = 9,
    EfiACPIMemoryNVS = 10,
    EfiMemoryMappedIO = 11,
    EfiMemoryMappedIOPortSpace = 12,
    EfiPalCode = 13,
    EfiPersistentMemory = 14,
    EfiMaxMemoryType = 15
} EFI_MEMORY_TYPE;

typedef enum {
    AllocateAnyPages = 0,
    AllocateMaxAddress = 1,
    AllocateAddress = 2,
    MaxAllocateType = 3
} EFI_ALLOCATE_TYPE;

#define EFI_MEMORY_UC   0x0000000000000001ULL
#define EFI_MEMORY_WC   0x0000000000000002ULL
#define EFI_MEMORY_WT   0x0000000000000004ULL
#define EFI_MEMORY_WB   0x0000000000000008ULL
#define EFI_MEMORY_UCE  0x0000000000000010ULL
#define EFI_MEMORY_WP   0x0000000000001000ULL
#define EFI_MEMORY_RP   0x0000000000002000ULL
#define EFI_MEMORY_XP   0x0000000000004000ULL
#define EFI_MEMORY_NV   0x0000000000008000ULL
#define EFI_MEMORY_MORE_RELIABLE 0x0000000000010000ULL
#define EFI_MEMORY_RO   0x0000000000020000ULL
#define EFI_MEMORY_RT   0x8000000000000000ULL

typedef struct {
    UINT32               Type;
    EFI_PHYSICAL_ADDRESS PhysicalStart;
    EFI_VIRTUAL_ADDRESS  VirtualStart;
    UINT64               NumberOfPages;
    UINT64               Attribute;
} EFI_MEMORY_DESCRIPTOR;

/* Time & Reset & Variable Attributes */
typedef struct {
    UINT16 Year;       /* 1900 - 9999 */
    UINT8  Month;      /* 1 - 12 */
    UINT8  Day;        /* 1 - 31 */
    UINT8  Hour;       /* 0 - 23 */
    UINT8  Minute;     /* 0 - 59 */
    UINT8  Second;     /* 0 - 59 */
    UINT8  Pad1;
    UINT32 Nanosecond;
    INT16  TimeZone;
    UINT8  Daylight;
    UINT8  Pad2;
} EFI_TIME;

typedef struct {
    UINT32  Resolution;
    UINT32  Accuracy;
    BOOLEAN SetsToZero;
} EFI_TIME_CAPABILITIES;

typedef enum {
    EfiResetCold = 0,
    EfiResetWarm = 1,
    EfiResetShutdown = 2,
    EfiResetPlatformSpecific = 3
} EFI_RESET_TYPE;

#define EFI_VARIABLE_NON_VOLATILE                          0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                    0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS                        0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                 0x00000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            0x00000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#define EFI_VARIABLE_APPEND_WRITE                          0x00000040

#define LOAD_OPTION_ACTIVE          0x00000001
#define LOAD_OPTION_FORCE_RECONNECT 0x00000002
#define LOAD_OPTION_HIDDEN          0x00000008

/* OS Indications */
#define EFI_OS_INDICATIONS_BOOT_TO_FW_UI 0x0000000000000001ULL

/* Runtime Services */
typedef EFI_STATUS (EFIAPI *EFI_GET_TIME)(EFI_TIME *Time, EFI_TIME_CAPABILITIES *Capabilities);
typedef EFI_STATUS (EFIAPI *EFI_SET_TIME)(EFI_TIME *Time);
typedef EFI_STATUS (EFIAPI *EFI_GET_WAKEUP_TIME)(BOOLEAN *Enabled, BOOLEAN *Pending, EFI_TIME *Time);
typedef EFI_STATUS (EFIAPI *EFI_SET_WAKEUP_TIME)(BOOLEAN Enable, EFI_TIME *Time);
typedef EFI_STATUS (EFIAPI *EFI_SET_VIRTUAL_ADDRESS_MAP)(
    UINTN MemoryMapSize, UINTN DescriptorSize, UINT32 DescriptorVersion, EFI_MEMORY_DESCRIPTOR *VirtualMap);
typedef EFI_STATUS (EFIAPI *EFI_CONVERT_POINTER)(UINTN DebugDisposition, VOID **Address);
typedef EFI_STATUS (EFIAPI *EFI_GET_VARIABLE)(
    CHAR16 *VariableName, EFI_GUID *VendorGuid, UINT32 *Attributes, UINTN *DataSize, VOID *Data);
typedef EFI_STATUS (EFIAPI *EFI_GET_NEXT_VARIABLE_NAME)(
    UINTN *VariableNameSize, CHAR16 *VariableName, EFI_GUID *VendorGuid);
typedef EFI_STATUS (EFIAPI *EFI_SET_VARIABLE)(
    CHAR16 *VariableName, EFI_GUID *VendorGuid, UINT32 Attributes, UINTN DataSize, VOID *Data);
typedef EFI_STATUS (EFIAPI *EFI_GET_NEXT_HIGH_MONO_COUNT)(UINT32 *HighCount);
typedef VOID (EFIAPI *EFI_RESET_SYSTEM)(
    EFI_RESET_TYPE ResetType, EFI_STATUS ResetStatus, UINTN DataSize, VOID *ResetData);
typedef EFI_STATUS (EFIAPI *EFI_UPDATE_CAPSULE)(
    VOID **CapsuleHeaderArray, UINTN CapsuleCount, EFI_PHYSICAL_ADDRESS ScatterGatherList);
typedef EFI_STATUS (EFIAPI *EFI_QUERY_CAPSULE_CAPABILITIES)(
    VOID **CapsuleHeaderArray, UINTN CapsuleCount, UINT64 *MaximumCapsuleSize, EFI_RESET_TYPE *ResetType);
typedef EFI_STATUS (EFIAPI *EFI_QUERY_VARIABLE_INFO)(
    UINT32 Attributes, UINT64 *MaximumVariableStorageSize,
    UINT64 *RemainingVariableStorageSize, UINT64 *MaximumVariableSize);

typedef struct {
    EFI_TABLE_HEADER               Hdr;
    EFI_GET_TIME                   GetTime;
    EFI_SET_TIME                   SetTime;
    EFI_GET_WAKEUP_TIME            GetWakeupTime;
    EFI_SET_WAKEUP_TIME            SetWakeupTime;
    EFI_SET_VIRTUAL_ADDRESS_MAP    SetVirtualAddressMap;
    EFI_CONVERT_POINTER            ConvertPointer;
    EFI_GET_VARIABLE               GetVariable;
    EFI_GET_NEXT_VARIABLE_NAME     GetNextVariableName;
    EFI_SET_VARIABLE               SetVariable;
    EFI_GET_NEXT_HIGH_MONO_COUNT   GetNextHighMonotonicCount;
    EFI_RESET_SYSTEM               ResetSystem;
    EFI_UPDATE_CAPSULE             UpdateCapsule;
    EFI_QUERY_CAPSULE_CAPABILITIES QueryCapsuleCapabilities;
    EFI_QUERY_VARIABLE_INFO        QueryVariableInfo;
} EFI_RUNTIME_SERVICES;

/* Device Path Protocol */
typedef struct _EFI_DEVICE_PATH_PROTOCOL {
    UINT8 Type;
    UINT8 SubType;
    UINT8 Length[2];
} PACKED EFI_DEVICE_PATH_PROTOCOL;

/* Locate Search Types */
typedef enum {
    AllHandles = 0,
    ByRegisterNotify = 1,
    ByProtocol = 2
} EFI_LOCATE_SEARCH_TYPE;

typedef enum {
    TimerCancel = 0,
    TimerPeriodic = 1,
    TimerRelative = 2
} EFI_TIMER_DELAY;

#define EVT_TIMER 0x80000000
#define TPL_APPLICATION 4
#define TPL_CALLBACK    8

/* Boot Services Function Typedefs */
typedef EFI_TPL    (EFIAPI *EFI_RAISE_TPL)(EFI_TPL NewTpl);
typedef VOID       (EFIAPI *EFI_RESTORE_TPL)(EFI_TPL OldTpl);
typedef EFI_STATUS (EFIAPI *EFI_ALLOCATE_PAGES)(
    EFI_ALLOCATE_TYPE Type, EFI_MEMORY_TYPE MemoryType, UINTN Pages, EFI_PHYSICAL_ADDRESS *Memory);
typedef EFI_STATUS (EFIAPI *EFI_FREE_PAGES)(EFI_PHYSICAL_ADDRESS Memory, UINTN Pages);
typedef EFI_STATUS (EFIAPI *EFI_GET_MEMORY_MAP)(
    UINTN *MemoryMapSize, EFI_MEMORY_DESCRIPTOR *MemoryMap,
    UINTN *MapKey, UINTN *DescriptorSize, UINT32 *DescriptorVersion);
typedef EFI_STATUS (EFIAPI *EFI_ALLOCATE_POOL)(EFI_MEMORY_TYPE PoolType, UINTN Size, VOID **Buffer);
typedef EFI_STATUS (EFIAPI *EFI_FREE_POOL)(VOID *Buffer);
typedef EFI_STATUS (EFIAPI *EFI_CREATE_EVENT)(
    UINT32 Type, EFI_TPL NotifyTpl, VOID *NotifyFunction, VOID *NotifyContext, EFI_EVENT *Event);
typedef EFI_STATUS (EFIAPI *EFI_SET_TIMER)(EFI_EVENT Event, EFI_TIMER_DELAY Type, UINT64 TriggerTime);
typedef EFI_STATUS (EFIAPI *EFI_WAIT_FOR_EVENT)(UINTN NumberOfEvents, EFI_EVENT *Event, UINTN *Index);
typedef EFI_STATUS (EFIAPI *EFI_SIGNAL_EVENT)(EFI_EVENT Event);
typedef EFI_STATUS (EFIAPI *EFI_CLOSE_EVENT)(EFI_EVENT Event);
typedef EFI_STATUS (EFIAPI *EFI_CHECK_EVENT)(EFI_EVENT Event);
typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL)(EFI_HANDLE Handle, EFI_GUID *Protocol, VOID **Interface);
typedef EFI_STATUS (EFIAPI *EFI_LOCATE_HANDLE)(
    EFI_LOCATE_SEARCH_TYPE SearchType, EFI_GUID *Protocol, VOID *SearchKey,
    UINTN *BufferSize, EFI_HANDLE *Buffer);
typedef EFI_STATUS (EFIAPI *EFI_LOCATE_DEVICE_PATH)(
    EFI_GUID *Protocol, EFI_DEVICE_PATH_PROTOCOL **DevicePath, EFI_HANDLE *Device);
typedef EFI_STATUS (EFIAPI *EFI_INSTALL_CONFIGURATION_TABLE)(EFI_GUID *Guid, VOID *Table);
typedef EFI_STATUS (EFIAPI *EFI_IMAGE_LOAD)(
    BOOLEAN BootPolicy, EFI_HANDLE ParentImageHandle, EFI_DEVICE_PATH_PROTOCOL *DevicePath,
    VOID *SourceBuffer, UINTN SourceSize, EFI_HANDLE *ImageHandle);
typedef EFI_STATUS (EFIAPI *EFI_IMAGE_START)(
    EFI_HANDLE ImageHandle, UINTN *ExitDataSize, CHAR16 **ExitData);
typedef EFI_STATUS (EFIAPI *EFI_EXIT)(
    EFI_HANDLE ImageHandle, EFI_STATUS ExitStatus, UINTN ExitDataSize, CHAR16 *ExitData);
typedef EFI_STATUS (EFIAPI *EFI_IMAGE_UNLOAD)(EFI_HANDLE ImageHandle);
typedef EFI_STATUS (EFIAPI *EFI_EXIT_BOOT_SERVICES)(EFI_HANDLE ImageHandle, UINTN MapKey);
typedef EFI_STATUS (EFIAPI *EFI_STALL)(UINTN Microseconds);
typedef EFI_STATUS (EFIAPI *EFI_SET_WATCHDOG_TIMER)(
    UINTN Timeout, UINT64 WatchdogCode, UINTN DataSize, CHAR16 *WatchdogData);
typedef EFI_STATUS (EFIAPI *EFI_OPEN_PROTOCOL)(
    EFI_HANDLE Handle, EFI_GUID *Protocol, VOID **Interface,
    EFI_HANDLE AgentHandle, EFI_HANDLE ControllerHandle, UINT32 Attributes);
typedef EFI_STATUS (EFIAPI *EFI_CLOSE_PROTOCOL)(
    EFI_HANDLE Handle, EFI_GUID *Protocol, EFI_HANDLE AgentHandle, EFI_HANDLE ControllerHandle);
typedef EFI_STATUS (EFIAPI *EFI_PROTOCOLS_PER_HANDLE)(
    EFI_HANDLE Handle, EFI_GUID ***ProtocolBuffer, UINTN *ProtocolBufferCount);
typedef EFI_STATUS (EFIAPI *EFI_LOCATE_HANDLE_BUFFER)(
    EFI_LOCATE_SEARCH_TYPE SearchType, EFI_GUID *Protocol, VOID *SearchKey,
    UINTN *NoHandles, EFI_HANDLE **Buffer);
typedef EFI_STATUS (EFIAPI *EFI_LOCATE_PROTOCOL)(
    EFI_GUID *Protocol, VOID *Registration, VOID **Interface);
typedef EFI_STATUS (EFIAPI *EFI_CALCULATE_CRC32)(VOID *Data, UINTN DataSize, UINT32 *Crc32);

#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL  0x00000001
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL        0x00000002

typedef struct {
    EFI_TABLE_HEADER         Hdr;
    /* Task Priority Services */
    EFI_RAISE_TPL            RaiseTPL;
    EFI_RESTORE_TPL          RestoreTPL;
    /* Memory Services */
    EFI_ALLOCATE_PAGES       AllocatePages;
    EFI_FREE_PAGES           FreePages;
    EFI_GET_MEMORY_MAP       GetMemoryMap;
    EFI_ALLOCATE_POOL        AllocatePool;
    EFI_FREE_POOL            FreePool;
    /* Event & Timer Services */
    EFI_CREATE_EVENT         CreateEvent;
    EFI_SET_TIMER            SetTimer;
    EFI_WAIT_FOR_EVENT       WaitForEvent;
    EFI_SIGNAL_EVENT         SignalEvent;
    EFI_CLOSE_EVENT          CloseEvent;
    EFI_CHECK_EVENT          CheckEvent;
    /* Protocol Handler Services */
    VOID                     *InstallProtocolInterface;
    VOID                     *ReinstallProtocolInterface;
    VOID                     *UninstallProtocolInterface;
    EFI_HANDLE_PROTOCOL      HandleProtocol;
    VOID                     *Reserved;
    VOID                     *RegisterProtocolNotify;
    EFI_LOCATE_HANDLE        LocateHandle;
    EFI_LOCATE_DEVICE_PATH   LocateDevicePath;
    EFI_INSTALL_CONFIGURATION_TABLE InstallConfigurationTable;
    /* Image Services */
    EFI_IMAGE_LOAD           LoadImage;
    EFI_IMAGE_START          StartImage;
    EFI_EXIT                 Exit;
    EFI_IMAGE_UNLOAD         UnloadImage;
    EFI_EXIT_BOOT_SERVICES   ExitBootServices;
    /* Miscellaneous Services */
    VOID                     *GetNextMonotonicCount;
    EFI_STALL                Stall;
    EFI_SET_WATCHDOG_TIMER   SetWatchdogTimer;
    /* DriverSupport Services */
    VOID                     *ConnectController;
    VOID                     *DisconnectController;
    /* Open and Close Protocol Services */
    EFI_OPEN_PROTOCOL        OpenProtocol;
    EFI_CLOSE_PROTOCOL       CloseProtocol;
    VOID                     *OpenProtocolInformation;
    /* Library Services */
    EFI_PROTOCOLS_PER_HANDLE ProtocolsPerHandle;
    EFI_LOCATE_HANDLE_BUFFER LocateHandleBuffer;
    EFI_LOCATE_PROTOCOL      LocateProtocol;
    VOID                     *InstallMultipleProtocolInterfaces;
    VOID                     *UninstallMultipleProtocolInterfaces;
    /* 32-bit CRC Services */
    EFI_CALCULATE_CRC32      CalculateCrc32;
    /* Miscellaneous Services */
    VOID                     *CopyMem;
    VOID                     *SetMem;
    VOID                     *CreateEventEx;
} EFI_BOOT_SERVICES;

typedef struct {
    EFI_GUID VendorGuid;
    VOID     *VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct {
    EFI_TABLE_HEADER                Hdr;
    CHAR16                          *FirmwareVendor;
    UINT32                          FirmwareRevision;
    EFI_HANDLE                      ConsoleInHandle;
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL  *ConIn;
    EFI_HANDLE                      ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
    EFI_HANDLE                      StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;
    EFI_RUNTIME_SERVICES            *RuntimeServices;
    EFI_BOOT_SERVICES               *BootServices;
    UINTN                           NumberOfTableEntries;
    EFI_CONFIGURATION_TABLE         *ConfigurationTable;
} EFI_SYSTEM_TABLE;

/* Loaded Image Protocol */
typedef struct {
    UINT32                   Revision;
    EFI_HANDLE               ParentHandle;
    EFI_SYSTEM_TABLE         *SystemTable;
    EFI_HANDLE               DeviceHandle;
    EFI_DEVICE_PATH_PROTOCOL *FilePath;
    VOID                     *Reserved;
    UINT32                   LoadOptionsSize;
    VOID                     *LoadOptions;
    VOID                     *ImageBase;
    UINT64                   ImageSize;
    EFI_MEMORY_TYPE          ImageCodeType;
    EFI_MEMORY_TYPE          ImageDataType;
    EFI_IMAGE_UNLOAD         Unload;
} EFI_LOADED_IMAGE_PROTOCOL;

/* Simple File System & File Protocol */
#define EFI_FILE_MODE_READ   0x0000000000000001ULL
#define EFI_FILE_MODE_WRITE  0x0000000000000002ULL
#define EFI_FILE_MODE_CREATE 0x8000000000000000ULL
#define EFI_FILE_READ_ONLY   0x0000000000000001ULL
#define EFI_FILE_HIDDEN      0x0000000000000002ULL
#define EFI_FILE_SYSTEM      0x0000000000000004ULL
#define EFI_FILE_DIRECTORY   0x0000000000000010ULL

struct _EFI_FILE_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_FILE_OPEN)(
    struct _EFI_FILE_PROTOCOL *This, struct _EFI_FILE_PROTOCOL **NewHandle,
    CHAR16 *FileName, UINT64 OpenMode, UINT64 Attributes);
typedef EFI_STATUS (EFIAPI *EFI_FILE_CLOSE)(struct _EFI_FILE_PROTOCOL *This);
typedef EFI_STATUS (EFIAPI *EFI_FILE_DELETE)(struct _EFI_FILE_PROTOCOL *This);
typedef EFI_STATUS (EFIAPI *EFI_FILE_READ)(struct _EFI_FILE_PROTOCOL *This, UINTN *BufferSize, VOID *Buffer);
typedef EFI_STATUS (EFIAPI *EFI_FILE_WRITE)(struct _EFI_FILE_PROTOCOL *This, UINTN *BufferSize, VOID *Buffer);
typedef EFI_STATUS (EFIAPI *EFI_FILE_SET_POSITION)(struct _EFI_FILE_PROTOCOL *This, UINT64 Position);
typedef EFI_STATUS (EFIAPI *EFI_FILE_GET_INFO)(
    struct _EFI_FILE_PROTOCOL *This, EFI_GUID *InformationType, UINTN *BufferSize, VOID *Buffer);
typedef EFI_STATUS (EFIAPI *EFI_FILE_FLUSH)(struct _EFI_FILE_PROTOCOL *This);

typedef struct _EFI_FILE_PROTOCOL {
    UINT64                Revision;
    EFI_FILE_OPEN         Open;
    EFI_FILE_CLOSE        Close;
    EFI_FILE_DELETE       Delete;
    EFI_FILE_READ         Read;
    EFI_FILE_WRITE        Write;
    VOID                  *GetPosition;
    EFI_FILE_SET_POSITION SetPosition;
    EFI_FILE_GET_INFO     GetInfo;
    VOID                  *SetInfo;
    EFI_FILE_FLUSH        Flush;
} EFI_FILE_PROTOCOL;

typedef struct {
    UINT64   Size;
    UINT64   FileSize;
    UINT64   PhysicalSize;
    EFI_TIME CreateTime;
    EFI_TIME LastAccessTime;
    EFI_TIME ModificationTime;
    UINT64   Attribute;
    CHAR16   FileName[1];
} EFI_FILE_INFO;

typedef struct {
    UINT64  Size;
    BOOLEAN ReadOnly;
    UINT64  VolumeSize;
    UINT64  FreeSpace;
    UINT32  BlockSize;
    CHAR16  VolumeLabel[1];
} EFI_FILE_SYSTEM_INFO;

struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_SIMPLE_FILE_SYSTEM_OPEN_VOLUME)(
    struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *This, EFI_FILE_PROTOCOL **Root);

typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
    UINT64                             Revision;
    EFI_SIMPLE_FILE_SYSTEM_OPEN_VOLUME OpenVolume;
} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

/* Block I/O Protocol */
typedef struct {
    UINT32  MediaId;
    BOOLEAN RemovableMedia;
    BOOLEAN MediaPresent;
    BOOLEAN LogicalPartition;
    BOOLEAN ReadOnly;
    BOOLEAN WriteCaching;
    UINT32  BlockSize;
    UINT32  IoAlign;
    UINT64  LastBlock;
} EFI_BLOCK_IO_MEDIA;

typedef struct {
    UINT64             Revision;
    EFI_BLOCK_IO_MEDIA *Media;
    VOID               *Reset;
    VOID               *ReadBlocks;
    VOID               *WriteBlocks;
    VOID               *FlushBlocks;
} EFI_BLOCK_IO_PROTOCOL;

/* PCI I/O Protocol */
typedef enum {
    EfiPciIoWidthUint8 = 0,
    EfiPciIoWidthUint16 = 1,
    EfiPciIoWidthUint32 = 2,
    EfiPciIoWidthUint64 = 3
} EFI_PCI_IO_PROTOCOL_WIDTH;

struct _EFI_PCI_IO_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_PCI_IO_CONFIG)(
    struct _EFI_PCI_IO_PROTOCOL *This,
    EFI_PCI_IO_PROTOCOL_WIDTH Width,
    UINT32 Offset,
    UINTN Count,
    VOID *Buffer
);
typedef EFI_STATUS (EFIAPI *EFI_PCI_IO_GET_LOCATION)(
    struct _EFI_PCI_IO_PROTOCOL *This,
    UINTN *SegmentNumber,
    UINTN *BusNumber,
    UINTN *DeviceNumber,
    UINTN *FunctionNumber
);

typedef struct {
    VOID *Read;
    VOID *Write;
} EFI_PCI_IO_ACCESS_GENERIC;

typedef struct {
    EFI_PCI_IO_CONFIG Read;
    EFI_PCI_IO_CONFIG Write;
} EFI_PCI_IO_CONFIG_ACCESS;

typedef struct _EFI_PCI_IO_PROTOCOL {
    VOID                      *PollMem;
    VOID                      *PollIo;
    EFI_PCI_IO_ACCESS_GENERIC Mem;
    EFI_PCI_IO_ACCESS_GENERIC Io;
    EFI_PCI_IO_CONFIG_ACCESS  Pci;
    VOID                      *CopyMem;
    VOID                      *Map;
    VOID                      *Unmap;
    VOID                      *AllocateBuffer;
    VOID                      *FreeBuffer;
    VOID                      *Flush;
    EFI_PCI_IO_GET_LOCATION   GetLocation;
    VOID                      *Attributes;
    VOID                      *GetBarAttributes;
    VOID                      *SetBarAttributes;
    UINT64                    RomSize;
    VOID                      *RomImage;
} EFI_PCI_IO_PROTOCOL;

/* Graphics Output Protocol (GOP) */
typedef enum {
    PixelRedGreenBlueReserved8BitPerColor = 0,
    PixelBlueGreenRedReserved8BitPerColor = 1,
    PixelBitMask = 2,
    PixelBltOnly = 3,
    PixelFormatMax = 4
} EFI_GRAPHICS_PIXEL_FORMAT;

typedef struct {
    UINT32 RedMask;
    UINT32 GreenMask;
    UINT32 BlueMask;
    UINT32 ReservedMask;
} EFI_PIXEL_BITMASK;

typedef struct {
    UINT32                    Version;
    UINT32                    HorizontalResolution;
    UINT32                    VerticalResolution;
    EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;
    EFI_PIXEL_BITMASK         PixelInformation;
    UINT32                    PixelsPerScanLine;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

typedef struct {
    UINT32                               MaxMode;
    UINT32                               Mode;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
    UINTN                                SizeOfInfo;
    EFI_PHYSICAL_ADDRESS                 FrameBufferBase;
    UINTN                                FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

struct _EFI_GRAPHICS_OUTPUT_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_GRAPHICS_OUTPUT_QUERY_MODE)(
    struct _EFI_GRAPHICS_OUTPUT_PROTOCOL *This, UINT32 ModeNumber,
    UINTN *SizeOfInfo, EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **Info);
typedef EFI_STATUS (EFIAPI *EFI_GRAPHICS_OUTPUT_SET_MODE)(
    struct _EFI_GRAPHICS_OUTPUT_PROTOCOL *This, UINT32 ModeNumber);

typedef struct _EFI_GRAPHICS_OUTPUT_PROTOCOL {
    EFI_GRAPHICS_OUTPUT_QUERY_MODE     QueryMode;
    EFI_GRAPHICS_OUTPUT_SET_MODE       SetMode;
    VOID                               *Blt;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE  *Mode;
} EFI_GRAPHICS_OUTPUT_PROTOCOL;

/* HII Database Protocol (for discovering firmware Setup IFR/VarStores) */
struct _EFI_HII_DATABASE_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_HII_DATABASE_EXPORT_PACKS)(
    const struct _EFI_HII_DATABASE_PROTOCOL *This,
    EFI_HANDLE Handle,
    UINTN *BufferSize,
    VOID *Buffer
);

typedef struct _EFI_HII_DATABASE_PROTOCOL {
    VOID                          *NewPackageList;
    VOID                          *RemovePackageList;
    VOID                          *UpdatePackageList;
    VOID                          *ListPackageLists;
    EFI_HII_DATABASE_EXPORT_PACKS ExportPackageLists;
    VOID                          *RegisterPackageNotify;
    VOID                          *UnregisterPackageNotify;
    VOID                          *FindKeyboardLayouts;
    VOID                          *GetKeyboardLayout;
    VOID                          *SetKeyboardLayout;
    VOID                          *GetPackageListHandle;
} EFI_HII_DATABASE_PROTOCOL;

typedef struct {
    EFI_GUID PackageListGuid;
    UINT32   PackageLength;
} PACKED EFI_HII_PACKAGE_LIST_HEADER;

typedef struct {
    UINT32 Length : 24;
    UINT32 Type   : 8;
} PACKED EFI_HII_PACKAGE_HEADER;

#define EFI_HII_PACKAGE_FORMS        0x02
#define EFI_HII_PACKAGE_STRINGS      0x04
#define EFI_HII_PACKAGE_END          0xDF

/* Firmware Volume 2 Protocol (UEFI PI Spec - for extracting hidden PE32 HII Setup IFR) */
typedef UINT64 EFI_FV_ATTRIBUTES;
typedef UINT32 EFI_FV_FILE_ATTRIBUTES;
typedef UINT8  EFI_FV_FILETYPE;
typedef UINT8  EFI_SECTION_TYPE;

#define EFI_FV_FILETYPE_ALL                   0x00
#define EFI_FV_FILETYPE_FREEFORM              0x02
#define EFI_FV_FILETYPE_DRIVER                0x07
#define EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER  0x08
#define EFI_FV_FILETYPE_APPLICATION           0x09

#define EFI_SECTION_PE32                      0x10
#define EFI_SECTION_PIC                       0x11
#define EFI_SECTION_RAW                       0x19

struct _EFI_FIRMWARE_VOLUME2_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_FV_READ_SECTION)(
    const struct _EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
    const EFI_GUID *NameGuid,
    EFI_SECTION_TYPE SectionType,
    UINTN SectionInstance,
    VOID **Buffer,
    UINTN *BufferSize,
    UINT32 *AuthenticationStatus
);
typedef EFI_STATUS (EFIAPI *EFI_FV_GET_NEXT_FILE)(
    const struct _EFI_FIRMWARE_VOLUME2_PROTOCOL *This,
    VOID *Key,
    EFI_FV_FILETYPE *FileType,
    EFI_GUID *NameGuid,
    EFI_FV_FILE_ATTRIBUTES *Attributes,
    UINTN *Size
);

typedef struct _EFI_FIRMWARE_VOLUME2_PROTOCOL {
    VOID                 *GetVolumeAttributes;
    VOID                 *SetVolumeAttributes;
    VOID                 *ReadFile;
    EFI_FV_READ_SECTION   ReadSection;
    VOID                 *WriteFile;
    EFI_FV_GET_NEXT_FILE  GetNextFile;
    UINT32                KeySize;
    EFI_HANDLE            ParentHandle;
    VOID                 *GetInfo;
    VOID                 *SetInfo;
} EFI_FIRMWARE_VOLUME2_PROTOCOL;

/* MP Services Protocol (CPU core/thread count & all-core MSR/AP control) */
struct _EFI_MP_SERVICES_PROTOCOL;
typedef VOID (EFIAPI *EFI_AP_PROCEDURE)(VOID *Buffer);

typedef EFI_STATUS (EFIAPI *EFI_MP_GET_NUMBER_OF_PROCESSORS)(
    struct _EFI_MP_SERVICES_PROTOCOL *This,
    UINTN *NumberOfProcessors,
    UINTN *NumberOfEnabledProcessors
);

typedef EFI_STATUS (EFIAPI *EFI_MP_STARTUP_ALL_APS)(
    struct _EFI_MP_SERVICES_PROTOCOL *This,
    EFI_AP_PROCEDURE Procedure,
    BOOLEAN SingleThread,
    VOID *WaitEvent,
    UINTN TimeoutInMicroseconds,
    VOID *ProcedureArgument,
    UINTN **FailedCpuList
);

typedef EFI_STATUS (EFIAPI *EFI_MP_ENABLE_DISABLE_AP)(
    struct _EFI_MP_SERVICES_PROTOCOL *This,
    UINTN ProcessorNumber,
    BOOLEAN EnableAP,
    UINT32 *HealthFlag
);

typedef struct _EFI_MP_SERVICES_PROTOCOL {
    EFI_MP_GET_NUMBER_OF_PROCESSORS GetNumberOfProcessors;
    VOID                            *GetProcessorInfo;
    EFI_MP_STARTUP_ALL_APS          StartupAllAPs;
    VOID                            *StartupThisAP;
    VOID                            *SwitchBSP;
    EFI_MP_ENABLE_DISABLE_AP        EnableDisableAP;
    VOID                            *WhoAmI;
} EFI_MP_SERVICES_PROTOCOL;

/* Device Path To Text Protocol */
struct _EFI_DEVICE_PATH_TO_TEXT_PROTOCOL;
typedef CHAR16* (EFIAPI *EFI_DEVICE_PATH_TO_TEXT_PATH)(
    const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
    BOOLEAN DisplayOnly,
    BOOLEAN AllowShortcuts
);
typedef struct _EFI_DEVICE_PATH_TO_TEXT_PROTOCOL {
    VOID                         *ConvertDeviceNodeToText;
    EFI_DEVICE_PATH_TO_TEXT_PATH ConvertDevicePathToText;
} EFI_DEVICE_PATH_TO_TEXT_PROTOCOL;

/* HII Config Routing & Config Access Protocols (Persistent Driver / Checksum / APCB Sync) */
struct _EFI_HII_CONFIG_ROUTING_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_HII_EXTRACT_CONFIG)(
    const struct _EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
    const CHAR16 *Request,
    CHAR16 **Progress,
    CHAR16 **Results
);
typedef EFI_STATUS (EFIAPI *EFI_HII_EXPORT_CONFIG)(
    const struct _EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
    CHAR16 **Results
);
typedef EFI_STATUS (EFIAPI *EFI_HII_ROUTE_CONFIG)(
    const struct _EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
    const CHAR16 *Configuration,
    CHAR16 **Progress
);
typedef EFI_STATUS (EFIAPI *EFI_HII_BLOCK_TO_CONFIG)(
    const struct _EFI_HII_CONFIG_ROUTING_PROTOCOL *This,
    const CHAR16 *ConfigRequest,
    const UINT8 *Block,
    UINTN BlockSize,
    CHAR16 **Config,
    CHAR16 **Progress
);

typedef struct _EFI_HII_CONFIG_ROUTING_PROTOCOL {
    EFI_HII_EXTRACT_CONFIG  ExtractConfig;
    EFI_HII_EXPORT_CONFIG   ExportConfig;
    EFI_HII_ROUTE_CONFIG    RouteConfig;
    EFI_HII_BLOCK_TO_CONFIG BlockToConfig;
    VOID                   *ConfigToBlock;
    VOID                   *GetAltCfg;
} EFI_HII_CONFIG_ROUTING_PROTOCOL;

/* SMBIOS Structures */
typedef struct {
    CHAR8  Anchor[4];              /* "_SM_" */
    UINT8  EntryPointChecksum;
    UINT8  EntryPointLength;
    UINT8  MajorVersion;
    UINT8  MinorVersion;
    UINT16 MaxStructureSize;
    UINT8  EntryPointRevision;
    CHAR8  FormattedArea[5];
    CHAR8  IntermediateAnchor[5];  /* "_DMI_" */
    UINT8  IntermediateChecksum;
    UINT16 TableLength;
    UINT32 TableAddress;
    UINT16 NumberOfSmbiosStructures;
    UINT8  SmbiosBcdRevision;
} PACKED SMBIOS_ENTRY_POINT_21;

typedef struct {
    CHAR8  Anchor[5];              /* "_SM3_" */
    UINT8  EntryPointChecksum;
    UINT8  EntryPointLength;
    UINT8  MajorVersion;
    UINT8  MinorVersion;
    UINT8  Docrev;
    UINT8  EntryPointRevision;
    UINT8  Reserved;
    UINT32 TableMaximumSize;
    UINT64 TableAddress;
} PACKED SMBIOS_ENTRY_POINT_30;

typedef struct {
    UINT8 Type;
    UINT8 Length;
    UINT16 Handle;
} PACKED SMBIOS_HEADER;

/* ACPI Structures */
typedef struct {
    CHAR8  Signature[8];           /* "RSD PTR " */
    UINT8  Checksum;
    CHAR8  OemId[6];
    UINT8  Revision;
    UINT32 RsdtAddress;
    UINT32 Length;
    UINT64 XsdtAddress;
    UINT8  ExtendedChecksum;
    UINT8  Reserved[3];
} PACKED ACPI_RSDP;

typedef struct {
    CHAR8  Signature[4];
    UINT32 Length;
    UINT8  Revision;
    UINT8  Checksum;
    CHAR8  OemId[6];
    CHAR8  OemTableId[8];
    UINT32 OemRevision;
    CHAR8  CreatorId[4];
    UINT32 CreatorRevision;
} PACKED ACPI_SDT_HEADER;

/* Global UEFI Pointers */
extern EFI_HANDLE        gImageHandle;
extern EFI_SYSTEM_TABLE  *gST;
extern EFI_BOOT_SERVICES *gBS;
extern EFI_RUNTIME_SERVICES *gRT;

/* Well-Known GUIDs */
extern EFI_GUID gEfiGlobalVariableGuid;
extern EFI_GUID gEfiImageSecurityDatabaseGuid;
extern EFI_GUID gEfiSmbiosTableGuid;
extern EFI_GUID gEfiSmbios3TableGuid;
extern EFI_GUID gEfiAcpi20TableGuid;
extern EFI_GUID gEfiAcpi10TableGuid;
extern EFI_GUID gEfiConsoleControlProtocolGuid;
extern EFI_GUID gEfiLoadedImageProtocolGuid;
extern EFI_GUID gEfiSimpleFileSystemProtocolGuid;
extern EFI_GUID gEfiFileInfoGuid;
extern EFI_GUID gEfiFileSystemInfoGuid;
extern EFI_GUID gEfiBlockIoProtocolGuid;
extern EFI_GUID gEfiDevicePathProtocolGuid;
extern EFI_GUID gEfiDevicePathToTextProtocolGuid;
extern EFI_GUID gEfiPciIoProtocolGuid;
extern EFI_GUID gEfiGraphicsOutputProtocolGuid;
extern EFI_GUID gEfiHiiDatabaseProtocolGuid;
extern EFI_GUID gEfiHiiConfigRoutingProtocolGuid;
extern EFI_GUID gEfiHiiConfigAccessProtocolGuid;
extern EFI_GUID gEdkiiIfrBitVarstoreGuid;
extern EFI_GUID gEfiFirmwareVolume2ProtocolGuid;
extern EFI_GUID gEfiMpServicesProtocolGuid;
extern EFI_GUID gAppleBootVariableGuid;
extern EFI_GUID gAppleFirmwareVariableGuid;
extern EFI_GUID gAppleGpuPowerPrefsGuid;
extern EFI_GUID gSetupUtilityConfigGuid;
extern EFI_GUID gOhMyEfiAutoPatchGuid;

#endif /* EFI_SETUP_EFI_H */
