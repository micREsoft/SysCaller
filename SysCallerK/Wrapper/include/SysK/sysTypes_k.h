#pragma once

#include <SysK/sysExternals_k.h>
#include <SysK/sysConstants_k.h>

/* Forward declarations for cyclic dependencies */
typedef struct _ACTIVATION_CONTEXT* PACTIVATION_CONTEXT;
typedef struct _ACTIVATION_CONTEXT_DATA* PACTIVATION_CONTEXT_DATA;
typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* PRTL_ACTIVATION_CONTEXT_STACK_FRAME;
typedef struct _ACTIVATION_CONTEXT_STACK* PACTIVATION_CONTEXT_STACK;
typedef struct _TEB* PTEB;

// #define USE_PISID  /* Uncomment this line to use PISID instead of PSID */
#define USE_DYNAMIC_ARRAY  /* Uncomment this line to use dynamic array */
#define USE_POINTER_SUBAUTH /* Uncomment this line to use pointer to an array for SubAuthority */

/* APC Routines */
typedef VOID(NTAPI * PPS_APC_ROUTINE)(
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );

typedef VOID(NTAPI * TIMER_APC_ROUTINE)(
    _In_ PVOID TimerContext,
    _In_ ULONG TimerLowValue,
    _In_ LONG TimerHighValue
    );

typedef VOID(NTAPI * PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

typedef VOID(NTAPI * IO_APC_ROUTINE)(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );

typedef VOID(NTAPI * PENCLAVE_ROUTINE)(VOID);

/* User Thread Start Routine */
typedef VOID(*PUSER_THREAD_START_ROUTINE)(PVOID);

/* Timer APC Routine */

typedef VOID(NTAPI* PACTIVATION_CONTEXT_NOTIFY_ROUTINE)(
    _In_ ULONG NotificationType, /* ACTIVATION_CONTEXT_NOTIFICATION_* */
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _In_ PACTIVATION_CONTEXT_DATA ActivationContextData,
    _In_opt_ PVOID NotificationContext,
    _In_opt_ PVOID NotificationData,
    _Inout_ PBOOLEAN DisableThisNotification
    );

/* Activation Context Data */
typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset; /* to ACTIVATION_CONTEXT_DATA_TOC_HEADER */
    ULONG ExtendedTocOffset; /* to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER */
    ULONG AssemblyRosterOffset; /* to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER */
    ULONG Flags; /* ACTIVATION_CONTEXT_FLAG_* */
} ACTIVATION_CONTEXT_DATA, * PACTIVATION_CONTEXT_DATA;

/* Assembly Storage Map Entry */
typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, * PASSEMBLY_STORAGE_MAP_ENTRY;

/* Assembly Storage Map */
typedef struct _ASSEMBLY_STORAGE_MAP
{
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY* AssemblyArray;
} ASSEMBLY_STORAGE_MAP, * PASSEMBLY_STORAGE_MAP;

/* Activation Context */
typedef struct _ACTIVATION_CONTEXT
{
    LONG RefCount;
    ULONG Flags;
    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
    PVOID NotificationContext;
    ULONG SentNotifications[8];
    ULONG DisabledNotifications[8];
    ASSEMBLY_STORAGE_MAP StorageMap;
    PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[32];
} ACTIVATION_CONTEXT, * PACTIVATION_CONTEXT;

/* RTL Activation Context Stack Frame */
typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags; /* RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_* */
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

/* Activation Context Stack Frame */
typedef struct _ACTIVATION_CONTEXT_STACK
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags; /* ACTIVATION_CONTEXT_STACK_FLAG_* */
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

/* Boot Options */
typedef struct _BOOT_OPTIONS
{
    ULONG Version;
    ULONG Length;
    ULONG Timeout;
    ULONG CurrentBootEntryId;
    ULONG NextBootEntryId;
    WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, * PBOOT_OPTIONS;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

/* CM Extended Parameter */
typedef struct DECLSPEC_ALIGN(8) _CM_EXTENDED_PARAMETER
{
    /* Bit field for the type of the extended parameter */
    struct
    {
        ULONG64 Type : CM_EXTENDED_PARAMETER_TYPE_BITS; /* Type of the extended parameter */
        ULONG64 Reserved : 64 - CM_EXTENDED_PARAMETER_TYPE_BITS; /* Reserved bits for future use */
    };
    /* Union to hold different types of data */
    union
    {
        ULONG64 ULong64; /* 64-bit unsigned long */
        PVOID Pointer;   /* Pointer to any type */
        SIZE_T Size;     /* Size type */
        HANDLE Handle;   /* Handle type */
        ULONG ULong;     /* 32-bit unsigned long */
        ACCESS_MASK AccessMask; /* Access mask type */
    };
} CM_EXTENDED_PARAMETER, * PCM_EXTENDED_PARAMETER;

/* DBGKM Create Thread */
typedef struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, * PDBGKM_CREATE_THREAD;

/* DBGKM Create Process */
typedef struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, * PDBGKM_CREATE_PROCESS;

/* DBGKM Exception */
typedef struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, * PDBGKM_EXCEPTION;

/* DBGKM Exit Thread */
typedef struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, * PDBGKM_EXIT_THREAD;

/* DBGKM Exit Process */
typedef struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, * PDBGKM_EXIT_PROCESS;

/* DBGKM Load DLL */
typedef struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, * PDBGKM_LOAD_DLL;

/* DBGKM Unload DLL */
typedef struct _DBGKM_UNLOAD_DLL
{
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, * PDBGKM_UNLOAD_DLL;

/* DBGUI Create Thread */
typedef struct _DBGUI_CREATE_THREAD
{
    HANDLE HandleToThread;
    DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, * PDBGUI_CREATE_THREAD;

/* DBGUI Create Process */
typedef struct _DBGUI_CREATE_PROCESS
{
    HANDLE HandleToProcess;
    HANDLE HandleToThread;
    DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, * PDBGUI_CREATE_PROCESS;

/* DBGUI Wait State Change */
typedef struct _DBGUI_WAIT_STATE_CHANGE
{
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union
    {
        DBGKM_EXCEPTION Exception;
        DBGUI_CREATE_THREAD CreateThread;
        DBGUI_CREATE_PROCESS CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, * PDBGUI_WAIT_STATE_CHANGE;

/* File Basic Information */
typedef struct _SYSK_FILE_BASIC_INFORMATION
{
    LARGE_INTEGER CreationTime;         /* Specifies the time that the file was created. */
    LARGE_INTEGER LastAccessTime;       /* Specifies the time that the file was last accessed. */
    LARGE_INTEGER LastWriteTime;        /* Specifies the time that the file was last written to. */
    LARGE_INTEGER ChangeTime;           /* Specifies the last time the file was changed. */
    ULONG FileAttributes;               /* Specifies one or more FILE_ATTRIBUTE_XXX flags. */
} SYSK_FILE_BASIC_INFORMATION, * PSYSK_FILE_BASIC_INFORMATION;

/* File IO Completion Information */
typedef struct _FILE_IO_COMPLETION_INFORMATION
{
    PVOID KeyContext;
    PVOID ApcContext;
    IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, * PFILE_IO_COMPLETION_INFORMATION;

/* File Network Open Information */
typedef struct _SYSK_FILE_NETWORK_OPEN_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} SYSK_FILE_NETWORK_OPEN_INFORMATION, * PSYSK_FILE_NETWORK_OPEN_INFORMATION;

/* File Path */
typedef struct _FILE_PATH
{
    ULONG Version;
    ULONG Length;
    ULONG Type;
    _Field_size_bytes_(Length) UCHAR FilePath[1];
} FILE_PATH, * PFILE_PATH;

/* GDI TEB Batch */
typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

/* Initial TEB */
typedef struct _INITIAL_TEB
{
    struct
    {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, * PINITIAL_TEB;

/* Job Set Arrary */
typedef struct _JOB_SET_ARRAY {
    HANDLE JobHandle;
    DWORD MemberLevel;
    DWORD Flags;
} JOB_SET_ARRAY, * PJOB_SET_ARRAY;

/* Memory Range Entry */
typedef struct _SYSK_MEMORY_RANGE_ENTRY
{
    PVOID VirtualAddress;
    SIZE_T NumberOfBytes;
} SYSK_MEMORY_RANGE_ENTRY, * PSYSK_MEMORY_RANGE_ENTRY;

/* NTPSS Memory Bulk Information */
typedef struct _NTPSS_MEMORY_BULK_INFORMATION
{
    ULONG QueryFlags;
    ULONG NumberOfEntries;
    PVOID NextValidAddress;
} NTPSS_MEMORY_BULK_INFORMATION, * PNTPSS_MEMORY_BULK_INFORMATION;

/* Object Boundary Descriptor */
typedef struct _OBJECT_BOUNDARY_DESCRIPTOR
{
    ULONG Version;
    ULONG Items;
    ULONG TotalSize;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG AddAppContainerSid : 1;
            ULONG Reserved : 31;
        };
    };
    /* OBJECT_BOUNDARY_ENTRY Entries[1]; */
} OBJECT_BOUNDARY_DESCRIPTOR, * POBJECT_BOUNDARY_DESCRIPTOR;

/* PS Attribute */
typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

/* PS Attribute List */
typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

/* PS Create Info */
typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        /* PsCreateInitialState */
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;
        /* PsCreateFailOnSectionCreate */
        struct
        {
            HANDLE FileHandle;
        } FailSection;
        /* PsCreateFailExeFormat */
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;
        /* PsCreateFailExeName */
        struct
        {
            HANDLE IFEOKey;
        } ExeName;
        /* PsCreateSuccess */
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; /* from Image File Execution Options */
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;

/* RTL Drive Letter Current Directory */
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

/* RTL User Process Parameters */
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName; /* REDSTONE4 */
    UNICODE_STRING HeapPartitionName; /* 19H1 */
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; /* WIN11 */
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

/* SE File Cache Claim Information */
typedef struct _SE_FILE_CACHE_CLAIM_INFORMATION
{
    ULONG Size;
    PVOID Claim;
} SE_FILE_CACHE_CLAIM_INFORMATION, * PSE_FILE_CACHE_CLAIM_INFORMATION;

/* SE Set File Cache Information */
typedef struct _SE_SET_FILE_CACHE_INFORMATION
{
    ULONG Size;
    UNICODE_STRING CatalogDirectoryPath;
    SE_FILE_CACHE_CLAIM_INFORMATION OriginClaimInfo;
} SE_SET_FILE_CACHE_INFORMATION, * PSE_SET_FILE_CACHE_INFORMATION;

/* System Thread Information */
typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;       /* Number of 100-nanosecond intervals spent executing kernel code. */
    LARGE_INTEGER UserTime;         /* Number of 100-nanosecond intervals spent executing user code. */
    LARGE_INTEGER CreateTime;       /* The date and time when the thread was created. */
    ULONG WaitTime;                 /* The current time spent in ready queue or waiting (depending on the thread state). */
    PVOID StartAddress;             /* The initial start address of the thread. */
    CLIENT_ID ClientId;             /* The identifier of the thread and the process owning the thread. */
    KPRIORITY Priority;             /* The dynamic priority of the thread. */
    KPRIORITY BasePriority;         /* The starting priority of the thread. */
    ULONG ContextSwitches;          /* The total number of context switches performed. */
    KTHREAD_STATE ThreadState;      /* The current state of the thread. */
    KWAIT_REASON WaitReason;        /* The current reason the thread is waiting. */
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

/* System Process Information */
typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;                  /* The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0. */
    ULONG NumberOfThreads;                  /* The NumberOfThreads member contains the number of threads in the process. */
    ULONGLONG WorkingSetPrivateSize;        /* since VISTA */
    ULONG HardFaultCount;                   /* since WIN7 */
    ULONG NumberOfThreadsHighWatermark;     /* The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management. */
    ULONGLONG CycleTime;                    /* The sum of the cycle time of all threads in the process. */
    LARGE_INTEGER CreateTime;               /* Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes resullting in an incorrect value. */
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;               /* The file name of the executable image. */
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;             /* since VISTA (requires SystemExtendedProcessInformation) */
    SIZE_T PeakVirtualSize;                 /* The peak size, in bytes, of the virtual memory used by the process. */
    SIZE_T VirtualSize;                     /* The current size, in bytes, of virtual memory used by the process. */
    ULONG PageFaultCount;                   /* The member of page faults for data that is not currently in memory. */
    SIZE_T PeakWorkingSetSize;              /* The peak size, in kilobytes, of the working set of the process. */
    SIZE_T WorkingSetSize;                  /* The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault. */
    SIZE_T QuotaPeakPagedPoolUsage;         /* The peak quota charged to the process for pool usage, in bytes. */
    SIZE_T QuotaPagedPoolUsage;             /* The quota charged to the process for paged pool usage, in bytes. */
    SIZE_T QuotaPeakNonPagedPoolUsage;      /* The peak quota charged to the process for nonpaged pool usage, in bytes. */
    SIZE_T QuotaNonPagedPoolUsage;          /* The current quota charged to the process for nonpaged pool usage. */
    SIZE_T PagefileUsage;                   /* The PagefileUsage member contains the number of bytes of page file storage in use by the process. */
    SIZE_T PeakPagefileUsage;               /* The maximum number of bytes of page-file storage used by the process. */
    SIZE_T PrivatePageCount;                /* The number of memory pages allocated for the use by the process. */
    LARGE_INTEGER ReadOperationCount;       /* The total number of read operations performed. */
    LARGE_INTEGER WriteOperationCount;      /* The total number of write operations performed. */
    LARGE_INTEGER OtherOperationCount;      /* The total number of I/O operations performed other than read and write operations. */
    LARGE_INTEGER ReadTransferCount;        /* The total number of bytes read during a read operation. */
    LARGE_INTEGER WriteTransferCount;       /* The total number of bytes written during a write operation. */
    LARGE_INTEGER OtherTransferCount;       /* The total number of bytes transferred during operations other than read and write operations. */
    SYSTEM_THREAD_INFORMATION Threads[1];   /* This type is not defined in the structure but was added for convenience. */
} SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

/* tagSOleTlsData */
typedef struct tagSOleTlsData
{
    PVOID ThreadBase;
    PVOID SmAllocator;
    ULONG ApartmentID;
    ULONG Flags; /* OLETLSFLAGS */
    LONG TlsMapIndex;
    PVOID* TlsSlot;
    ULONG ComInits;
    ULONG OleInits;
    ULONG Calls;
    PVOID ServerCall; /* previously CallInfo (before TH1) */
    PVOID CallObjectCache; /* previously FreeAsyncCall (before TH1) */
    PVOID ContextStack; /* previously FreeClientCall (before TH1) */
    PVOID ObjServer;
    ULONG TIDCaller;
    /* ... (other fields are version-dependant) */
} SOleTlsData, * PSOleTlsData;

/* TEB Active Frame Context */
typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

/* TEB Active Frame */
typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

/* TEB */
typedef struct _TEB
{
    /*
    Thread Information Block (TIB) contains the thread's stack, base and limit addresses, the current stack pointer, and the exception list.
    */
    NT_TIB NtTib;
    /*
    Reserved.
    */
    PVOID EnvironmentPointer;
    /*
    Client ID for this thread.
    */
    CLIENT_ID ClientId;
    /*
    A handle to an active Remote Procedure Call (RPC) if the thread is currently involved in an RPC operation.
    */
    PVOID ActiveRpcHandle;
    /*
    A pointer to the __declspec(thread) local storage array.
    */
    PVOID ThreadLocalStoragePointer;
    /*
    A pointer to the Process Environment Block (PEB), which contains information about the process.
    */
    PPEB ProcessEnvironmentBlock;
    /*
    The previous Win32 error value for this thread.
    */
    ULONG LastErrorValue;
    /*
    The number of critical sections currently owned by this thread.
    */
    ULONG CountOfOwnedCriticalSections;
    /*
    Reserved.
    */
    PVOID CsrClientThread;
    /*
    Reserved for GDI/USER (Win32k).
    */
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    /*
    Reserved.
    */
    PVOID WOW32Reserved;
    /*
    The LCID of the current thread. (Kernel32!GetThreadLocale)
    */
    LCID CurrentLocale;
    /*
    Reserved.
    */
    ULONG FpSoftwareStatusRegister;
    /*
    Reserved.
    */
    PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
    /*
    Reserved.
    */
    PVOID SystemReserved1[25];
    /*
    Per-thread fiber local storage. (Teb->HasFiberData)
    */
    PVOID HeapFlsData;
    /*
    Reserved.
    */
    ULONG_PTR RngState[4];
#else
    /*
    Reserved.
    */
    PVOID SystemReserved1[26];
#endif
    /*
    Placeholder compatibility mode. (ProjFs and Cloud Files)
    */
    CHAR PlaceholderCompatibilityMode;
    /*
    Indicates whether placeholder hydration is always explicit.
    */
    BOOLEAN PlaceholderHydrationAlwaysExplicit;
    /*
    ProjFs and Cloud Files (reparse point) file virtualization.
    */
    CHAR PlaceholderReserved[10];
    /*
    The process ID (PID) that the current COM server thread is acting on behalf of.
    */
    ULONG ProxiedProcessId;
    /*
    Pointer to the activation context stack for the current thread.
    */
    ACTIVATION_CONTEXT_STACK ActivationStack;
    /*
    Opaque operation on behalf of another user or process.
    */
    UCHAR WorkingOnBehalfTicket[8];
    /*
    The last exception status for the current thread.
    */
    NTSTATUS ExceptionCode;
    /*
    Pointer to the activation context stack for the current thread.
    */
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    /*
    The stack pointer (SP) of the current system call or exception during instrumentation.
    */
    ULONG_PTR InstrumentationCallbackSp;
    /*
    The program counter (PC) of the previous system call or exception during instrumentation.
    */
    ULONG_PTR InstrumentationCallbackPreviousPc;
    /*
    The stack pointer (SP) of the previous system call or exception during instrumentation.
    */
    ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
    /*
    The miniversion ID of the current transacted file operation.
    */
    ULONG TxFsContext;
#endif
    /*
    Indicates the state of the system call or exception instrumentation callback.
    */
    BOOLEAN InstrumentationCallbackDisabled;
#ifdef _WIN64
    /*
    Indicates the state of alignment exceptions for unaligned load/store operations.
    */
    BOOLEAN UnalignedLoadStoreExceptions;
#endif
#ifndef _WIN64
    /*
    SpareBytes.
    */
    UCHAR SpareBytes[23];
    /*
    The miniversion ID of the current transacted file operation.
    */
    ULONG TxFsContext;
#endif
    /*
    Reserved for GDI (Win32k).
    */
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    /*
    Reserved for User32 (Win32k).
    */
    ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];
    /*
    Reserved for opengl32.dll
    */
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    /*
    The previous status value for this thread.
    */
    NTSTATUS LastStatusValue;
    /*
    A static string for use by the application.
    */
    UNICODE_STRING StaticUnicodeString;
    /*
    A static buffer for use by the application.
    */
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];
    /*
    The maximum stack size and indicates the base of the stack.
    */
    PVOID DeallocationStack;
    /*
    Data for Thread Local Storage. (TlsGetValue)
    */
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];
    /*
    Reserved for TLS.
    */
    LIST_ENTRY TlsLinks;
    /*
    Reserved for NTVDM.
    */
    PVOID Vdm;
    /*
    Reserved for RPC.
    */
    PVOID ReservedForNtRpc;
    /*
    Reserved for Debugging (DebugActiveProcess).
    */
    PVOID DbgSsReserved[2];
    /*
    The error mode for the current thread. (GetThreadErrorMode)
    */
    ULONG HardErrorMode;
    /*
    Reserved.
    */
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    /*
    Reserved.
    */
    GUID ActivityId;
    /*
    The identifier of the service that created the thread. (svchost)
    */
    PVOID SubProcessTag;
    /*
    Reserved.
    */
    PVOID PerflibData;
    /*
    Reserved.
    */
    PVOID EtwTraceData;
    /*
    The address of a socket handle during a blocking socket operation. (WSAStartup)
    */
    HANDLE WinSockData;
    /*
    The number of function calls accumulated in the current GDI batch. (GdiSetBatchLimit)
    */
    ULONG GdiBatchCount;
    /*
    The preferred processor for the current thread. (SetThreadIdealProcessor/SetThreadIdealProcessorEx)
    */
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };
    /*
    The minimum size of the stack available during any stack overflow exceptions. (SetThreadStackGuarantee)
    */
    ULONG GuaranteedStackBytes;
    /*
    Reserved.
    */
    PVOID ReservedForPerf;
    /*
    Reserved for Object Linking and Embedding (OLE)
    */
    PSOleTlsData ReservedForOle;
    /*
    Indicates whether the thread is waiting on the loader lock.
    */
    ULONG WaitingOnLoaderLock;
    /*
    The saved priority state for the thread.
    */
    PVOID SavedPriorityState;
    /*
    Reserved.
    */
    ULONG_PTR ReservedForCodeCoverage;
    /*
    Reserved.
    */
    PVOID ThreadPoolData;
    /*
    Pointer to the TLS (Thread Local Storage) expansion slots for the thread.
    */
    PVOID* TlsExpansionSlots;
#ifdef _WIN64
    PVOID ChpeV2CpuAreaInfo; /* CHPEV2_CPUAREA_INFO, previously DeallocationBStore */
    PVOID Unused; /* previously BStoreLimit */
#endif
    /*
    The generation of the MUI (Multilingual User Interface) data.
    */
    ULONG MuiGeneration;
    /*
    Indicates whether the thread is impersonating another security context.
    */
    ULONG IsImpersonating;
    /*
    Pointer to the NLS (National Language Support) cache.
    */
    PVOID NlsCache;
    /*
    Pointer to the AppCompat/Shim Engine data.
    */
    PVOID pShimData;
    /*
    Reserved.
    */
    ULONG HeapData;
    /*
    Handle to the current transaction associated with the thread.
    */
    HANDLE CurrentTransactionHandle;
    /*
    Pointer to the active frame for the thread.
    */
    PTEB_ACTIVE_FRAME ActiveFrame;
    /*
    Reserved for FLS (RtlProcessFlsData).
    */
    PVOID FlsData;
    /*
    Pointer to the preferred languages for the current thread. (GetThreadPreferredUILanguages)
    */
    PVOID PreferredLanguages;
    /*
    Pointer to the user-preferred languages for the current thread. (GetUserPreferredUILanguages)
    */
    PVOID UserPrefLanguages;
    /*
    Pointer to the merged preferred languages for the current thread. (MUI_MERGE_USER_FALLBACK)
    */
    PVOID MergedPrefLanguages;
    /*
    Indicates whether the thread is impersonating another user's language settings.
    */
    ULONG MuiImpersonation;
    /*
    Reserved.
    */
    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    /*
    SameTebFlags modify the state and behavior of the current thread.
    */
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;            /* Indicates if the thread is currently in a debug print routine. */
            USHORT HasFiberData : 1;            /* Indicates if the thread has local fiber-local storage (FLS). */
            USHORT SkipThreadAttach : 1;        /* Indicates if the thread should suppress DLL_THREAD_ATTACH notifications. */
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;          /* Indicates if the thread has run process initialization code. */
            USHORT ClonedThread : 1;            /* Indicates if the thread is a clone of a different thread. */
            USHORT SuppressDebugMsg : 1;        /* Indicates if the thread should suppress LOAD_DLL_DEBUG_INFO notifications. */
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;           /* Indicates if the thread is the initial thread of the process. */
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;               /* Indicates if the thread is the owner of the process loader lock. */
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };
    /*
    Pointer to the callback function that is called when a KTM transaction scope is entered.
    */
    PVOID TxnScopeEnterCallback;
    /*
    Pointer to the callback function that is called when a KTM transaction scope is exited.
    */
    PVOID TxnScopeExitCallback;
    /*
    Pointer to optional context data for use by the application when a KTM transaction scope callback is called.
    */
    PVOID TxnScopeContext;
    /*
    The lock count of critical sections for the current thread.
    */
    ULONG LockCount;
    /*
    The offset to the WOW64 (Windows on Windows) TEB for the current thread.
    */
    LONG WowTebOffset;
    /*
    Reserved.
    */
    PVOID ResourceRetValue;
    /*
    Reserved for Windows Driver Framework (WDF).
    */
    PVOID ReservedForWdf;
    /*
    Reserved for the Microsoft C runtime (CRT).
    */
    ULONGLONG ReservedForCrt;
    /*
    The Host Compute Service (HCS) container identifier.
    */
    GUID EffectiveContainerId;
    /*
    Reserved for Kernel32!Sleep (SpinWait).
    */
    ULONGLONG LastSleepCounter; /* since Win11 */
    /*
    Reserved for Kernel32!Sleep (SpinWait).
    */
    ULONG SpinCallCount;
    /*
    Extended feature disable mask (AVX).
    */
    ULONGLONG ExtendedFeatureDisableMask;
    /*
    Reserved.
    */
    PVOID SchedulerSharedDataSlot; /* since 24H2 */
    /*
    Reserved.
    */
    PVOID HeapWalkContext;
    /*
    The primary processor group affinity of the thread.
    */
    GROUP_AFFINITY PrimaryGroupAffinity;
    /*
    Read-copy-update (RCU) synchronization context.
    */
    ULONG Rcu[2];
} TEB, * PTEB;

/* Thread Basic Information */
typedef struct _THREAD_BASIC_INFO
{
    NTSTATUS ExitStatus;
    PTEB TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFO, * PTHREAD_BASIC_INFO;

/* T2 Set Parameters */
typedef struct _T2_SET_PARAMETERS_V0
{
    ULONG Version;
    ULONG Reserved;
    LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

/* WNF Delivery Descriptor */
typedef struct _WNF_DELIVERY_DESCRIPTOR
{
    ULONGLONG SubscriptionId;
    WNF_STATE_NAME StateName;
    WNF_CHANGE_STAMP ChangeStamp;
    ULONG StateDataSize;
    ULONG EventMask;
    WNF_TYPE_ID TypeId;
    ULONG StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, * PWNF_DELIVERY_DESCRIPTOR;

/* Worker Factory Deferred Work */
typedef struct _WORKER_FACTORY_DEFERRED_WORK
{
    PPORT_MESSAGE AlpcSendMessage;
    PVOID AlpcSendMessagePort;
    ULONG AlpcSendMessageFlags;
    ULONG Flags;
} WORKER_FACTORY_DEFERRED_WORK, * PWORKER_FACTORY_DEFERRED_WORK;