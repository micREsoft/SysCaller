#pragma once

#include "sysTypes_k.h"

typedef struct _SYSK_WNF_STATE_NAME
{
    ULONG Data[2];
} SYSK_WNF_STATE_NAME, * SYSK_PWNF_STATE_NAME;

/* WNF Type ID */
typedef struct _WNF_TYPE_ID
{
    GUID TypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;

typedef unsigned long DWORD;

/* General Types */
typedef LONG NTSTATUS;
typedef ULONG LOGICAL;
typedef ULONG_PTR SIZE_T;
typedef SIZE_T * PSIZE_T;
typedef GUID * PCGUID;
typedef GUID * PCRM_PROTOCOL_ID;
typedef DWORD SECURITY_INFORMATION, * PSECURITY_INFORMATION;
typedef LARGE_INTEGER * PLARGE_INTEGER;
typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;
typedef ULONG_PTR KAFFINITY;
typedef WNF_STATE_NAME * PWNF_STATE_NAME;
typedef PVOID PT2_CANCEL_PARAMETERS;
typedef const WNF_STATE_NAME * PCWNF_STATE_NAME;
typedef const WNF_TYPE_ID * PCWNF_TYPE_ID;
typedef const wchar_t * PCWSTR;
typedef const UNICODE_STRING * PCUNICODE_STRING;
typedef LANGID * PLANGID;
typedef ULONG LCID;
typedef LCID * PLCID;
typedef const GUID * LPCGUID;
typedef GUID * LPGUID;

/* ALPC Types */
typedef struct _PORT_MESSAGE * PPORT_MESSAGE;
typedef struct _PORT_VIEW * PPORT_VIEW;
typedef struct _REMOTE_PORT_VIEW * PREMOTE_PORT_VIEW;
typedef struct _ALPC_PORT_ATTRIBUTES * PALPC_PORT_ATTRIBUTES;
typedef struct _ALPC_MESSAGE_ATTRIBUTES * PALPC_MESSAGE_ATTRIBUTES;
typedef struct _ALPC_CONTEXT_ATTR * PALPC_CONTEXT_ATTR;
typedef HANDLE ALPC_HANDLE;
typedef struct _ALPC_DATA_VIEW_ATTR * PALPC_DATA_VIEW_ATTR;
typedef struct _ALPC_SECURITY_ATTR * PALPC_SECURITY_ATTR;
typedef HANDLE PALPC_HANDLE;

/* Proccess & Thread Types */
typedef struct _OBJECT_TYPE * POBJECT_TYPE;
typedef NTSTATUS * PNTSTATUS;
typedef HANDLE AUDIT_EVENT_HANDLE;
typedef struct _BOOT_ENTRY * PBOOT_ENTRY;
typedef struct _EFI_DRIVER_ENTRY * PEFI_DRIVER_ENTRY;
typedef ULONG PROCESS_ACTIVITY_TYPE;
typedef struct _RTL_ATOM * PRTL_ATOM;
typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION * PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;
typedef struct _SYSK_OBJECT_ATTRIBUTES * PSYSK_COBJECT_ATTRIBUTES;
typedef enum _MEMORY_RESERVE_TYPE MEMORY_RESERVE_TYPE;

/* Enum Classes & Types -> */

/* ALPC Message Information Classes */
typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
    AlpcMessageSidInformation, /* q: out SID */
    AlpcMessageTokenModifiedIdInformation,  /* q: out LUID */
    AlpcMessageDirectStatusInformation,
    AlpcMessageHandleInformation, /* ALPC_MESSAGE_HANDLE_INFORMATION */
    MaxAlpcMessageInfoClass
} ALPC_MESSAGE_INFORMATION_CLASS, * PALPC_MESSAGE_INFORMATION_CLASS;

/* ALPC Port Information Classes */
typedef enum _ALPC_PORT_INFORMATION_CLASS
{
    AlpcBasicInformation, /* q: out ALPC_BASIC_INFORMATION */
    AlpcPortInformation, /* s: in ALPC_PORT_ATTRIBUTES */
    AlpcAssociateCompletionPortInformation, /* s: in ALPC_PORT_ASSOCIATE_COMPLETION_PORT */
    AlpcConnectedSIDInformation, /* q: in SID */
    AlpcServerInformation, /* q: inout ALPC_SERVER_INFORMATION */
    AlpcMessageZoneInformation, /* s: in ALPC_PORT_MESSAGE_ZONE_INFORMATION */
    AlpcRegisterCompletionListInformation, /* s: in ALPC_PORT_COMPLETION_LIST_INFORMATION */
    AlpcUnregisterCompletionListInformation, /* s: VOID */
    AlpcAdjustCompletionListConcurrencyCountInformation, /* s: in ULONG */
    AlpcRegisterCallbackInformation, /* s: ALPC_REGISTER_CALLBACK, kernel-mode only */
    AlpcCompletionListRundownInformation, /* s: VOID, 10 */
    AlpcWaitForPortReferences,
    AlpcServerSessionInformation /* q: ALPC_SERVER_SESSION_INFORMATION, since 19H2 */
} ALPC_PORT_INFORMATION_CLASS;

/* Atom Information Classes */
typedef enum _ATOM_INFORMATION_CLASS
{
    AtomBasicInformation,
    AtomTableInformation
} ATOM_INFORMATION_CLASS;

/* CPU Partition Information Classes */
typedef enum _CPU_PARTITION_INFORMATION_CLASS
{
    CpuPartitionBasicInformation,        /* q: BASIC_CPU_PARTITION_INFORMATION */
    CpuPartitionPerformanceInformation,  /* q: CPU_PARTITION_PERFORMANCE_INFORMATION */
    CpuPartitionTopologyInformation,     /* q: CPU_PARTITION_TOPOLOGY_INFORMATION */
    CpuPartitionAffinityInformation,     /* q; s: CPU_PARTITION_AFFINITY_INFORMATION */
    CpuPartitionPolicyInformation,       /* q; s: CPU_PARTITION_POLICY_INFORMATION */
    CpuPartitionSchedulingInformation,   /* q: CPU_PARTITION_SCHEDULING_INFORMATION */
    CpuPartitionResourceControl,         /* s: CPU_PARTITION_RESOURCE_CONTROL_INFORMATION */
    CpuPartitionPowerManagement,         /* q; s: CPU_PARTITION_POWER_MANAGEMENT_INFORMATION */
    CpuPartitionStatistics,              /* q: CPU_PARTITION_STATISTICS_INFORMATION */
    CpuPartitionDebugInformation,        /* q: CPU_PARTITION_DEBUG_INFORMATION */
    CpuPartitionMax
} CPU_PARTITION_INFORMATION_CLASS, * PCPU_PARTITION_INFORMATION_CLASS;

/* Debug States */
typedef enum _DBG_STATE
{
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, * PDBG_STATE;

/* Debug Object Information Classes */
typedef enum _DEBUGOBJECTINFOCLASS
{
    DebugObjectUnusedInformation,
    DebugObjectKillProcessOnExitInformation, /* s: ULONG */
    MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, * PDEBUGOBJECTINFOCLASS;

/* Directory Notify Information Classes */
typedef enum _SYSK_DIRECTORY_NOTIFY_INFORMATION_CLASS {
    SysKDirectoryNotifyInformation,
    SysKDirectoryNotifyInformationEx,
    SysKDirectoryNotifyInformationMax
} SYSK_DIRECTORY_NOTIFY_INFORMATION_CLASS;

/* ETW Trace Control Codes */
typedef enum _ETWTRACECONTROLCODE
{
    EtwStartLoggerCode = 1, /* inout WMI_LOGGER_INFORMATION */
    EtwStopLoggerCode = 2, /* inout WMI_LOGGER_INFORMATION */
    EtwQueryLoggerCode = 3, /* inout WMI_LOGGER_INFORMATION */
    EtwUpdateLoggerCode = 4, /* inout WMI_LOGGER_INFORMATION */
    EtwFlushLoggerCode = 5, /* inout WMI_LOGGER_INFORMATION */
    EtwIncrementLoggerFile = 6, /* inout WMI_LOGGER_INFORMATION */
    EtwRealtimeTransition = 7, /* inout WMI_LOGGER_INFORMATION */
    /* reserved */
    EtwRealtimeConnectCode = 11,
    EtwActivityIdCreate = 12,
    EtwWdiScenarioCode = 13,
    EtwRealtimeDisconnectCode = 14, /* in HANDLE */
    EtwRegisterGuidsCode = 15,
    EtwReceiveNotification = 16,
    EtwSendDataBlock = 17, /* ETW_ENABLE_NOTIFICATION_PACKET, ETW_SESSION_NOTIFICATION_PACKET */
    EtwSendReplyDataBlock = 18,
    EtwReceiveReplyDataBlock = 19,
    EtwWdiSemUpdate = 20,
    EtwEnumTraceGuidList = 21, /* out GUID[] */
    EtwGetTraceGuidInfo = 22, /* in GUID, out ETW_TRACE_GUID_INFO */
    EtwEnumerateTraceGuids = 23, /* out TRACE_GUID_PROPERTIES[] */
    EtwRegisterSecurityProv = 24,
    EtwReferenceTimeCode = 25, /* in ULONG LoggerId, out ETW_REF_CLOCK */
    EtwTrackBinaryCode = 26, /* in HANDLE */
    EtwAddNotificationEvent = 27,
    EtwUpdateDisallowList = 28,
    EtwSetEnableAllKeywordsCode = 29,
    EtwSetProviderTraitsCode = 30,
    EtwUseDescriptorTypeCode = 31,
    EtwEnumTraceGroupList = 32,
    EtwGetTraceGroupInfo = 33,
    EtwGetDisallowList = 34,
    EtwSetCompressionSettings = 35,
    EtwGetCompressionSettings = 36,
    EtwUpdatePeriodicCaptureState = 37,
    EtwGetPrivateSessionTraceHandle = 38,
    EtwRegisterPrivateSession = 39,
    EtwQuerySessionDemuxObject = 40,
    EtwSetProviderBinaryTracking = 41,
    EtwMaxLoggers = 42, /* out ULONG */
    EtwMaxPmcCounter = 43, /* out ULONG */
    EtwQueryUsedProcessorCount = 44, /* ULONG, since WIN11 */
    EtwGetPmcOwnership = 45,
    EtwGetPmcSessions = 46,
} ETWTRACECONTROLCODE;

/* Event Information Classes */
typedef enum _EVENT_INFORMATION_CLASS
{
    EventBasicInformation
} EVENT_INFORMATION_CLASS;

/* Event Types */
typedef enum _SYSK_EVENT_TYPE {
    SysKNotificationEvent,
    SysKSynchronizationEvent,
} SYSK_EVENT_TYPE;

/* Filter Boot Option Operations */
typedef enum _FILTER_BOOT_OPTION_OPERATION {
    FilterBootOptionAdd,
    FilterBootOptionRemove,
    FilterBootOptionModify,
    FilterBootOptionQuery
} FILTER_BOOT_OPTION_OPERATION;

/* File System Information Classes */
typedef enum _SYSK_FSINFOCLASS
{
    SysKFileFsVolumeInformation = 1, /* q: FILE_FS_VOLUME_INFORMATION */
    SysKFileFsLabelInformation, /* s: FILE_FS_LABEL_INFORMATION (requires FILE_WRITE_DATA to volume) */
    SysKFileFsSizeInformation, /* q: FILE_FS_SIZE_INFORMATION */
    SysKFileFsDeviceInformation, /* q: FILE_FS_DEVICE_INFORMATION */
    SysKFileFsAttributeInformation, /* q: FILE_FS_ATTRIBUTE_INFORMATION */
    SysKFileFsControlInformation, /* q, s: FILE_FS_CONTROL_INFORMATION  (q: requires FILE_READ_DATA; s: requires FILE_WRITE_DATA to volume) */
    SysKFileFsFullSizeInformation, /* q: FILE_FS_FULL_SIZE_INFORMATION */
    SysKFileFsObjectIdInformation, /* q; s: FILE_FS_OBJECTID_INFORMATION (s: requires FILE_WRITE_DATA to volume) */
    SysKFileFsDriverPathInformation, /* q: FILE_FS_DRIVER_PATH_INFORMATION */
    SysKFileFsVolumeFlagsInformation, /* q; s: FILE_FS_VOLUME_FLAGS_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES to volume), 10 */
    SysKFileFsSectorSizeInformation, /* q: FILE_FS_SECTOR_SIZE_INFORMATION, since WIN8 */
    SysKFileFsDataCopyInformation, /* q: FILE_FS_DATA_COPY_INFORMATION */
    SysKFileFsMetadataSizeInformation, /* q: FILE_FS_METADATA_SIZE_INFORMATION, since THRESHOLD */
    SysKFileFsFullSizeInformationEx, /* q: FILE_FS_FULL_SIZE_INFORMATION_EX, since REDSTONE5 */
    SysKFileFsGuidInformation, /* q: FILE_FS_GUID_INFORMATION, since 23H2 */
    SysKFileFsMaximumInformation
} SYSK_FSINFOCLASS, * PSYSK_FSINFOCLASS;

/* IO Completion Information Classes */
typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
    IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

/* IO Session Events */
typedef enum _SYSK_IO_SESSION_EVENT
{
    SysKIoSessionEventIgnore,
    SysKIoSessionEventCreated,
    SysKIoSessionEventTerminated,
    SysKIoSessionEventConnected,
    SysKIoSessionEventDisconnected,
    SysKIoSessionEventLogon,
    SysKIoSessionEventLogoff,
    SysKIoSessionEventMax
} SYSK_IO_SESSION_EVENT;

/* IO Session States */
typedef enum _SYSK_IO_SESSION_STATE
{
    SysKIoSessionStateCreated = 1,
    SysKIoSessionStateInitialized = 2,
    SysKIoSessionStateConnected = 3,
    SysKIoSessionStateDisconnected = 4,
    SysKIoSessionStateDisconnectedLoggedOn = 5,
    SysKIoSessionStateLoggedOn = 6,
    SysKIoSessionStateLoggedOff = 7,
    SysKIoSessionStateTerminated = 8,
    SysKIoSessionStateMax
} SYSK_IO_SESSION_STATE;

/* Job Object Information Classes */

typedef enum _JOBOBJECTINFOCLASS {
    JobObjectBasicAccountingInformation = 1,
    JobObjectBasicLimitInformation = 2,
    JobObjectBasicProcessIdList = 3,
    JobObjectBasicUIRestrictions = 4,
    JobObjectSecurityLimitInformation = 5,
    JobObjectEndOfJobTimeInformation = 6,
    JobObjectAssociateCompletionPortInformation = 7,
    JobObjectBasicAndIoAccountingInformation = 8,
    JobObjectExtendedLimitInformation = 9,
    JobObjectJobSetInformation = 10,
    JobObjectGroupInformation = 11,
    JobObjectNotificationLimitInformation = 12,
    JobObjectLimitViolationInformation = 13,
    JobObjectGroupInformationEx = 14,
    JobObjectCpuRateControlInformation = 15,
    JobObjectCompletionFilter = 16,
    JobObjectCompletionCounter = 17,
    JobObjectFreezeInformation = 18,
    JobObjectExtendedAccountingInformation = 19,
    JobObjectWakeInformation = 20,
    JobObjectBackgroundInformation = 21,
    JobObjectSchedulingRankBiasInformation = 22,
    JobObjectTimerVirtualizationInformation = 23,
    JobObjectCycleTimeNotification = 24,
    JobObjectClearEvent = 25,
    JobObjectInterferenceInformation = 26,
    JobObjectClearPeakJobMemoryUsed = 27,
    JobObjectMemoryUsageInformation = 28,
    JobObjectSharedCommit = 29,
    JobObjectContainerId = 30,
    JobObjectIoRateControlInformation = 31,
    JobObjectNetRateControlInformation = 32,
    JobObjectNotificationLimitInformation2 = 33,
    JobObjectLimitViolationInformation2 = 34,
    JobObjectCreateSilo = 35,
    JobObjectSiloBasicInformation = 36,
    JobObjectReserved1 = 37,
    JobObjectReserved2 = 38,
    JobObjectReserved3 = 39,
    JobObjectReserved4 = 40,
    JobObjectReserved5 = 41,
    JobObjectReserved6 = 42,
    JobObjectReserved7 = 43,
    JobObjectReserved8 = 44,
    JobObjectReserved9 = 45,
    JobObjectReserved10 = 46,
    JobObjectReserved11 = 47,
    JobObjectReserved12 = 48,
    JobObjectReserved13 = 49,
    JobObjectReserved14 = 50,
    JobObjectNetRateControlInformation2 = 51,
    JobObjectMax = 52
} JOBOBJECTINFOCLASS;

/* Key Information Classes */
typedef enum _SYSK_KEY_INFORMATION_CLASS
{
    SysKKeyBasicInformation, /* KEY_BASIC_INFORMATION */
    SysKKeyNodeInformation, /* KEY_NODE_INFORMATION */
    SysKKeyFullInformation, /* KEY_FULL_INFORMATION */
    SysKKeyNameInformation, /* KEY_NAME_INFORMATION */
    SysKKeyCachedInformation, /* KEY_CACHED_INFORMATION */
    SysKKeyFlagsInformation, /* KEY_FLAGS_INFORMATION */
    SysKKeyVirtualizationInformation, /* KEY_VIRTUALIZATION_INFORMATION */
    SysKKeyHandleTagsInformation, /* KEY_HANDLE_TAGS_INFORMATION */
    SysKKeyTrustInformation, /* KEY_TRUST_INFORMATION */
    SysKKeyLayerInformation, /* KEY_LAYER_INFORMATION */
    SysKMaxKeyInfoClass
} SYSK_KEY_INFORMATION_CLASS;

/* Key Value Information Classes */
typedef enum _SYSK_KEY_VALUE_INFORMATION_CLASS
{
    SysKKeyValueBasicInformation, /* KEY_VALUE_BASIC_INFORMATION */
    SysKKeyValueFullInformation, /* KEY_VALUE_FULL_INFORMATION */
    SysKKeyValuePartialInformation, /* KEY_VALUE_PARTIAL_INFORMATION */
    SysKKeyValueFullInformationAlign64,
    SysKKeyValuePartialInformationAlign64,  /* KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 */
    SysKKeyValueLayerInformation, /* KEY_VALUE_LAYER_INFORMATION */
    SysKMaxKeyValueInfoClass
} SYSK_KEY_VALUE_INFORMATION_CLASS;

/* KProfile Sources */
typedef enum _SYSK_KPROFILE_SOURCE {
    SysKProfileTime,
    SysKProfileAlignmentFaults,
    SysKProfileCacheMisses,
    SysKProfileDpcTime,
    SysKProfileInterrupts,
    SysKProfileDeferredProcedureCalls,
    SysKProfileTotalCycles,
    SysKProfileUserTime,
    SysKProfileKernelTime,
    SysKProfileMaximum
} SYSK_KPROFILE_SOURCE;

/* KThread State */
typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, *PKTHREAD_STATE;

/* KWait Reason */
typedef enum _SYSK_KWAIT_REASON
{
    SysKExecutive,               /* Waiting for an executive event. */
    SysKFreePage,                /* Waiting for a free page. */
    SysKPageIn,                  /* Waiting for a page to be read in. */
    SysKPoolAllocation,          /* Waiting for a pool allocation. */
    SysKDelayExecution,          /* Waiting due to a delay execution.            NtDelayExecution */
    SysKSuspended,               /* Waiting because the thread is suspended.    NtSuspendThread */
    SysKUserRequest,             /* Waiting due to a user request.              NtWaitForSingleObject */
    SysKWrExecutive,             /* Waiting for an executive event. */
    SysKWrFreePage,              /* Waiting for a free page. */
    SysKWrPageIn,                /* Waiting for a page to be read in. */
    SysKWrPoolAllocation,        /* Waiting for a pool allocation. */
    SysKWrDelayExecution,        /* Waiting due to a delay execution. */
    SysKWrSuspended,             /* Waiting because the thread is suspended. */
    SysKWrUserRequest,           /* Waiting due to a user request. */
    SysKWrEventPair,             /* Waiting for an event pair.                  NtCreateEventPair */
    SysKWrQueue,                 /* Waiting for a queue.                        NtRemoveIoCompletion */
    SysKWrLpcReceive,            /* Waiting for an LPC receive. */
    SysKWrLpcReply,              /* Waiting for an LPC reply. */
    SysKWrVirtualMemory,         /* Waiting for virtual memory. */
    SysKWrPageOut,               /* Waiting for a page to be written out. */
    SysKWrRendezvous,            /* Waiting for a rendezvous. */
    SysKWrKeyedEvent,            /* Waiting for a keyed event.                  NtCreateKeyedEvent */
    SysKWrTerminated,            /* Waiting for thread termination. */
    SysKWrProcessInSwap,         /* Waiting for a process to be swapped in. */
    SysKWrCpuRateControl,        /* Waiting for CPU rate control. */
    SysKWrCalloutStack,          /* Waiting for a callout stack. */
    SysKWrKernel,                /* Waiting for a kernel event. */
    SysKWrResource,              /* Waiting for a resource. */
    SysKWrPushLock,              /* Waiting for a push lock. */
    SysKWrMutex,                 /* Waiting for a mutex. */
    SysKWrQuantumEnd,            /* Waiting for the end of a quantum. */
    SysKWrDispatchInt,           /* Waiting for a dispatch interrupt. */
    SysKWrPreempted,             /* Waiting because the thread was preempted. */
    SysKWrYieldExecution,        /* Waiting to yield execution. */
    SysKWrFastMutex,             /* Waiting for a fast mutex. */
    SysKWrGuardedMutex,          /* Waiting for a guarded mutex. */
    SysKWrRundown,               /* Waiting for a rundown. */
    SysKWrAlertByThreadId,       /* Waiting for an alert by thread ID. */
    SysKWrDeferredPreempt,       /* Waiting for a deferred preemption. */
    SysKWrPhysicalFault,         /* Waiting for a physical fault. */
    SysKWrIoRing,                /* Waiting for an I/O ring. */
    SysKWrMdlCache,              /* Waiting for an MDL cache. */
    SysKWrRcu,                   /* Waiting for read-copy-update (RCU) synchronization. */
    SysKMaximumWaitReason
} SYSK_KWAIT_REASON, *PSYSK_KWAIT_REASON;

/* Memory Information CLasses */
typedef enum _SYSK_MEMORY_INFORMATION_CLASS
{
    SysKMemoryBasicInformation, /* q: MEMORY_BASIC_INFORMATION */
    SysKMemoryWorkingSetInformation, /* q: MEMORY_WORKING_SET_INFORMATION */
    SysKMemoryMappedFilenameInformation, /* q: UNICODE_STRING */
    SysKMemoryRegionInformation, /* q: MEMORY_REGION_INFORMATION */
    SysKMemoryWorkingSetExInformation, /* q: MEMORY_WORKING_SET_EX_INFORMATION, since VISTA */
    SysKMemorySharedCommitInformation, /* q: MEMORY_SHARED_COMMIT_INFORMATION, since WIN8 */
    SysKMemoryImageInformation, /* q: MEMORY_IMAGE_INFORMATION */
    SysKMemoryRegionInformationEx, /* MEMORY_REGION_INFORMATION */
    SysKMemoryPrivilegedBasicInformation, /* MEMORY_BASIC_INFORMATION */
    SysKMemoryEnclaveImageInformation, /* MEMORY_ENCLAVE_IMAGE_INFORMATION, since REDSTONE3 */
    SysKMemoryBasicInformationCapped, /* 10 */
    SysKMemoryPhysicalContiguityInformation, /* MEMORY_PHYSICAL_CONTIGUITY_INFORMATION, since 20H1 */
    SysKMemoryBadInformation, /* since WIN11 */
    SysKMemoryBadInformationAllProcesses, /* since 22H1 */
    SysKMemoryImageExtensionInformation, /* MEMORY_IMAGE_EXTENSION_INFORMATION, since 24H2 */
    SysKMaxMemoryInfoClass
} SYSK_MEMORY_INFORMATION_CLASS;

/* Memory Reserve Type */
typedef enum _MEMORY_RESERVE_TYPE
{
    MemoryReserveUserApc,
    MemoryReserveIoCompletion,
    MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE;

/* Mutant Information Classes */
typedef enum _MUTANT_INFORMATION_CLASS
{
    MutantBasicInformation, /* MUTANT_BASIC_INFORMATION */
    MutantOwnerInformation /* MUTANT_OWNER_INFORMATION */
} MUTANT_INFORMATION_CLASS;

/* Partition Information Classses */
typedef enum _SYSK_PARTITION_INFORMATION_CLASS
{
    SysKSystemMemoryPartitionInformation, /* q: MEMORY_PARTITION_CONFIGURATION_INFORMATION */
    SysKSystemMemoryPartitionMoveMemory, /* s: MEMORY_PARTITION_TRANSFER_INFORMATION */
    SysKSystemMemoryPartitionAddPagefile, /* s: MEMORY_PARTITION_PAGEFILE_INFORMATION */
    SysKSystemMemoryPartitionCombineMemory, /* q; s: MEMORY_PARTITION_PAGE_COMBINE_INFORMATION */
    SysKSystemMemoryPartitionInitialAddMemory, /* q; s: MEMORY_PARTITION_INITIAL_ADD_INFORMATION */
    SysKSystemMemoryPartitionGetMemoryEvents, /* MEMORY_PARTITION_MEMORY_EVENTS_INFORMATION, since REDSTONE2 */
    SysKSystemMemoryPartitionSetAttributes,
    SysKSystemMemoryPartitionNodeInformation,
    SysKSystemMemoryPartitionCreateLargePages,
    SysKSystemMemoryPartitionDedicatedMemoryInformation,
    SysKSystemMemoryPartitionOpenDedicatedMemory, /* 10 */
    SysKSystemMemoryPartitionMemoryChargeAttributes,
    SysKSystemMemoryPartitionClearAttributes,
    SysKSystemMemoryPartitionSetMemoryThresholds, /* since WIN11 */
    SysKSystemMemoryPartitionMemoryListCommand, /* since 24H2 */
    SysKSystemMemoryPartitionMax
} SYSK_PARTITION_INFORMATION_CLASS, * SYSK_PPARTITION_INFORMATION_CLASS;

/* PlugPlay Control Classes */
typedef enum _PLUGPLAY_CONTROL_CLASS
{
    PlugPlayControlEnumerateDevice, /* PLUGPLAY_CONTROL_ENUMERATE_DEVICE_DATA */
    PlugPlayControlRegisterNewDevice, /* PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA */
    PlugPlayControlDeregisterDevice, /* PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA */
    PlugPlayControlInitializeDevice, /* PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA */
    PlugPlayControlStartDevice, /* PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA */
    PlugPlayControlUnlockDevice, /* PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA */
    PlugPlayControlQueryAndRemoveDevice, /* PLUGPLAY_CONTROL_QUERY_AND_REMOVE_DATA */
    PlugPlayControlUserResponse, /* PLUGPLAY_CONTROL_USER_RESPONSE_DATA */
    PlugPlayControlGenerateLegacyDevice, /* PLUGPLAY_CONTROL_LEGACY_DEVGEN_DATA */
    PlugPlayControlGetInterfaceDeviceList, /* PLUGPLAY_CONTROL_INTERFACE_LIST_DATA */
    PlugPlayControlProperty, /* PLUGPLAY_CONTROL_PROPERTY_DATA */
    PlugPlayControlDeviceClassAssociation, /* PLUGPLAY_CONTROL_CLASS_ASSOCIATION_DATA */
    PlugPlayControlGetRelatedDevice, /* PLUGPLAY_CONTROL_RELATED_DEVICE_DATA */
    PlugPlayControlGetInterfaceDeviceAlias, /* PLUGPLAY_CONTROL_INTERFACE_ALIAS_DATA */
    PlugPlayControlDeviceStatus, /* PLUGPLAY_CONTROL_STATUS_DATA */
    PlugPlayControlGetDeviceDepth, /* PLUGPLAY_CONTROL_DEPTH_DATA */
    PlugPlayControlQueryDeviceRelations, /* PLUGPLAY_CONTROL_DEVICE_RELATIONS_DATA */
    PlugPlayControlTargetDeviceRelation, /* PLUGPLAY_CONTROL_TARGET_RELATION_DATA */
    PlugPlayControlQueryConflictList, /* PLUGPLAY_CONTROL_CONFLICT_LIST */
    PlugPlayControlRetrieveDock, /* PLUGPLAY_CONTROL_RETRIEVE_DOCK_DATA */
    PlugPlayControlResetDevice, /* PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA */
    PlugPlayControlHaltDevice, /* PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA */
    PlugPlayControlGetBlockedDriverList, /* PLUGPLAY_CONTROL_BLOCKED_DRIVER_DATA */
    PlugPlayControlGetDeviceInterfaceEnabled, /* PLUGPLAY_CONTROL_DEVICE_INTERFACE_ENABLED */
    MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, * PPLUGPLAY_CONTROL_CLASS;

/* Port Information Classes */
typedef enum _PORT_INFORMATION_CLASS
{
    PortBasicInformation,
    PortDumpInformation
} PORT_INFORMATION_CLASS;

/* Process State Change Types */
typedef enum _PROCESS_STATE_CHANGE_TYPE
{
    ProcessStateChangeSuspend,
    ProcessStateChangeResume,
    ProcessStateChangeMax,
} PROCESS_STATE_CHANGE_TYPE, * PPROCESS_STATE_CHANGE_TYPE;

/* PS Create States */
typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, /* Debugger specified */
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

/* Section Information Classes */
typedef enum _SECTION_INFORMATION_CLASS
{
    SectionBasicInformation, /* q; SECTION_BASIC_INFORMATION */
    SectionImageInformation, /* q; SECTION_IMAGE_INFORMATION */
    SectionRelocationInformation, /* q; ULONG_PTR RelocationDelta, name:wow64:whNtQuerySection_SectionRelocationInformation, since WIN7 */
    SectionOriginalBaseInformation, /* q; PVOID BaseAddress, since REDSTONE */
    SectionInternalImageInformation, /* SECTION_INTERNAL_IMAGE_INFORMATION, since REDSTONE2 */
    MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

/* Section Inherit */
typedef enum _SYSK_SECTION_INHERIT
{
    SysKViewShare = 1,
    SysKViewUnmap = 2
} SYSK_SECTION_INHERIT;

/* Secure Setting Value Types */
typedef enum _SECURE_SETTING_VALUE_TYPE
{
    SecureSettingValueTypeBoolean = 0,
    SecureSettingValueTypeUlong = 1,
    SecureSettingValueTypeBinary = 2,
    SecureSettingValueTypeString = 3,
    SecureSettingValueTypeUnknown = 4
} SECURE_SETTING_VALUE_TYPE, * PSECURE_SETTING_VALUE_TYPE;

/* Semaphore Information Classes */
typedef enum _SEMAPHORE_INFORMATION_CLASS
{
    SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

/* Shutdown Actions */
typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff,
    ShutdownRebootForRecovery /* since WIN11 */
} SHUTDOWN_ACTION;

/* Symbolic Link Info Classes */
typedef enum _SYMBOLIC_LINK_INFO_CLASS
{
    SymbolicLinkGlobalInformation = 1, /* s: ULONG */
    SymbolicLinkAccessMask, /* s: ACCESS_MASK */
    MaxnSymbolicLinkInfoClass
} SYMBOLIC_LINK_INFO_CLASS;

/* SYSDBG Commands */
typedef enum _SYSDBG_COMMAND
{
    SysDbgQueryModuleInformation,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall, /* PVOID */
    SysDbgClearSpecialCalls, /* void */
    SysDbgQuerySpecialCalls,
    SysDbgBreakPoint,
    SysDbgQueryVersion, /* DBGKD_GET_VERSION64 */
    SysDbgReadVirtual, /* SYSDBG_VIRTUAL */
    SysDbgWriteVirtual, /* SYSDBG_VIRTUAL */
    SysDbgReadPhysical, /* SYSDBG_PHYSICAL, 10 */
    SysDbgWritePhysical, /* SYSDBG_PHYSICAL */
    SysDbgReadControlSpace, /* SYSDBG_CONTROL_SPACE */
    SysDbgWriteControlSpace, /* SYSDBG_CONTROL_SPACE */
    SysDbgReadIoSpace, /* SYSDBG_IO_SPACE */
    SysDbgWriteIoSpace, /* SYSDBG_IO_SPACE */
    SysDbgReadMsr, /* SYSDBG_MSR */
    SysDbgWriteMsr, /* SYSDBG_MSR */
    SysDbgReadBusData, /* SYSDBG_BUS_DATA */
    SysDbgWriteBusData, /* SYSDBG_BUS_DATA */
    SysDbgCheckLowMemory, /* 20 */
    SysDbgEnableKernelDebugger,
    SysDbgDisableKernelDebugger,
    SysDbgGetAutoKdEnable,
    SysDbgSetAutoKdEnable,
    SysDbgGetPrintBufferSize,
    SysDbgSetPrintBufferSize,
    SysDbgGetKdUmExceptionEnable,
    SysDbgSetKdUmExceptionEnable,
    SysDbgGetTriageDump, /* SYSDBG_TRIAGE_DUMP */
    SysDbgGetKdBlockEnable, /* 30 */
    SysDbgSetKdBlockEnable,
    SysDbgRegisterForUmBreakInfo,
    SysDbgGetUmBreakPid,
    SysDbgClearUmBreakPid,
    SysDbgGetUmAttachPid,
    SysDbgClearUmAttachPid,
    SysDbgGetLiveKernelDump, /* SYSDBG_LIVEDUMP_CONTROL */
    SysDbgKdPullRemoteFile, /* SYSDBG_KD_PULL_REMOTE_FILE */
    SysDbgMaxInfoClass
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;

/* System Information Classes */
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, /* q: SYSTEM_BASIC_INFORMATION */
    SystemProcessorInformation, /* q: SYSTEM_PROCESSOR_INFORMATION */
    SystemPerformanceInformation, /* q: SYSTEM_PERFORMANCE_INFORMATION */
    SystemTimeOfDayInformation, /* q: SYSTEM_TIMEOFDAY_INFORMATION */
    SystemPathInformation, /* not implemented */
    SystemProcessInformation, /* q: SYSTEM_PROCESS_INFORMATION */
    SystemCallCountInformation, /* q: SYSTEM_CALL_COUNT_INFORMATION */
    SystemDeviceInformation, /* q: SYSTEM_DEVICE_INFORMATION */
    SystemProcessorPerformanceInformation, /* q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup) */
    SystemFlagsInformation, /* q: SYSTEM_FLAGS_INFORMATION */
    SystemCallTimeInformation, /* not implemented, SYSTEM_CALL_TIME_INFORMATION, 10 */
    SystemModuleInformation, /* q: RTL_PROCESS_MODULES */
    SystemLocksInformation, /* q: RTL_PROCESS_LOCKS */
    SystemStackTraceInformation, /* q: RTL_PROCESS_BACKTRACES */
    SystemPagedPoolInformation, /* not implemented */
    SystemNonPagedPoolInformation, /* not implemented */
    SystemHandleInformation, /* q: SYSTEM_HANDLE_INFORMATION */
    SystemObjectInformation, /* q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION */
    SystemPageFileInformation, /* q: SYSTEM_PAGEFILE_INFORMATION */
    SystemVdmInstemulInformation, /* q: SYSTEM_VDM_INSTEMUL_INFO */
    SystemVdmBopInformation, /* not implemented, 20 */
    SystemFileCacheInformation, /* q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache) */
    SystemPoolTagInformation, /* q: SYSTEM_POOLTAG_INFORMATION */
    SystemInterruptInformation, /* q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup) */
    SystemDpcBehaviorInformation, /* q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege) */
    SystemFullMemoryInformation, /* not implemented, SYSTEM_MEMORY_USAGE_INFORMATION */
    SystemLoadGdiDriverInformation, /* s (kernel-mode only) */
    SystemUnloadGdiDriverInformation, /* s (kernel-mode only) */
    SystemTimeAdjustmentInformation, /* q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege) */
    SystemSummaryMemoryInformation, /* not implemented, SYSTEM_MEMORY_USAGE_INFORMATION */
    SystemMirrorMemoryInformation, /* s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege), 30 */
    SystemPerformanceTraceInformation, /* q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS) */
    SystemObsolete0, /* not implemented */
    SystemExceptionInformation, /* q: SYSTEM_EXCEPTION_INFORMATION */
    SystemCrashDumpStateInformation, /* s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege) */
    SystemKernelDebuggerInformation, /* q: SYSTEM_KERNEL_DEBUGGER_INFORMATION */
    SystemContextSwitchInformation, /* q: SYSTEM_CONTEXT_SWITCH_INFORMATION */
    SystemRegistryQuotaInformation, /* q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege) */
    SystemExtendServiceTableInformation, /* s (requires SeLoadDriverPrivilege), loads win32k only */
    SystemPrioritySeparation, /* s (requires SeTcbPrivilege) */
    SystemVerifierAddDriverInformation, /* s: UNICODE_STRING (requires SeDebugPrivilege), 40 */
    SystemVerifierRemoveDriverInformation, /* s: UNICODE_STRING (requires SeDebugPrivilege) */
    SystemProcessorIdleInformation, /* q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX: USHORT ProcessorGroup) */
    SystemLegacyDriverInformation, /* q: SYSTEM_LEGACY_DRIVER_INFORMATION */
    SystemCurrentTimeZoneInformation, /* q; s: RTL_TIME_ZONE_INFORMATION */
    SystemLookasideInformation, /* q: SYSTEM_LOOKASIDE_INFORMATION */
    SystemTimeSlipNotification, /* s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege) */
    SystemSessionCreate, /* not implemented */
    SystemSessionDetach, /* not implemented */
    SystemSessionInformation, /* not implemented (SYSTEM_SESSION_INFORMATION) */
    SystemRangeStartInformation, /* q: SYSTEM_RANGE_START_INFORMATION, 50 */
    SystemVerifierInformation, /* q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege) */
    SystemVerifierThunkExtend, /* s (kernel-mode only) */
    SystemSessionProcessInformation, /* q: SYSTEM_SESSION_PROCESS_INFORMATION */
    SystemLoadGdiDriverInSystemSpace, /* s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation) */
    SystemNumaProcessorMap, /* q: SYSTEM_NUMA_INFORMATION */
    SystemPrefetcherInformation, /* q; s: PREFETCHER_INFORMATION, PfSnQueryPrefetcherInformation */
    SystemExtendedProcessInformation, /* q: SYSTEM_EXTENDED_PROCESS_INFORMATION */
    SystemRecommendedSharedDataAlignment, /* q: ULONG, KeGetRecommendedSharedDataAlignment */
    SystemComPlusPackage, /* q; s: ULONG */
    SystemNumaAvailableMemory, /* q: SYSTEM_NUMA_INFORMATION, 60 */
    SystemProcessorPowerInformation, /* q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup) */
    SystemEmulationBasicInformation, /* q: SYSTEM_BASIC_INFORMATION */
    SystemEmulationProcessorInformation, /* q: SYSTEM_PROCESSOR_INFORMATION */
    SystemExtendedHandleInformation, /* q: SYSTEM_HANDLE_INFORMATION_EX */
    SystemLostDelayedWriteInformation, /* q: ULONG */
    SystemBigPoolInformation, /* q: SYSTEM_BIGPOOL_INFORMATION */
    SystemSessionPoolTagInformation, /* q: SYSTEM_SESSION_POOLTAG_INFORMATION */
    SystemSessionMappedViewInformation, /* q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION */
    SystemHotpatchInformation, /* q; s: SYSTEM_HOTPATCH_CODE_INFORMATION */
    SystemObjectSecurityMode, /* q: ULONG, 70 */
    SystemWatchdogTimerHandler, /* s: SYSTEM_WATCHDOG_HANDLER_INFORMATION, (kernel-mode only) */
    SystemWatchdogTimerInformation, /* q: SYSTEM_WATCHDOG_TIMER_INFORMATION, NtQuerySystemInformationEx, (kernel-mode only) */
    SystemLogicalProcessorInformation, /* q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup), NtQuerySystemInformationEx */
    SystemWow64SharedInformationObsolete, /* not implemented */
    SystemRegisterFirmwareTableInformationHandler, /* s: SYSTEM_FIRMWARE_TABLE_HANDLER, (kernel-mode only) */
    SystemFirmwareTableInformation, /* SYSTEM_FIRMWARE_TABLE_INFORMATION */
    SystemModuleInformationEx, /* q: RTL_PROCESS_MODULE_INFORMATION_EX, since VISTA */
    SystemVerifierTriageInformation, /* not implemented */
    SystemSuperfetchInformation, /* q; s: SUPERFETCH_INFORMATION, PfQuerySuperfetchInformation */
    SystemMemoryListInformation, /* q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege), 80 */
    SystemFileCacheInformationEx, /* q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation) */
    SystemThreadPriorityClientIdInformation, /* s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege), NtQuerySystemInformationEx */
    SystemProcessorIdleCycleTimeInformation, /* q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup), NtQuerySystemInformationEx */
    SystemVerifierCancellationInformation, /* SYSTEM_VERIFIER_CANCELLATION_INFORMATION, name:wow64:whNT32QuerySystemVerifierCancellationInformation */
    SystemProcessorPowerInformationEx, /* not implemented */
    SystemRefTraceInformation, /* q; s: SYSTEM_REF_TRACE_INFORMATION, ObQueryRefTraceInformation */
    SystemSpecialPoolInformation, /* q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege), MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0 */
    SystemProcessIdInformation, /* q: SYSTEM_PROCESS_ID_INFORMATION */
    SystemErrorPortInformation, /* s (requires SeTcbPrivilege) */
    SystemBootEnvironmentInformation, /* q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION, 90 */
    SystemHypervisorInformation, /* q: SYSTEM_HYPERVISOR_QUERY_INFORMATION */
    SystemVerifierInformationEx, /* q; s: SYSTEM_VERIFIER_INFORMATION_EX */
    SystemTimeZoneInformation, /* q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege) */
    SystemImageFileExecutionOptionsInformation, /* s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege) */
    SystemCoverageInformation, /* q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST, ExpCovQueryInformation (requires SeDebugPrivilege) */
    SystemPrefetchPatchInformation, /* SYSTEM_PREFETCH_PATCH_INFORMATION */
    SystemVerifierFaultsInformation, /* s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege) */
    SystemSystemPartitionInformation, /* q: SYSTEM_SYSTEM_PARTITION_INFORMATION */
    SystemSystemDiskInformation, /* q: SYSTEM_SYSTEM_DISK_INFORMATION */
    SystemProcessorPerformanceDistribution, /* q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) NtQuerySystemInformationEx, 100 */
    SystemNumaProximityNodeInformation, /* q; s: SYSTEM_NUMA_PROXIMITY_MAP */
    SystemDynamicTimeZoneInformation, /* q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege) */
    SystemCodeIntegrityInformation, /* q: SYSTEM_CODEINTEGRITY_INFORMATION, SeCodeIntegrityQueryInformation */
    SystemProcessorMicrocodeUpdateInformation, /* s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION */
    SystemProcessorBrandString, /* q: CHAR[], HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23 */
    SystemVirtualAddressInformation, /* q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege), MmQuerySystemVaInformation */
    SystemLogicalProcessorAndGroupInformation, /* q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) since WIN7 NtQuerySystemInformationEx KeQueryLogicalProcessorRelationship */
    SystemProcessorCycleTimeInformation, /* q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup), NtQuerySystemInformationEx */
    SystemStoreInformation, /* q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege), SmQueryStoreInformation */
    SystemRegistryAppendString, /* s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS, 110 */
    SystemAitSamplingValue, /* s: ULONG (requires SeProfileSingleProcessPrivilege) */
    SystemVhdBootInformation, /* q: SYSTEM_VHD_BOOT_INFORMATION */
    SystemCpuQuotaInformation, /* q; s: PS_CPU_QUOTA_QUERY_INFORMATION */
    SystemNativeBasicInformation, /* q: SYSTEM_BASIC_INFORMATION */
    SystemErrorPortTimeouts, /* SYSTEM_ERROR_PORT_TIMEOUTS */
    SystemLowPriorityIoInformation, /* q: SYSTEM_LOW_PRIORITY_IO_INFORMATION */
    SystemTpmBootEntropyInformation, /* q: BOOT_ENTROPY_NT_RESULT, ExQueryBootEntropyInformation */
    SystemVerifierCountersInformation, /* q: SYSTEM_VERIFIER_COUNTERS_INFORMATION */
    SystemPagedPoolInformationEx, /* q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool) */
    SystemSystemPtesInformationEx, /* q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) 120 */
    SystemNodeDistanceInformation, /* q: USHORT[4*NumaNodes] (EX in: USHORT NodeNumber) NtQuerySystemInformationEx */
    SystemAcpiAuditInformation, /* q: SYSTEM_ACPI_AUDIT_INFORMATION, HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26 */
    SystemBasicPerformanceInformation, /* q: SYSTEM_BASIC_PERFORMANCE_INFORMATION, name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation */
    SystemQueryPerformanceCounterInformation, /* q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION, since WIN7 SP1 */
    SystemSessionBigPoolInformation, /* q: SYSTEM_SESSION_POOLTAG_INFORMATION, since WIN8 */
    SystemBootGraphicsInformation, /* q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only) */
    SystemScrubPhysicalMemoryInformation, /* q; s: MEMORY_SCRUB_INFORMATION */
    SystemBadPageInformation, /* SYSTEM_BAD_PAGE_INFORMATION */
    SystemProcessorProfileControlArea, /* q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA */
    SystemCombinePhysicalMemoryInformation, /* s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2, 130 */
    SystemEntropyInterruptTimingInformation, /* q; s: SYSTEM_ENTROPY_TIMING_INFORMATION */
    SystemConsoleInformation, /* q; s: SYSTEM_CONSOLE_INFORMATION */
    SystemPlatformBinaryInformation, /* q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege) */
    SystemPolicyInformation, /* q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute) */
    SystemHypervisorProcessorCountInformation, /* q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION */
    SystemDeviceDataInformation, /* q: SYSTEM_DEVICE_DATA_INFORMATION */
    SystemDeviceDataEnumerationInformation, /* q: SYSTEM_DEVICE_DATA_INFORMATION */
    SystemMemoryTopologyInformation, /* q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION */
    SystemMemoryChannelInformation, /* q: SYSTEM_MEMORY_CHANNEL_INFORMATION */
    SystemBootLogoInformation, /* q: SYSTEM_BOOT_LOGO_INFORMATION, 140 */
    SystemProcessorPerformanceInformationEx, /* q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX (EX in: USHORT ProcessorGroup) NtQuerySystemInformationEx since WINBLUE */
    SystemCriticalProcessErrorLogInformation, /* CRITICAL_PROCESS_EXCEPTION_DATA */
    SystemSecureBootPolicyInformation, /* q: SYSTEM_SECUREBOOT_POLICY_INFORMATION */
    SystemPageFileInformationEx, /* q: SYSTEM_PAGEFILE_INFORMATION_EX */
    SystemSecureBootInformation, /* q: SYSTEM_SECUREBOOT_INFORMATION */
    SystemEntropyInterruptTimingRawInformation, /* q; s: SYSTEM_ENTROPY_TIMING_INFORMATION */
    SystemPortableWorkspaceEfiLauncherInformation, /* q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION */
    SystemFullProcessInformation, /* q: SYSTEM_EXTENDED_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin) */
    SystemKernelDebuggerInformationEx, /* q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX */
    SystemBootMetadataInformation, /* 150 (requires SeTcbPrivilege) */
    SystemSoftRebootInformation, /* q: ULONG */
    SystemElamCertificateInformation, /* s: SYSTEM_ELAM_CERTIFICATE_INFORMATION */
    SystemOfflineDumpConfigInformation, /* q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2 */
    SystemProcessorFeaturesInformation, /* q: SYSTEM_PROCESSOR_FEATURES_INFORMATION */
    SystemRegistryReconciliationInformation, /* s: NULL (requires admin) (flushes registry hives) */
    SystemEdidInformation, /* q: SYSTEM_EDID_INFORMATION */
    SystemManufacturingInformation, /* q: SYSTEM_MANUFACTURING_INFORMATION since THRESHOLD */
    SystemEnergyEstimationConfigInformation, /* q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION */
    SystemHypervisorDetailInformation, /* q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION */
    SystemProcessorCycleStatsInformation, /* q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) NtQuerySystemInformationEx, 160 */
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation, /* q: SYSTEM_TPM_INFORMATION */
    SystemKernelDebuggerFlags, /* SYSTEM_KERNEL_DEBUGGER_FLAGS */
    SystemCodeIntegrityPolicyInformation, /* q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION */
    SystemIsolatedUserModeInformation, /* q: SYSTEM_ISOLATED_USER_MODE_INFORMATION */
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation, /* q: SYSTEM_SINGLE_MODULE_INFORMATION */
    SystemAllowedCpuSetsInformation, /* s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION */
    SystemVsmProtectionInformation, /* q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation) */
    SystemInterruptCpuSetsInformation, /* q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION, 170 */
    SystemSecureBootPolicyFullInformation, /* q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION */
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation, /* q: KAFFINITY_EX (requires SeIncreaseBasePriorityPrivilege) */
    SystemRootSiloInformation, /* q: SYSTEM_ROOT_SILO_INFORMATION */
    SystemCpuSetInformation, /* q: SYSTEM_CPU_SET_INFORMATION since THRESHOLD2 */
    SystemCpuSetTagInformation, /* q: SYSTEM_CPU_SET_TAG_INFORMATION */
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation, /* q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION */
    SystemCodeIntegrityPlatformManifestInformation, /* q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION NtQuerySystemInformationEx since REDSTONE */
    SystemInterruptSteeringInformation, /* q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT NtQuerySystemInformationEx, 180 */
    SystemSupportedProcessorArchitectures, /* p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] NtQuerySystemInformationEx */
    SystemMemoryUsageInformation, /* q: SYSTEM_MEMORY_USAGE_INFORMATION */
    SystemCodeIntegrityCertificateInformation, /* q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION */
    SystemPhysicalMemoryInformation, /* q: SYSTEM_PHYSICAL_MEMORY_INFORMATION since REDSTONE2 */
    SystemControlFlowTransition, /* (Warbird/Encrypt/Decrypt/Execute) */
    SystemKernelDebuggingAllowed, /* s: ULONG */
    SystemActivityModerationExeState, /* s: SYSTEM_ACTIVITY_MODERATION_EXE_STATE */
    SystemActivityModerationUserSettings, /* q: SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS */
    SystemCodeIntegrityPoliciesFullInformation, /* NtQuerySystemInformationEx */
    SystemCodeIntegrityUnlockInformation, /* SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION, 190 */
    SystemIntegrityQuotaInformation,
    SystemFlushInformation, /* q: SYSTEM_FLUSH_INFORMATION */
    SystemProcessorIdleMaskInformation, /* q: ULONG_PTR[ActiveGroupCount] since REDSTONE3 */
    SystemSecureDumpEncryptionInformation, /* NtQuerySystemInformationEx */
    SystemWriteConstraintInformation, /* SYSTEM_WRITE_CONSTRAINT_INFORMATION */
    SystemKernelVaShadowInformation, /* SYSTEM_KERNEL_VA_SHADOW_INFORMATION */
    SystemHypervisorSharedPageInformation, /* SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION since REDSTONE4 */
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation, /* SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION */
    SystemFirmwarePartitionInformation, /* SYSTEM_FIRMWARE_PARTITION_INFORMATION, 200 */
    SystemSpeculationControlInformation, /* SYSTEM_SPECULATION_CONTROL_INFORMATION (CVE-2017-5715) REDSTONE3 and above. */
    SystemDmaGuardPolicyInformation, /* SYSTEM_DMA_GUARD_POLICY_INFORMATION */
    SystemEnclaveLaunchControlInformation, /* SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION */
    SystemWorkloadAllowedCpuSetsInformation, /* SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION since REDSTONE5 */
    SystemCodeIntegrityUnlockModeInformation, /* SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION */
    SystemLeapSecondInformation, /* SYSTEM_LEAP_SECOND_INFORMATION */
    SystemFlags2Information, /* q: SYSTEM_FLAGS_INFORMATION */
    SystemSecurityModelInformation, /* SYSTEM_SECURITY_MODEL_INFORMATION since 19H1 */
    SystemCodeIntegritySyntheticCacheInformation, /* NtQuerySystemInformationEx */
    SystemFeatureConfigurationInformation, /* q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE NtQuerySystemInformationEx since 20H1, 210 */
    SystemFeatureConfigurationSectionInformation, /* q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION NtQuerySystemInformationEx */
    SystemFeatureUsageSubscriptionInformation, /* q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE */
    SystemSecureSpeculationControlInformation, /* SECURE_SPECULATION_CONTROL_INFORMATION */
    SystemSpacesBootInformation, /* since 20H2 */
    SystemFwRamdiskInformation, /* SYSTEM_FIRMWARE_RAMDISK_INFORMATION */
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation, /* s: SYSTEM_DIF_VOLATILE_INFORMATION (requires SeDebugPrivilege) */
    SystemDifClearRuleClassInformation, /* s: NULL (requires SeDebugPrivilege) */
    SystemDifApplyPluginVerificationOnDriver, /* SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege) */
    SystemDifRemovePluginVerificationOnDriver, /* SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege) 220 */
    SystemShadowStackInformation, /* SYSTEM_SHADOW_STACK_INFORMATION */
    SystemBuildVersionInformation, /* q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION NtQuerySystemInformationEx, 222 */
    SystemPoolLimitInformation, /* SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege) NtQuerySystemInformationEx */
    SystemCodeIntegrityAddDynamicStore, /* CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners */
    SystemCodeIntegrityClearDynamicStores, /* CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners */
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation, /* q: SYSTEM_POOL_ZEROING_INFORMATION */
    SystemDpcWatchdogInformation, /* q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION */
    SystemDpcWatchdogInformation2, /* q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2 */
    SystemSupportedProcessorArchitectures2, /* q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] NtQuerySystemInformationEx, 230 */
    SystemSingleProcessorRelationshipInformation, /* q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: PROCESSOR_NUMBER Processor) NtQuerySystemInformationEx */
    SystemXfgCheckFailureInformation, /* q: SYSTEM_XFG_FAILURE_INFORMATION */
    SystemIommuStateInformation, /* SYSTEM_IOMMU_STATE_INFORMATION since 22H1 */
    SystemHypervisorMinrootInformation, /* SYSTEM_HYPERVISOR_MINROOT_INFORMATION */
    SystemHypervisorBootPagesInformation, /* SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION */
    SystemPointerAuthInformation, /* SYSTEM_POINTER_AUTH_INFORMATION */
    SystemSecureKernelDebuggerInformation, /* NtQuerySystemInformationEx */
    SystemOriginalImageFeatureInformation, /* q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT NtQuerySystemInformationEx */
    SystemMemoryNumaInformation, /* SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT NtQuerySystemInformationEx */
    SystemMemoryNumaPerformanceInformation, /* SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUTSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT since 24H2, 240 */
    SystemCodeIntegritySignedPoliciesFullInformation,
    SystemSecureCoreInformation, /* SystemSecureSecretsInformation */
    SystemTrustedAppsRuntimeInformation, /* SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION */
    SystemBadPageInformationEx, /* SYSTEM_BAD_PAGE_INFORMATION */
    SystemResourceDeadlockTimeout, /* ULONG */
    SystemBreakOnContextUnwindFailureInformation, /* ULONG (requires SeDebugPrivilege) */
    SystemOslRamdiskInformation, /* SYSTEM_OSL_RAMDISK_INFORMATION */
    SystemCodeIntegrityPolicyManagementInformation, /* SYSTEM_CODEINTEGRITYPOLICY_MANAGEMENT since 25H2 */
    SystemMemoryNumaCacheInformation,
    SystemProcessorFeaturesBitMapInformation, /* 250 */
    SystemRefTraceInformationEx, /* SYSTEM_REF_TRACE_INFORMATION_EX */
    SystemBasicProcessInformation, /* SYSTEM_BASICPROCESS_INFORMATION */
    SystemHandleCountInformation, /* SYSTEM_HANDLECOUNT_INFORMATION */
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

/* Thread State Change Types */
typedef enum _THREAD_STATE_CHANGE_TYPE
{
    ThreadStateChangeSuspend,
    ThreadStateChangeResume,
    ThreadStateChangeMax,
} THREAD_STATE_CHANGE_TYPE, * PTHREAD_STATE_CHANGE_TYPE;

/* Timer Information Classes */
typedef enum _TIMER_INFORMATION_CLASS
{
    TimerBasicInformation /* TIMER_BASIC_INFORMATION */
} TIMER_INFORMATION_CLASS;

/* Timer Set Information Classes */
typedef enum _SYSK_TIMER_SET_INFORMATION_CLASS
{
    SysKTimerSetCoalescableTimer, /* TIMER_SET_COALESCABLE_TIMER_INFO */
    SysKMaxTimerInfoClass
} SYSK_TIMER_SET_INFORMATION_CLASS;

/* Timer Types */
typedef enum _SYSK_TIMER_TYPE {
    SysKTimerNotification,
    SysKTimerSynchronization
} SYSK_TIMER_TYPE;

/* VDM Service Classes */
typedef enum _VDMSERVICECLASS
{
    VdmStartExecution,
    VdmQueueInterrupt,
    VdmDelayInterrupt,
    VdmInitialize,
    VdmFeatures,
    VdmSetInt21Handler,
    VdmQueryDir,
    VdmPrinterDirectIoOpen,
    VdmPrinterDirectIoClose,
    VdmPrinterInitialize,
    VdmSetLdtEntries,
    VdmSetProcessLdtInfo,
    VdmAdlibEmulation,
    VdmPMCliControl,
    VdmQueryVdmProcess,
    VdmPreInitialize
} VDMSERVICECLASS, * PVDMSERVICECLASS;

/* Virtual Memory Information Classes */
typedef enum _SYSK_VIRTUAL_MEMORY_INFORMATION_CLASS
{
    SysKVmPrefetchInformation, /* MEMORY_PREFETCH_INFORMATION */
    SysKVmPagePriorityInformation, /* MEMORY_PAGE_PRIORITY_INFORMATION */
    SysKVmCfgCallTargetInformation, /* CFG_CALL_TARGET_LIST_INFORMATION REDSTONE2 */
    SysKVmPageDirtyStateInformation, /* REDSTONE3 */
    SysKVmImageHotPatchInformation, /* 19H1 */
    SysKVmPhysicalContiguityInformation, /* 20H1 */
    SysKVmVirtualMachinePrepopulateInformation,
    SysKVmRemoveFromWorkingSetInformation,
    SysKMaxVmInfoClass
} SYSK_VIRTUAL_MEMORY_INFORMATION_CLASS;

/* Wait Types */
typedef enum _SYSK_WAIT_TYPE
{
    SysKWaitAll,
    SysKWaitAny,
    SysKWaitNotification,
    SysKWaitDequeue,
    SysKWaitDpc,
} SYSK_WAIT_TYPE;

/* WNF Data Scope */
typedef enum _WNF_DATA_SCOPE
{
    WnfDataScopeSystem,
    WnfDataScopeSession,
    WnfDataScopeUser,
    WnfDataScopeProcess,
    WnfDataScopeMachine, /* REDSTONE3 */
    WnfDataScopePhysicalMachine, /* WIN11 */
} WNF_DATA_SCOPE;

/* WNF State Name Information */
typedef enum _WNF_STATE_NAME_INFORMATION
{
    WnfInfoStateNameExist,
    WnfInfoSubscribersPresent,
    WnfInfoIsQuiescent
} WNF_STATE_NAME_INFORMATION;

/* WNF State Name Lifetime */
typedef enum _WNF_STATE_NAME_LIFETIME
{
    WnfWellKnownStateName,
    WnfPermanentStateName,
    WnfPersistentStateName,
    WnfTemporaryStateName
} WNF_STATE_NAME_LIFETIME;

/* Worker Factory Information Classes */
typedef enum _WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout, /* LARGE_INTEGER */
    WorkerFactoryRetryTimeout, /* LARGE_INTEGER */
    WorkerFactoryIdleTimeout, /* s: LARGE_INTEGER */
    WorkerFactoryBindingCount, /* s: ULONG */
    WorkerFactoryThreadMinimum, /* s: ULONG */
    WorkerFactoryThreadMaximum, /* s: ULONG */
    WorkerFactoryPaused, /* ULONG or BOOLEAN */
    WorkerFactoryBasicInformation, /* q: WORKER_FACTORY_BASIC_INFORMATION */
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation, /* 10 */
    WorkerFactoryThreadBasePriority, /* s: ULONG */
    WorkerFactoryTimeoutWaiters, /* s: ULONG, since THRESHOLD */
    WorkerFactoryFlags, /* s: ULONG */
    WorkerFactoryThreadSoftMaximum, /* s: ULONG */
    WorkerFactoryThreadCpuSets, /* since REDSTONE5 */
    MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, * PWORKERFACTORYINFOCLASS;