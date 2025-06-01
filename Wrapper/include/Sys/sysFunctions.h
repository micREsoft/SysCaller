#pragma once
#include "../syscaller.h"
#include "sysTypes.h"
#include "sysExternals.h"

#ifdef _WIN64 // Only compile on 64bit systems.

extern "C" NTSTATUS SCAcceptConnectPort(
    PHANDLE PortHandle,
    PVOID PortContext OPTIONAL,
    PPORT_MESSAGE ConnectionRequest,
    BOOLEAN AcceptConnection,
    PPORT_VIEW ServerView OPTIONAL,
    PREMOTE_PORT_VIEW ClientView OPTIONAL
);

extern "C" NTSTATUS SCAccessCheck(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus
);

extern "C" NTSTATUS SCAccessCheckAndAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping,
    BOOLEAN ObjectCreation,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus,
    PBOOLEAN GenerateOnClose
);

extern "C" NTSTATUS SCAccessCheckByType(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus
);

extern "C" NTSTATUS SCAccessCheckByTypeAndAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid OPTIONAL,
    ACCESS_MASK DesiredAccess,
    AUDIT_EVENT_TYPE AuditType,
    ULONG Flags,
    POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    BOOLEAN ObjectCreation,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus,
    PBOOLEAN GenerateOnClose
);

extern "C" NTSTATUS SCAccessCheckByTypeResultList(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus
);

extern "C" NTSTATUS SCAccessCheckByTypeResultListAndAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid OPTIONAL,
    ACCESS_MASK DesiredAccess,
    AUDIT_EVENT_TYPE AuditType,
    ULONG Flags,
    POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    BOOLEAN ObjectCreation,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus,
    PBOOLEAN GenerateOnClose
);

extern "C" NTSTATUS SCAccessCheckByTypeResultListAndAuditAlarmByHandle(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    BOOLEAN ObjectCreation,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus,
    PBOOLEAN GenerateOnClose,
    AUDIT_EVENT_HANDLE AuditHandle OPTIONAL
);

extern "C" NTSTATUS SCAcquireCrossVmMutant(
    HANDLE CrossVmMutant,
    PLARGE_INTEGER Timeout
);

extern "C" NTSTATUS SCAcquireProcessActivityReference(
    PHANDLE ActivityReferenceHandle,
    HANDLE ParentProcessHandle,
    PROCESS_ACTIVITY_TYPE Reserved
);

extern "C" NTSTATUS SCAddAtom(
    PCWSTR AtomName OPTIONAL,
    ULONG Length,
    PRTL_ATOM Atom OPTIONAL
);

extern "C" NTSTATUS SCAddAtomEx(
    PCWSTR AtomName OPTIONAL,
    ULONG Length,
    PRTL_ATOM Atom OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SCAddBootEntry(
    PBOOT_ENTRY BootEntry,
    PULONG Id OPTIONAL
);

extern "C" NTSTATUS SCAddDriverEntry(
    PEFI_DRIVER_ENTRY DriverEntry,
    PULONG Id OPTIONAL
);

extern "C" NTSTATUS SCAdjustGroupsToken(
    HANDLE TokenHandle,
    BOOLEAN ResetToDefault,
    PTOKEN_GROUPS NewState OPTIONAL,
    ULONG BufferLength OPTIONAL,
    PTOKEN_GROUPS PreviousState OPTIONAL,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState OPTIONAL,
    ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState OPTIONAL,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCAdjustTokenClaimsAndDeviceGroups(
    HANDLE TokenHandle,
    BOOLEAN UserResetToDefault,
    BOOLEAN DeviceResetToDefault,
    BOOLEAN DeviceGroupsResetToDefault,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState OPTIONAL,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState OPTIONAL,
    PTOKEN_GROUPS NewDeviceGroupsState OPTIONAL,
    ULONG UserBufferLength,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState OPTIONAL,
    ULONG DeviceBufferLength,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState OPTIONAL,
    ULONG DeviceGroupsBufferLength,
    PTOKEN_GROUPS PreviousDeviceGroups OPTIONAL,
    PULONG UserReturnLength OPTIONAL,
    PULONG DeviceReturnLength OPTIONAL,
    PULONG DeviceGroupsReturnBufferLength OPTIONAL
);

extern "C" NTSTATUS SCAlertResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount OPTIONAL
);

extern "C" NTSTATUS SCAlertThread(
    HANDLE ThreadHandle
);

extern "C" NTSTATUS SCAlertThreadByThreadId(
    HANDLE ThreadId
);

extern "C" NTSTATUS SCAllocateLocallyUniqueId(
    PLUID Luid
);

extern "C" NTSTATUS SCAllocateReserveObject(
    PHANDLE MemoryReserveHandle,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    MEMORY_RESERVE_TYPE Type
);

extern "C" NTSTATUS SCAllocateUserPhysicalPages(
    HANDLE ProcessHandle,
    PSIZE_T NumberOfPages,
    PULONG_PTR UserPfnArray
);

extern "C" NTSTATUS SCAllocateUserPhysicalPagesEx(
    HANDLE ProcessHandle,
    PULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray,
    PMEM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount
);

extern "C" NTSTATUS SCAllocateUuids(
    PULARGE_INTEGER Time,
    PULONG Range,
    PULONG Sequence,
    PCHAR Seed
);

extern "C" NTSTATUS SCAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
);

extern "C" NTSTATUS SCAllocateVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount
);

extern "C" NTSTATUS SCAlpcAcceptConnectPort(
    PHANDLE PortHandle,
    HANDLE ConnectionPortHandle,
    ULONG Flags,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
    PVOID PortContext OPTIONAL,
    PPORT_MESSAGE ConnectionRequest,
    PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes OPTIONAL,
    BOOLEAN AcceptConnection
);

extern "C" NTSTATUS SCAlpcCancelMessage(
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_CONTEXT_ATTR MessageContext
);

extern "C" NTSTATUS SCAlpcConnectPort(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
    ULONG Flags,
    PSID RequiredServerSid OPTIONAL,
    PPORT_MESSAGE ConnectionMessage,
    PSIZE_T BufferLength OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCAlpcConnectPortEx(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
    POBJECT_ATTRIBUTES ClientPortObjectAttributes OPTIONAL,
    PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
    ULONG Flags,
    PSECURITY_DESCRIPTOR ServerSecurityRequirements OPTIONAL,
    PPORT_MESSAGE ConnectionMessage,
    PSIZE_T BufferLength OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCAlpcCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL
);

extern "C" NTSTATUS SCAlpcCreatePortSection(
    HANDLE PortHandle,
    ULONG Flags,
    HANDLE SectionHandle OPTIONAL,
    SIZE_T SectionSize,
    PALPC_HANDLE AlpcSectionHandle,
    PSIZE_T ActualSectionSize
);

extern "C" NTSTATUS SCAlpcCreateResourceReserve(
    HANDLE PortHandle,
    ULONG Flags,
    SIZE_T MessageSize,
    PALPC_HANDLE ResourceId
);

extern "C" NTSTATUS SCAlpcCreateSectionView(
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_DATA_VIEW_ATTR ViewAttributes
);

extern "C" NTSTATUS SCAlpcCreateSecurityContext(
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_SECURITY_ATTR SecurityAttribute
);

extern "C" NTSTATUS SCAlpcDeletePortSection(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE SectionHandle
);

extern "C" NTSTATUS SCAlpcDeleteResourceReserve(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE ResourceId
);

extern "C" NTSTATUS SCAlpcDeleteSectionView(
    HANDLE PortHandle,
    ULONG Flags,
    PVOID ViewBase
);

extern "C" NTSTATUS SCAlpcDeleteSecurityContext(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE ContextHandle
);

extern "C" NTSTATUS SCAlpcDisconnectPort(
    HANDLE PortHandle,
    ULONG Flags
);

extern "C" NTSTATUS SCAlpcImpersonateClientContainerOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG Flags
);

extern "C" NTSTATUS SCAlpcImpersonateClientOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    PVOID Flags
);

extern "C" NTSTATUS SCAlpcOpenSenderProcess(
    PHANDLE ProcessHandle,
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ULONG Flags,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCAlpcOpenSenderThread(
    PHANDLE ThreadHandle,
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ULONG Flags,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCAlpcQueryInformation(
    HANDLE PortHandle OPTIONAL,
    ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCAlpcQueryInformationMessage(
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
    PVOID MessageInformation,
    ULONG Length,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCAlpcRevokeSecurityContext(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE ContextHandle
);

extern "C" NTSTATUS SCAlpcSendWaitReceivePort(
    HANDLE PortHandle,
    ULONG Flags,
    PPORT_MESSAGE SendMessage OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
    PPORT_MESSAGE ReceiveMessage OPTIONAL,
    PSIZE_T BufferLength OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCAlpcSetInformation(
    HANDLE PortHandle,
    ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation OPTIONAL,
    ULONG Length
);

extern "C" NTSTATUS SCApphelpCacheControl(
    ULONG Command,
    PVOID Buffer OPTIONAL,
    ULONG BufferSize
);

extern "C" NTSTATUS SCAreMappedFilesTheSame(
    PVOID File1MappedAsAnImage,
    PVOID File2MappedAsFile
);

extern "C" NTSTATUS SCAssignProcessToJobObject(
    HANDLE JobHandle,
    HANDLE ProcessHandle
);

extern "C" NTSTATUS SCAssociateWaitCompletionPacket(
    HANDLE WaitCompletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID KeyContext OPTIONAL,
    PVOID ApcContext OPTIONAL,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled OPTIONAL
);

extern "C" NTSTATUS SCCallEnclave(
    PENCLAVE_ROUTINE Routine,
    PVOID Reserved,
    ULONG Flags,
    PVOID * RoutineParamReturn
);

extern "C" NTSTATUS SCCallbackReturn(
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputLength,
    NTSTATUS Status
);

extern "C" NTSTATUS SCCancelIoFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SCCancelIoFileEx(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SCCancelSynchronousIoFile(
    HANDLE ThreadHandle,
    PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SCCancelTimer(
    HANDLE TimerHandle,
    PBOOLEAN CurrentState OPTIONAL
);

extern "C" NTSTATUS SCCancelTimer2(
    HANDLE TimerHandle,
    PT2_CANCEL_PARAMETERS Parameters
);

extern "C" NTSTATUS SCCancelWaitCompletionPacket(
    HANDLE WaitCompletionPacketHandle,
    BOOLEAN RemoveSignaledPacket
);

extern "C" NTSTATUS SCChangeProcessState(
    HANDLE ProcessStateChangeHandle,
    HANDLE ProcessHandle,
    PROCESS_STATE_CHANGE_TYPE StateChangeType,
    PVOID ExtendedInformation OPTIONAL,
    SIZE_T ExtendedInformationLength OPTIONAL,
    ULONG64 Reserved OPTIONAL
);

extern "C" NTSTATUS SCChangeThreadState(
    HANDLE ThreadStateChangeHandle,
    HANDLE ThreadHandle,
    THREAD_STATE_CHANGE_TYPE StateChangeType,
    PVOID ExtendedInformation OPTIONAL,
    SIZE_T ExtendedInformationLength OPTIONAL,
    ULONG64 Reserved OPTIONAL
);

extern "C" NTSTATUS SCClearEvent(
    HANDLE EventHandle
);

extern "C" NTSTATUS SCClose(
    HANDLE Handle
);

extern "C" NTSTATUS SCCloseObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    BOOLEAN GenerateOnClose
);

extern "C" NTSTATUS SCCommitComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCCommitEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCCommitRegistryTransaction(
    HANDLE RegistryTransactionHandle,
    ULONG Flags // Reserved
);

extern "C" NTSTATUS SCCommitTransaction(
    HANDLE TransactionHandle,
    BOOLEAN Wait
);

extern "C" NTSTATUS SCCompactKeys(
    ULONG Count,
    HANDLE KeyArray[]
);

extern "C" NTSTATUS SCCompareObjects(
    HANDLE FirstObjectHandle,
    HANDLE SecondObjectHandle
);

extern "C" NTSTATUS SCCompareSigningLevels(
    SE_SIGNING_LEVEL FirstSigningLevel,
    SE_SIGNING_LEVEL SecondSigningLevel
);

extern "C" NTSTATUS SCCompareTokens(
    HANDLE FirstTokenHandle,
    HANDLE SecondTokenHandle,
    PBOOLEAN Equal
);

extern "C" NTSTATUS SCCompleteConnectPort(
    HANDLE PortHandle
);

extern "C" NTSTATUS SCCompressKey(
    HANDLE KeyHandle
);

extern "C" NTSTATUS SCConnectPort(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    PPORT_VIEW ClientView OPTIONAL,
    PREMOTE_PORT_VIEW ServerView OPTIONAL,
    PULONG MaxMessageLength OPTIONAL,
    PVOID ConnectionInformation OPTIONAL,
    PULONG ConnectionInformationLength OPTIONAL
);

extern "C" NTSTATUS SCContinue(
    PCONTEXT ContextRecord,
    BOOLEAN TestAlert
);

extern "C" NTSTATUS SCContinueEx(
    PCONTEXT ContextRecord,
    PVOID ContinueArgument // Can be PKCONTINUE_ARGUMENT or BOOLEAN
);

extern "C" NTSTATUS SCConvertBetweenAuxiliaryCounterAndPerformanceCounter(
    BOOLEAN ConvertAuxiliaryToPerformanceCounter,
    PULONG64 PerformanceOrAuxiliaryCounterValue,
    PULONG64 ConvertedValue,
    PULONG64 ConversionError OPTIONAL
);

extern "C" NTSTATUS SCCopyFileChunk(
    HANDLE SourceHandle,
    HANDLE DestinationHandle,
    HANDLE EventHandle OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG Length,
    PLARGE_INTEGER SourceOffset,
    PLARGE_INTEGER DestOffset,
    PULONG SourceKey OPTIONAL,
    PULONG DestKey OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SCCreateCpuPartition(
    PHANDLE CpuPartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SCCreateCrossVmEvent(
    PHANDLE CrossVmEvent,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CrossVmEventFlags,
    LPCGUID VMID,
    LPCGUID ServiceID
);

extern "C" NTSTATUS SCCreateCrossVmMutant(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CrossVmEventFlags,
    LPCGUID VMID,
    LPCGUID ServiceID
);

extern "C" NTSTATUS SCCreateDebugObject(
    PHANDLE DebugObjectHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SCCreateDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCCreateDirectoryObjectEx(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ShadowDirectoryHandle,
    ULONG Flags
);

extern "C" NTSTATUS SCCreateEnclave(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T Size,
    SIZE_T InitialCommitment,
    ULONG EnclaveType,
    PVOID EnclaveInformation,
    ULONG EnclaveInformationLength,
    PULONG EnclaveError OPTIONAL
);

extern "C" NTSTATUS SCCreateEnlistment(
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    HANDLE TransactionHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    NOTIFICATION_MASK NotificationMask,
    PVOID EnlistmentKey OPTIONAL
);

extern "C" NTSTATUS SCCreateEvent(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    EVENT_TYPE EventType,
    BOOLEAN InitialState
);

extern "C" NTSTATUS SCCreateEventPair(
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SCCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize OPTIONAL,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer OPTIONAL,
    ULONG EaLength
);

extern "C" NTSTATUS SCCreateIRTimer(
    PHANDLE TimerHandle,
    PVOID Reserved,
    ACCESS_MASK DesiredAccess
);

extern "C" NTSTATUS SCCreateIoCompletion(
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG NumberOfConcurrentThreads OPTIONAL
);

extern "C" NTSTATUS SCCreateIoRing(
    PHANDLE IoRingHandle,
    ULONG CreateParametersLength,
    PVOID CreateParameters,
    ULONG OutputParametersLength,
    PVOID OutputParameters
);

extern "C" NTSTATUS SCCreateJobObject(
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SCCreateJobSet(
    ULONG NumJob,
    PJOB_SET_ARRAY UserJobSet,
    ULONG Flags
);

extern "C" NTSTATUS SCCreateKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class OPTIONAL,
    ULONG CreateOptions,
    PULONG Disposition OPTIONAL
);

extern "C" NTSTATUS SCCreateKeyTransacted(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class OPTIONAL,
    ULONG CreateOptions,
    HANDLE TransactionHandle,
    PULONG Disposition OPTIONAL
);

extern "C" NTSTATUS SCCreateKeyedEvent(
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SCCreateLowBoxToken(
    PHANDLE TokenHandle,
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PSID PackageSid,
    ULONG CapabilityCount,
    PSID_AND_ATTRIBUTES Capabilities OPTIONAL,
    ULONG HandleCount,
    HANDLE * Handles OPTIONAL
);

extern "C" NTSTATUS SCCreateMailslotFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CreateOptions,
    ULONG MailslotQuota,
    ULONG MaximumMessageSize,
    PLARGE_INTEGER ReadTimeout
);

extern "C" NTSTATUS SCCreateMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    BOOLEAN InitialOwner
);

extern "C" NTSTATUS SCCreateNamedPipeFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    ULONG NamedPipeType,
    ULONG ReadMode,
    ULONG CompletionMode,
    ULONG MaximumInstances,
    ULONG InboundQuota,
    ULONG OutboundQuota,
    PLARGE_INTEGER DefaultTimeout
);

extern "C" NTSTATUS SCCreatePagingFile(
    PUNICODE_STRING PageFileName,
    PLARGE_INTEGER MinimumSize,
    PLARGE_INTEGER MaximumSize,
    ULONG Priority
);

extern "C" NTSTATUS SCCreatePartition(
    HANDLE ParentPartitionHandle OPTIONAL,
    PHANDLE PartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG PreferredNode
);

extern "C" NTSTATUS SCCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG MaxConnectionInfoLength,
    ULONG MaxMessageLength,
    ULONG MaxPoolUsage OPTIONAL
);

extern "C" NTSTATUS SCCreatePrivateNamespace(
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor
);

extern "C" NTSTATUS SCCreateProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE TokenHandle OPTIONAL
);

extern "C" NTSTATUS SCCreateProcessEx(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE TokenHandle OPTIONAL,
    ULONG Reserved
);

extern "C" NTSTATUS SCCreateProcessStateChange(
    PHANDLE ProcessStateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    ULONG64 Reserved OPTIONAL
);

extern "C" NTSTATUS SCCreateProfile(
    PHANDLE ProfileHandle,
    HANDLE Process OPTIONAL,
    PVOID ProfileBase,
    SIZE_T ProfileSize,
    ULONG BucketSize,
    PULONG Buffer,
    ULONG BufferSize,
    KPROFILE_SOURCE ProfileSource,
    KAFFINITY Affinity
);

extern "C" NTSTATUS SCCreateProfileEx(
    PHANDLE ProfileHandle,
    HANDLE Process OPTIONAL,
    PVOID ProfileBase,
    SIZE_T ProfileSize,
    ULONG BucketSize,
    PULONG Buffer,
    ULONG BufferSize,
    KPROFILE_SOURCE ProfileSource,
    USHORT GroupCount,
    PGROUP_AFFINITY GroupAffinity
);

extern "C" NTSTATUS SCCreateRegistryTransaction(
    PHANDLE RegistryTransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions
);

extern "C" NTSTATUS SCCreateResourceManager(
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID RmGuid,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    PUNICODE_STRING Description OPTIONAL
);

extern "C" NTSTATUS SCCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

extern "C" NTSTATUS SCCreateSectionEx(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PLARGE_INTEGER MaximumSize OPTIONAL,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle OPTIONAL,
    PMEM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount
);

extern "C" NTSTATUS SCCreateSemaphore(
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    LONG InitialCount,
    LONG MaximumCount
);

extern "C" NTSTATUS SCCreateSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING LinkTarget
);

extern "C" NTSTATUS SCCreateThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    CLIENT_ID * ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended
);

extern "C" NTSTATUS SCCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    PUSER_THREAD_START_ROUTINE StartRoutine,
    PVOID Argument OPTIONAL,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

extern "C" NTSTATUS SCCreateThreadStateChange(
    PHANDLE ThreadStateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ThreadHandle,
    ULONG64 Reserved OPTIONAL
);

extern "C" NTSTATUS SCCreateTimer(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    TIMER_TYPE TimerType
);

extern "C" NTSTATUS SCCreateTimer2(
    PHANDLE TimerHandle,
    PVOID Reserved1 OPTIONAL,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Attributes,
    ACCESS_MASK DesiredAccess
);

extern "C" NTSTATUS SCCreateToken(
    PHANDLE TokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    TOKEN_TYPE Type,
    PLUID AuthenticationId,
    PLARGE_INTEGER ExpirationTime,
    PTOKEN_USER User,
    PTOKEN_GROUPS Groups,
    PTOKEN_PRIVILEGES Privileges,
    PTOKEN_OWNER Owner OPTIONAL,
    PTOKEN_PRIMARY_GROUP PrimaryGroup,
    PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
    PTOKEN_SOURCE Source
);

extern "C" NTSTATUS SCCreateTokenEx(
    PHANDLE TokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    TOKEN_TYPE Type,
    PLUID AuthenticationId,
    PLARGE_INTEGER ExpirationTime,
    PTOKEN_USER User,
    PTOKEN_GROUPS Groups,
    PTOKEN_PRIVILEGES Privileges,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes OPTIONAL,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes OPTIONAL,
    PTOKEN_GROUPS DeviceGroups OPTIONAL,
    PTOKEN_MANDATORY_POLICY MandatoryPolicy OPTIONAL,
    PTOKEN_OWNER Owner OPTIONAL,
    PTOKEN_PRIMARY_GROUP PrimaryGroup,
    PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
    PTOKEN_SOURCE Source
);

extern "C" NTSTATUS SCCreateTransaction(
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    LPGUID Uow OPTIONAL,
    HANDLE TmHandle OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    ULONG IsolationLevel OPTIONAL,
    ULONG IsolationFlags OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL,
    PUNICODE_STRING Description OPTIONAL
);

extern "C" NTSTATUS SCCreateTransactionManager(
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PUNICODE_STRING LogFileName OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    ULONG CommitStrength OPTIONAL
);

extern "C" NTSTATUS SCCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
    POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters OPTIONAL,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

extern "C" NTSTATUS SCCreateWaitCompletionPacket(
    PHANDLE WaitCompletionPacketHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SCCreateWaitablePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG MaxConnectionInfoLength,
    ULONG MaxMessageLength,
    ULONG MaxPoolUsage OPTIONAL
);

extern "C" NTSTATUS SCCreateWnfStateName(
    PWNF_STATE_NAME StateName,
    WNF_STATE_NAME_LIFETIME NameLifetime,
    WNF_DATA_SCOPE DataScope,
    BOOLEAN PersistData,
    PCWNF_TYPE_ID TypeId OPTIONAL,
    ULONG MaximumStateSize,
    PSECURITY_DESCRIPTOR SecurityDescriptor
);

extern "C" NTSTATUS SCCreateWorkerFactory(
    PHANDLE WorkerFactoryHandleReturn,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE CompletionPortHandle,
    HANDLE WorkerProcessHandle,
    PVOID StartRoutine,
    PVOID StartParameter OPTIONAL,
    ULONG MaxThreadCount OPTIONAL,
    SIZE_T StackReserve OPTIONAL,
    SIZE_T StackCommit OPTIONAL
);

extern "C" NTSTATUS SCDebugActiveProcess(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
);

extern "C" NTSTATUS SCDebugContinue(
    HANDLE DebugObjectHandle,
    CLIENT_ID * ClientId,
    NTSTATUS ContinueStatus
);

extern "C" NTSTATUS SCDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
);

extern "C" NTSTATUS SCDeleteAtom(
    PRTL_ATOM Atom
);

extern "C" NTSTATUS SCDeleteBootEntry(
    ULONG Id
);

extern "C" NTSTATUS SCDeleteDriverEntry(
    ULONG Id
);

extern "C" NTSTATUS SCDeleteFile(
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCDeleteKey(
    HANDLE KeyHandle
);

extern "C" NTSTATUS SCDeleteObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    BOOLEAN GenerateOnClose
);

extern "C" NTSTATUS SCDeletePrivateNamespace(
    HANDLE NamespaceHandle
);

extern "C" NTSTATUS SCDeleteValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName
);

extern "C" NTSTATUS SCDeleteWnfStateData(
    PCWNF_STATE_NAME StateName,
    const VOID * ExplicitScope OPTIONAL
);

extern "C" NTSTATUS SCDeleteWnfStateName(
    PCWNF_STATE_NAME StateName
);

extern "C" NTSTATUS SCDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength
);

extern "C" NTSTATUS SCDirectGraphicsCall(
    ULONG InputBufferLength,
    PVOID InputBuffer OPTIONAL,
    ULONG OutputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    PULONG ReturnLength
);

extern "C" NTSTATUS SCDisableLastKnownGood(VOID);

extern "C" NTSTATUS SCDisplayString(
    PUNICODE_STRING String
);

extern "C" NTSTATUS SCDrawText(
    PUNICODE_STRING Text
);

extern "C" NTSTATUS SCDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle OPTIONAL,
    PHANDLE TargetHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

extern "C" NTSTATUS SCDuplicateToken(
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE Type,
    PHANDLE NewTokenHandle
);

extern "C" NTSTATUS SCEnableLastKnownGood(VOID);

extern "C" NTSTATUS SCEnumerateBootEntries(
    PVOID Buffer OPTIONAL,
    PULONG BufferLength
);

extern "C" NTSTATUS SCEnumerateDriverEntries(
    PVOID Buffer OPTIONAL,
    PULONG BufferLength
);

extern "C" NTSTATUS SCEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation OPTIONAL,
    ULONG Length,
    PULONG ResultLength
);

extern "C" NTSTATUS SCEnumerateSystemEnvironmentValuesEx(
    ULONG InformationClass,
    PVOID Buffer,
    PULONG BufferLength
);

extern "C" NTSTATUS SCEnumerateTransactionObject(
    HANDLE RootObjectHandle OPTIONAL,
    KTMOBJECT_TYPE QueryType,
    PKTMOBJECT_CURSOR ObjectCursor,
    ULONG ObjectCursorLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS SCEnumerateValueKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation OPTIONAL,
    ULONG Length,
    PULONG ResultLength
);

extern "C" NTSTATUS SCExtendSection(
    HANDLE SectionHandle,
    PLARGE_INTEGER NewSectionSize
);

extern "C" NTSTATUS SCFilterBootOption(
    FILTER_BOOT_OPTION_OPERATION FilterOperation,
    ULONG ObjectType,
    ULONG ElementType,
    PVOID Data OPTIONAL,
    ULONG DataSize
);

extern "C" NTSTATUS SCFilterToken(
    HANDLE ExistingTokenHandle,
    ULONG Flags,
    PTOKEN_GROUPS SidsToDisable OPTIONAL,
    PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
    PTOKEN_GROUPS RestrictedSids OPTIONAL,
    PHANDLE NewTokenHandle
);

extern "C" NTSTATUS SCFilterTokenEx(
    HANDLE ExistingTokenHandle,
    ULONG Flags,
    PTOKEN_GROUPS SidsToDisable OPTIONAL,
    PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
    PTOKEN_GROUPS RestrictedSids OPTIONAL,
    ULONG DisableUserClaimsCount,
    PUNICODE_STRING UserClaimsToDisable OPTIONAL,
    ULONG DisableDeviceClaimsCount,
    PUNICODE_STRING DeviceClaimsToDisable OPTIONAL,
    PTOKEN_GROUPS DeviceGroupsToDisable OPTIONAL,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes OPTIONAL,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes OPTIONAL,
    PTOKEN_GROUPS RestrictedDeviceGroups OPTIONAL,
    PHANDLE NewTokenHandle
);

extern "C" NTSTATUS SCFindAtom(
    PCWSTR AtomName OPTIONAL,
    ULONG Length,
    PRTL_ATOM Atom OPTIONAL
);

extern "C" NTSTATUS SCFlushBuffersFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SCFlushBuffersFileEx(
    HANDLE FileHandle,
    ULONG Flags,
    PVOID Parameters,
    ULONG ParametersSize,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SCFlushInstallUILanguage(
    LANGID InstallUILanguage,
    ULONG SetCommittedFlag
);

extern "C" NTSTATUS SCFlushInstructionCache(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    SIZE_T Length
);

extern "C" NTSTATUS SCFlushKey(
    HANDLE KeyHandle
);

extern "C" NTSTATUS SCFlushProcessWriteBuffers(VOID);

extern "C" NTSTATUS SCFlushVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    PIO_STATUS_BLOCK IoStatus
);

extern "C" NTSTATUS SCFlushWriteBuffer(VOID);

extern "C" NTSTATUS SCFreeUserPhysicalPages(
    HANDLE ProcessHandle,
    PULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray
);

extern "C" NTSTATUS SCFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

extern "C" NTSTATUS SCFreezeRegistry(
    ULONG TimeOutInSeconds
);

extern "C" NTSTATUS SCFreezeTransactions(
    PLARGE_INTEGER FreezeTimeout,
    PLARGE_INTEGER ThawTimeout
);

extern "C" NTSTATUS SCFsControlFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength
);

extern "C" NTSTATUS SCGetCachedSigningLevel(
    HANDLE File,
    PULONG Flags,
    PSE_SIGNING_LEVEL SigningLevel,
    PUCHAR Thumbprint OPTIONAL,
    PULONG ThumbprintSize OPTIONAL,
    PULONG ThumbprintAlgorithm OPTIONAL
);

extern "C" NTSTATUS SCGetCompleteWnfStateSubscription(
    PWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
    ULONG64 * OldSubscriptionId OPTIONAL,
    ULONG OldDescriptorEventMask,
    ULONG OldDescriptorStatus,
    PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
    ULONG DescriptorSize
);

extern "C" NTSTATUS SCGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

extern "C" ULONG SCGetCurrentProcessorNumber(VOID);

extern "C" ULONG SCGetCurrentProcessorNumberEx(
    PPROCESSOR_NUMBER ProcessorNumber OPTIONAL
);

extern "C" NTSTATUS SCGetDevicePowerState(
    HANDLE Device,
    PDEVICE_POWER_STATE State
);

extern "C" NTSTATUS SCGetMUIRegistryInfo(
    ULONG Flags,
    PULONG DataSize,
    PVOID Data
);

extern "C" NTSTATUS SCGetNextProcess(
    HANDLE ProcessHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
);

extern "C" NTSTATUS SCGetNextThread(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
);

extern "C" NTSTATUS SCGetNlsSectionPtr(
    ULONG SectionType,
    ULONG SectionData,
    PVOID ContextData,
    PVOID * SectionPointer,
    PULONG SectionSize
);

extern "C" NTSTATUS SCGetNotificationResourceManager(
    HANDLE ResourceManagerHandle,
    PTRANSACTION_NOTIFICATION TransactionNotification,
    ULONG NotificationLength,
    PLARGE_INTEGER Timeout OPTIONAL,
    PULONG ReturnLength OPTIONAL,
    ULONG Asynchronous,
    ULONG_PTR AsynchronousContext OPTIONAL
);

extern "C" NTSTATUS SCGetWriteWatch(
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID BaseAddress,
    SIZE_T RegionSize,
    PVOID * UserAddressArray,
    PULONG_PTR EntriesInUserAddressArray,
    PULONG Granularity
);

extern "C" NTSTATUS SCImpersonateAnonymousToken(
    HANDLE ThreadHandle
);

extern "C" NTSTATUS SCImpersonateClientOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message
);

extern "C" NTSTATUS SCImpersonateThread(
    HANDLE ServerThreadHandle,
    HANDLE ClientThreadHandle,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos
);

extern "C" NTSTATUS SCInitializeEnclave(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID EnclaveInformation,
    ULONG EnclaveInformationLength,
    PULONG EnclaveError OPTIONAL
);

extern "C" NTSTATUS SCInitializeNlsFiles(
    PVOID * BaseAddress,
    PLCID DefaultLocaleId,
    PLARGE_INTEGER DefaultCasingTableSize,
    PULONG CurrentNLSVersion OPTIONAL
);

extern "C" NTSTATUS SCInitializeRegistry(
    USHORT BootCondition
);

extern "C" NTSTATUS SCInitiatePowerAction(
    POWER_ACTION SystemAction,
    SYSTEM_POWER_STATE LightestSystemState,
    ULONG Flags,
    BOOLEAN Asynchronous
);

extern "C" NTSTATUS SCIsProcessInJob(
    HANDLE ProcessHandle,
    HANDLE JobHandle OPTIONAL
);

extern "C" NTSTATUS SCIsSystemResumeAutomatic(VOID);

extern "C" NTSTATUS SCIsUILanguageComitted(VOID);

extern "C" NTSTATUS SCListenPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ConnectionRequest
);

extern "C" NTSTATUS SCLoadDriver(
    PUNICODE_STRING DriverServiceName
);

extern "C" NTSTATUS SCLoadEnclaveData(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    ULONG Protect,
    PVOID PageInformation,
    ULONG PageInformationLength,
    PSIZE_T NumberOfBytesWritten OPTIONAL,
    PULONG EnclaveError OPTIONAL
);

extern "C" NTSTATUS SCLoadKey(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile
);

extern "C" NTSTATUS SCLoadKey2(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags
);

extern "C" NTSTATUS SCLoadKey3(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    PCM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount,
    ACCESS_MASK DesiredAccess OPTIONAL,
    PHANDLE RootHandle OPTIONAL,
    PVOID Reserved OPTIONAL
);

extern "C" NTSTATUS SCLoadKeyEx(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    HANDLE TrustClassKey OPTIONAL,
    HANDLE Event OPTIONAL,
    ACCESS_MASK DesiredAccess OPTIONAL,
    PHANDLE RootHandle OPTIONAL,
    PVOID Reserved OPTIONAL // previously PIO_STATUS_BLOCK
);

extern "C" NTSTATUS SCLockFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER ByteOffset,
    PLARGE_INTEGER Length,
    ULONG Key,
    BOOLEAN FailImmediately,
    BOOLEAN ExclusiveLock
);

extern "C" NTSTATUS SCLockProductActivationKeys(
    ULONG * pPrivateVer OPTIONAL,
    ULONG * pSafeMode OPTIONAL
);

extern "C" NTSTATUS SCLockRegistryKey(
    HANDLE KeyHandle
);

extern "C" NTSTATUS SCLockVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG MapType
);

extern "C" NTSTATUS SCMakePermanentObject(
    HANDLE Handle
);

extern "C" NTSTATUS SCMakeTemporaryObject(
    HANDLE Handle
);

extern "C" NTSTATUS SCManageHotPatch(
    HANDLE ProcessHandle,
    ULONG Operation,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength
);

extern "C" NTSTATUS SCManagePartition(
    HANDLE TargetHandle,
    HANDLE SourceHandle OPTIONAL,
    PARTITION_INFORMATION_CLASS PartitionInformationClass,
    PVOID PartitionInformation,
    ULONG PartitionInformationLength
);

extern "C" NTSTATUS SCMapCMFModule(
    ULONG What,
    ULONG Index,
    PULONG CacheIndexOut OPTIONAL,
    PULONG CacheFlagsOut OPTIONAL,
    PULONG ViewSizeOut OPTIONAL,
    PVOID * BaseAddress OPTIONAL
);

extern "C" NTSTATUS SCMapUserPhysicalPages(
    PVOID VirtualAddress,
    SIZE_T NumberOfPages,
    PULONG_PTR UserPfnArray OPTIONAL
);

extern "C" NTSTATUS SCMapUserPhysicalPagesScatter(
    PVOID * VirtualAddresses,
    SIZE_T NumberOfPages,
    PULONG_PTR UserPfnArray OPTIONAL
);

extern "C" NTSTATUS SCMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

extern "C" NTSTATUS SCMapViewOfSectionEx(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PLARGE_INTEGER SectionOffset OPTIONAL,
    PSIZE_T ViewSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount
);

extern "C" NTSTATUS SCModifyBootEntry(
    PBOOT_ENTRY BootEntry
);

extern "C" NTSTATUS SCModifyDriverEntry(
    PEFI_DRIVER_ENTRY DriverEntry
);

extern "C" NTSTATUS SCNotifyChangeDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, // FILE_NOTIFY_INFORMATION
    ULONG Length,
    ULONG CompletionFilter,
    BOOLEAN WatchTree
);

extern "C" NTSTATUS SCNotifyChangeDirectoryFileEx(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass
);

extern "C" NTSTATUS SCNotifyChangeKey(
    HANDLE KeyHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer OPTIONAL,
    ULONG BufferSize,
    BOOLEAN Asynchronous
);

extern "C" NTSTATUS SCNotifyChangeMultipleKeys(
    HANDLE MasterKeyHandle,
    ULONG Count OPTIONAL,
    OBJECT_ATTRIBUTES SubordinateObjects[],
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer OPTIONAL,
    ULONG BufferSize,
    BOOLEAN Asynchronous
);

extern "C" NTSTATUS SCNotifyChangeSession(
    HANDLE SessionHandle,
    ULONG ChangeSequenceNumber,
    PLARGE_INTEGER ChangeTimeStamp,
    IO_SESSION_EVENT Event,
    IO_SESSION_STATE NewState,
    IO_SESSION_STATE PreviousState,
    PVOID Payload OPTIONAL,
    ULONG PayloadSize
);

extern "C" NTSTATUS SCOpenCpuPartition(
    PHANDLE CpuPartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SCOpenEnlistment(
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    LPGUID EnlistmentGuid,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SCOpenEvent(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenEventPair(
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

extern "C" NTSTATUS SCOpenIoCompletion(
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenJobObject(
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenKeyEx(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions
);

extern "C" NTSTATUS SCOpenKeyTransacted(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE TransactionHandle
);

extern "C" NTSTATUS SCOpenKeyTransactedEx(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions,
    HANDLE TransactionHandle
);

extern "C" NTSTATUS SCOpenKeyedEvent(
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    ACCESS_MASK GrantedAccess,
    PPRIVILEGE_SET Privileges OPTIONAL,
    BOOLEAN ObjectCreation,
    BOOLEAN AccessGranted,
    PBOOLEAN GenerateOnClose
);

extern "C" NTSTATUS SCOpenPartition(
    PHANDLE PartitionHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenPrivateNamespace(
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor
);

extern "C" NTSTATUS SCOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID * ClientId OPTIONAL
);

extern "C" NTSTATUS SCOpenProcessToken(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle
);

extern "C" NTSTATUS SCOpenProcessTokenEx(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    PHANDLE TokenHandle
);

extern "C" NTSTATUS SCOpenRegistryTransaction(
    HANDLE * RegistryTransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjAttributes
);

extern "C" NTSTATUS SCOpenResourceManager(
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID ResourceManagerGuid OPTIONAL,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SCOpenSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenSemaphore(
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenSession(
    PHANDLE SessionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID * ClientId OPTIONAL
);

extern "C" NTSTATUS SCOpenThreadToken(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    PHANDLE TokenHandle
);

extern "C" NTSTATUS SCOpenThreadTokenEx(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    ULONG HandleAttributes,
    PHANDLE TokenHandle
);

extern "C" NTSTATUS SCOpenTimer(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SCOpenTransaction(
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    LPGUID Uow,
    HANDLE TmHandle OPTIONAL
);

extern "C" NTSTATUS SCOpenTransactionManager(
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PUNICODE_STRING LogFileName OPTIONAL,
    LPGUID TmIdentity OPTIONAL,
    ULONG OpenOptions OPTIONAL
);

extern "C" NTSTATUS SCPlugPlayControl(
    PLUGPLAY_CONTROL_CLASS PnPControlClass,
    PVOID PnPControlData OPTIONAL,
    ULONG PnPControlDataLength
);

extern "C" NTSTATUS SCPowerInformation(
    POWER_INFORMATION_LEVEL InformationLevel,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength
);

extern "C" NTSTATUS SCPrePrepareComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCPrePrepareEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCPrepareComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCPrepareEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCPrivilegeCheck(
    HANDLE ClientToken,
    PPRIVILEGE_SET RequiredPrivileges,
    PBOOLEAN Result
);

extern "C" NTSTATUS SCPrivilegeObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    PPRIVILEGE_SET Privileges,
    BOOLEAN AccessGranted
);

extern "C" NTSTATUS SCPrivilegedServiceAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PUNICODE_STRING ServiceName,
    HANDLE ClientToken,
    PPRIVILEGE_SET Privileges,
    BOOLEAN AccessGranted
);

extern "C" NTSTATUS SCPropagationComplete(
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    ULONG BufferLength,
    PVOID Buffer
);

extern "C" NTSTATUS SCPropagationFailed(
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    NTSTATUS PropStatus
);

extern "C" NTSTATUS SCProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

extern "C" NTSTATUS SCPssCaptureVaSpaceBulk(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    PNTPSS_MEMORY_BULK_INFORMATION BulkInformation,
    SIZE_T BulkInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCPulseEvent(
    HANDLE EventHandle,
    PLONG PreviousState OPTIONAL
);

extern "C" NTSTATUS SCQueryAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
);

extern "C" NTSTATUS SCQueryAuxiliaryCounterFrequency(
    PULONG64 AuxiliaryCounterFrequency
);

extern "C" NTSTATUS SCQueryBootEntryOrder(
    PULONG Ids OPTIONAL,
    PULONG Count
);

extern "C" NTSTATUS SCQueryBootOptions(
    PBOOT_OPTIONS BootOptions OPTIONAL,
    PULONG BootOptionsLength
);

extern "C" NTSTATUS SCQueryDebugFilterState(
    ULONG ComponentId,
    ULONG Level
);

extern "C" NTSTATUS SCQueryDefaultLocale(
    BOOLEAN UserProfile,
    PLCID DefaultLocaleId
);

extern "C" NTSTATUS SCQueryDefaultUILanguage(
    LANGID * DefaultUILanguageId
);

extern "C" NTSTATUS SCQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName OPTIONAL,
    BOOLEAN RestartScan
);

extern "C" NTSTATUS SCQueryDirectoryFileEx(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags,
    PUNICODE_STRING FileName OPTIONAL
);

extern "C" NTSTATUS SCQueryDirectoryObject(
    HANDLE DirectoryHandle,
    PVOID Buffer OPTIONAL,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryDriverEntryOrder(
    PULONG Ids OPTIONAL,
    PULONG Count
);

extern "C" NTSTATUS SCQueryEaFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    PVOID EaList OPTIONAL,
    ULONG EaListLength,
    PULONG EaIndex OPTIONAL,
    BOOLEAN RestartScan
);

extern "C" NTSTATUS SCQueryEvent(
    HANDLE EventHandle,
    EVENT_INFORMATION_CLASS EventInformationClass,
    PVOID EventInformation,
    ULONG EventInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryFullAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_NETWORK_OPEN_INFORMATION FileInformation
);

extern "C" NTSTATUS SCQueryInformationAtom(
    PRTL_ATOM Atom,
    ATOM_INFORMATION_CLASS AtomInformationClass,
    PVOID AtomInformation,
    ULONG AtomInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationByName(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

extern "C" NTSTATUS SCQueryInformationCpuPartition(
    HANDLE PartitionHandle OPTIONAL,
    CPU_PARTITION_INFORMATION_CLASS PartitionInformationClass,
    PVOID PartitionInformation,
    ULONG PartitionInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationEnlistment(
    HANDLE EnlistmentHandle,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

extern "C" NTSTATUS SCQueryInformationJobObject(
    HANDLE JobHandle OPTIONAL,
    JOBOBJECTINFOCLASS JobObjectInformationClass,
    PVOID JobObjectInformation,
    ULONG JobObjectInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationPort(
    HANDLE PortHandle,
    PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationResourceManager(
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationTransaction(
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationTransactionManager(
    HANDLE TransactionManagerHandle,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    PVOID TransactionManagerInformation,
    ULONG TransactionManagerInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInformationWorkerFactory(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryInstallUILanguage(
    LANGID * InstallUILanguageId
);

extern "C" NTSTATUS SCQueryIntervalProfile(
    KPROFILE_SOURCE ProfileSource,
    PULONG Interval
);

extern "C" NTSTATUS SCQueryIoCompletion(
    HANDLE IoCompletionHandle,
    IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    PVOID IoCompletionInformation,
    ULONG IoCompletionInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryIoRingCapabilities(
    SIZE_T IoRingCapabilitiesLength,
    PVOID IoRingCapabilities
);

extern "C" NTSTATUS SCQueryKey(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength OPTIONAL
);

extern "C" NTSTATUS SCQueryLicenseValue(
    PUNICODE_STRING ValueName,
    PULONG Type OPTIONAL,
    PVOID Data OPTIONAL,
    ULONG DataSize,
    PULONG ResultDataSize
);

extern "C" NTSTATUS SCQueryMultipleValueKey(
    HANDLE KeyHandle,
    PKEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount,
    PVOID ValueBuffer,
    PULONG BufferLength,
    PULONG RequiredBufferLength OPTIONAL
);

extern "C" NTSTATUS SCQueryMutant(
    HANDLE MutantHandle,
    MUTANT_INFORMATION_CLASS MutantInformationClass,
    PVOID MutantInformation,
    ULONG MutantInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation OPTIONAL,
    ULONG ObjectInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryOpenSubKeys(
    POBJECT_ATTRIBUTES TargetKey,
    PULONG HandleCount
);

extern "C" NTSTATUS SCQueryOpenSubKeysEx(
    POBJECT_ATTRIBUTES TargetKey,
    ULONG BufferLength,
    PVOID Buffer,
    PULONG RequiredSize
);

extern "C" NTSTATUS SCQueryPerformanceCounter(
    PLARGE_INTEGER PerformanceCounter,
    PLARGE_INTEGER PerformanceFrequency OPTIONAL
);

extern "C" NTSTATUS SCQueryPortInformationProcess(VOID);

extern "C" NTSTATUS SCQueryQuotaInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    PVOID SidList OPTIONAL,
    ULONG SidListLength,
    PSID StartSid OPTIONAL,
    BOOLEAN RestartScan
);

extern "C" NTSTATUS SCQuerySection(
    HANDLE SectionHandle,
    SECTION_INFORMATION_CLASS SectionInformationClass,
    PVOID SectionInformation,
    SIZE_T SectionInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQuerySecurityAttributesToken(
    HANDLE TokenHandle,
    PUNICODE_STRING Attributes,
    ULONG NumberOfAttributes,
    PVOID Buffer, // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION
    ULONG Length,
    PULONG ReturnLength
);

extern "C" NTSTATUS SCQuerySecurityObject(
    HANDLE Handle,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG Length,
    PULONG LengthNeeded
);

extern "C" NTSTATUS SCQuerySecurityPolicy(
    PCUNICODE_STRING Policy,
    PCUNICODE_STRING KeyName,
    PCUNICODE_STRING ValueName,
    SECURE_SETTING_VALUE_TYPE ValueType,
    PVOID Value OPTIONAL,
    PULONG ValueSize
);

extern "C" NTSTATUS SCQuerySemaphore(
    HANDLE SemaphoreHandle,
    SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    PVOID SemaphoreInformation,
    ULONG SemaphoreInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQuerySymbolicLinkObject(
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength OPTIONAL
);

extern "C" NTSTATUS SCQuerySystemEnvironmentValue(
    PUNICODE_STRING VariableName,
    PWSTR VariableValue,
    USHORT ValueLength,
    PUSHORT ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQuerySystemEnvironmentValueEx(
    PCUNICODE_STRING VariableName,
    PCGUID VendorGuid,
    PVOID Buffer OPTIONAL,
    PULONG BufferLength,
    PULONG Attributes OPTIONAL // EFI_VARIABLE_*
);

extern "C" NTSTATUS SCQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS SCQuerySystemInformationEx(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryTimer(
    HANDLE TimerHandle,
    TIMER_INFORMATION_CLASS TimerInformationClass,
    PVOID TimerInformation,
    ULONG TimerInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryTimerResolution(
    PULONG MaximumTime,
    PULONG MinimumTime,
    PULONG CurrentTime
);

extern "C" NTSTATUS SCQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);

extern "C" NTSTATUS SCQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCQueryVolumeInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FSINFOCLASS FsInformationClass
);

extern "C" NTSTATUS SCQueryWnfStateData(
    PCWNF_STATE_NAME StateName,
    PCWNF_TYPE_ID TypeId OPTIONAL,
    const VOID * ExplicitScope OPTIONAL,
    PWNF_CHANGE_STAMP ChangeStamp,
    PVOID Buffer OPTIONAL,
    PULONG BufferSize
);

extern "C" NTSTATUS SCQueryWnfStateNameInformation(
    PCWNF_STATE_NAME StateName,
    WNF_STATE_NAME_INFORMATION NameInfoClass,
    const VOID * ExplicitScope OPTIONAL,
    PVOID InfoBuffer,
    ULONG InfoBufferSize
);

extern "C" NTSTATUS SCQueueApcThread(
    HANDLE ThreadHandle,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL
);

extern "C" NTSTATUS SCQueueApcThreadEx(
    HANDLE ThreadHandle,
    HANDLE ReserveHandle OPTIONAL,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL
);

extern "C" NTSTATUS SCQueueApcThreadEx2(
    HANDLE ThreadHandle,
    HANDLE ReserveHandle OPTIONAL,
    ULONG ApcFlags,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL
);

extern "C" NTSTATUS SCRaiseException(
    PEXCEPTION_RECORD ExceptionRecord,
    PCONTEXT ContextRecord,
    BOOLEAN FirstChance
);

extern "C" NTSTATUS SCRaiseHardError(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters,
    ULONG ValidResponseOptions,
    PULONG Response
);

extern "C" NTSTATUS SCReadFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset OPTIONAL,
    PULONG Key OPTIONAL
);

extern "C" NTSTATUS SCReadFileScatter(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_SEGMENT_ELEMENT SegmentArray,
    ULONG Length,
    PLARGE_INTEGER ByteOffset OPTIONAL,
    PULONG Key OPTIONAL
);

extern "C" NTSTATUS SCReadOnlyEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCReadRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead OPTIONAL
);

extern "C" NTSTATUS SCReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead OPTIONAL
);

extern "C" NTSTATUS SCReadVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SCRecoverEnlistment(
    HANDLE EnlistmentHandle,
    PVOID EnlistmentKey OPTIONAL
);

extern "C" NTSTATUS SCRecoverResourceManager(
    HANDLE ResourceManagerHandle
);

extern "C" NTSTATUS SCRecoverTransactionManager(
    HANDLE TransactionManagerHandle
);

extern "C" NTSTATUS SCRegisterProtocolAddressInformation(
    HANDLE ResourceManager,
    PCRM_PROTOCOL_ID ProtocolId,
    ULONG ProtocolInformationSize,
    PVOID ProtocolInformation,
    ULONG CreateOptions
);

extern "C" NTSTATUS SCRegisterThreadTerminatePort(
    HANDLE PortHandle
);

extern "C" NTSTATUS SCReleaseKeyedEvent(
    HANDLE KeyedEventHandle OPTIONAL,
    PVOID KeyValue,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCReleaseMutant(
    HANDLE MutantHandle,
    PLONG PreviousCount OPTIONAL
);

extern "C" NTSTATUS SCReleaseSemaphore(
    HANDLE SemaphoreHandle,
    LONG ReleaseCount,
    PLONG PreviousCount OPTIONAL
);

extern "C" NTSTATUS SCReleaseWorkerFactoryWorker(
    HANDLE WorkerFactoryHandle
);

extern "C" NTSTATUS SCRemoveIoCompletion(
    HANDLE IoCompletionHandle,
    PVOID * KeyContext,
    PVOID * ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCRemoveIoCompletionEx(
    HANDLE IoCompletionHandle,
    PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
    ULONG Count,
    PULONG NumEntriesRemoved,
    PLARGE_INTEGER Timeout OPTIONAL,
    BOOLEAN Alertable
);

extern "C" NTSTATUS SCRemoveProcessDebug(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
);

extern "C" NTSTATUS SCRenameKey(
    HANDLE KeyHandle,
    PUNICODE_STRING NewName
);

extern "C" NTSTATUS SCRenameTransactionManager(
    PUNICODE_STRING LogFileName,
    LPGUID ExistingTransactionManagerGuid
);

extern "C" NTSTATUS SCReplaceKey(
    POBJECT_ATTRIBUTES NewFile,
    HANDLE TargetHandle,
    POBJECT_ATTRIBUTES OldFile
);

extern "C" NTSTATUS SCReplacePartitionUnit(
    PUNICODE_STRING TargetInstancePath,
    PUNICODE_STRING SpareInstancePath,
    ULONG Flags
);

extern "C" NTSTATUS SCReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage
);

extern "C" NTSTATUS SCReplyWaitReceivePort(
    HANDLE PortHandle,
    PVOID * PortContext OPTIONAL,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage
);

extern "C" NTSTATUS SCReplyWaitReceivePortEx(
    HANDLE PortHandle,
    PVOID * PortContext OPTIONAL,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCReplyWaitReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage
);

extern "C" NTSTATUS SCRequestPort(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage
);

extern "C" NTSTATUS SCRequestWaitReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage
);

extern "C" NTSTATUS SCResetEvent(
    HANDLE EventHandle,
    PLONG PreviousState OPTIONAL
);

extern "C" NTSTATUS SCResetWriteWatch(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    SIZE_T RegionSize
);

extern "C" NTSTATUS SCRestoreKey(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Flags
);

extern "C" NTSTATUS SCResumeProcess(
    HANDLE ProcessHandle
);

extern "C" NTSTATUS SCResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

extern "C" NTSTATUS SCRevertContainerImpersonation(VOID);

extern "C" NTSTATUS SCRollbackComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCRollbackEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCRollbackRegistryTransaction(
    HANDLE RegistryTransactionHandle,
    ULONG Flags // Reserved
);

extern "C" NTSTATUS SCRollbackTransaction(
    HANDLE TransactionHandle,
    BOOLEAN Wait
);

extern "C" NTSTATUS SCRollforwardTransactionManager(
    HANDLE TransactionManagerHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCSaveKey(
    HANDLE KeyHandle,
    HANDLE FileHandle
);

extern "C" NTSTATUS SCSaveKeyEx(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Format
);

extern "C" NTSTATUS SCSaveMergedKeys(
    HANDLE HighPrecedenceKeyHandle,
    HANDLE LowPrecedenceKeyHandle,
    HANDLE FileHandle
);

extern "C" NTSTATUS SCSecureConnectPort(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    PPORT_VIEW ClientView OPTIONAL,
    PSID RequiredServerSid OPTIONAL,
    PREMOTE_PORT_VIEW ServerView OPTIONAL,
    PULONG MaxMessageLength OPTIONAL,
    PVOID ConnectionInformation OPTIONAL,
    PULONG ConnectionInformationLength OPTIONAL
);

extern "C" NTSTATUS SCSerializeBoot(VOID);

extern "C" NTSTATUS SCSetBootEntryOrder(
    PULONG Ids,
    ULONG Count
);

extern "C" NTSTATUS SCSetBootOptions(
    PBOOT_OPTIONS BootOptions,
    ULONG FieldsToChange
);

extern "C" NTSTATUS SCSetCachedSigningLevel(
    ULONG Flags,
    SE_SIGNING_LEVEL InputSigningLevel,
    PHANDLE SourceFiles,
    ULONG SourceFileCount,
    HANDLE TargetFile OPTIONAL
);

extern "C" NTSTATUS SCSetCachedSigningLevel2(
    ULONG Flags,
    SE_SIGNING_LEVEL InputSigningLevel,
    PHANDLE SourceFiles,
    ULONG SourceFileCount,
    HANDLE TargetFile OPTIONAL,
    SE_SET_FILE_CACHE_INFORMATION * CacheInformation OPTIONAL
);

extern "C" NTSTATUS SCSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

extern "C" NTSTATUS SCSetDebugFilterState(
    ULONG ComponentId,
    ULONG Level,
    BOOLEAN State
);

extern "C" NTSTATUS SCSetDefaultHardErrorPort(
    HANDLE DefaultHardErrorPort
);

extern "C" NTSTATUS SCSetDefaultLocale(
    BOOLEAN UserProfile,
    LCID DefaultLocaleId
);

extern "C" NTSTATUS SCSetDefaultUILanguage(
    LANGID DefaultUILanguageId
);

extern "C" NTSTATUS SCSetDriverEntryOrder(
    PULONG Ids,
    ULONG Count
);

extern "C" NTSTATUS SCSetEaFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length
);

extern "C" NTSTATUS SCSetEvent(
    HANDLE EventHandle,
    PLONG PreviousState OPTIONAL
);

extern "C" NTSTATUS SCSetEventBoostPriority(
    HANDLE EventHandle
);

extern "C" NTSTATUS SCSetHighEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SCSetHighWaitLowEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SCSetIRTimer(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime OPTIONAL
);

extern "C" NTSTATUS SCSetInformationCpuPartition(
    HANDLE CpuPartitionHandle,
    ULONG CpuPartitionInformationClass,
    PVOID CpuPartitionInformation,
    ULONG CpuPartitionInformationLength,
    PVOID Reserved1 OPTIONAL,
    ULONG Reserved2 OPTIONAL,
    ULONG Reserved3 OPTIONAL
);

extern "C" NTSTATUS SCSetInformationDebugObject(
    HANDLE DebugObjectHandle,
    DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
    PVOID DebugInformation,
    ULONG DebugInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCSetInformationEnlistment(
    HANDLE EnlistmentHandle OPTIONAL,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength
);

extern "C" NTSTATUS SCSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

extern "C" NTSTATUS SCSetInformationIoRing(
    HANDLE IoRingHandle,
    ULONG IoRingInformationClass,
    ULONG IoRingInformationLength,
    PVOID IoRingInformation
);

extern "C" NTSTATUS SCSetInformationJobObject(
    HANDLE JobHandle,
    JOBOBJECTINFOCLASS JobObjectInformationClass,
    PVOID JobObjectInformation,
    ULONG JobObjectInformationLength
);

extern "C" NTSTATUS SCSetInformationKey(
    HANDLE KeyHandle,
    KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    PVOID KeySetInformation,
    ULONG KeySetInformationLength
);

extern "C" NTSTATUS SCSetInformationObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength
);

extern "C" NTSTATUS SCSetInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

extern "C" NTSTATUS SCSetInformationResourceManager(
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength
);

extern "C" NTSTATUS SCSetInformationSymbolicLink(
    HANDLE LinkHandle,
    SYMBOLIC_LINK_INFO_CLASS SymbolicLinkInformationClass,
    PVOID SymbolicLinkInformation,
    ULONG SymbolicLinkInformationLength
);

extern "C" NTSTATUS SCSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

extern "C" NTSTATUS SCSetInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength
);

extern "C" NTSTATUS SCSetInformationTransaction(
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength
);

extern "C" NTSTATUS SCSetInformationTransactionManager(
    HANDLE TmHandle OPTIONAL,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    PVOID TransactionManagerInformation,
    ULONG TransactionManagerInformationLength
);

extern "C" NTSTATUS SCSetInformationVirtualMemory(
    HANDLE ProcessHandle,
    VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    SIZE_T NumberOfEntries,
    PMEMORY_RANGE_ENTRY VirtualAddresses,
    PVOID VmInformation,
    ULONG VmInformationLength
);

extern "C" NTSTATUS SCSetInformationWorkerFactory(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
);

extern "C" NTSTATUS SCSetIntervalProfile(
    ULONG Interval,
    KPROFILE_SOURCE Source
);

extern "C" NTSTATUS SCSetIoCompletion(
    HANDLE IoCompletionHandle,
    PVOID KeyContext OPTIONAL,
    PVOID ApcContext OPTIONAL,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

extern "C" NTSTATUS SCSetIoCompletionEx(
    HANDLE IoCompletionHandle,
    HANDLE IoCompletionPacketHandle,
    PVOID KeyContext OPTIONAL,
    PVOID ApcContext OPTIONAL,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

extern "C" NTSTATUS SCSetLdtEntries(
    ULONG Selector0,
    ULONG Entry0Low,
    ULONG Entry0Hi,
    ULONG Selector1,
    ULONG Entry1Low,
    ULONG Entry1Hi
);

extern "C" NTSTATUS SCSetLowEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SCSetLowWaitHighEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SCSetQuotaInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length
);

extern "C" NTSTATUS SCSetSecurityObject(
    HANDLE Handle,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor
);

extern "C" NTSTATUS SCSetSystemEnvironmentValue(
    PCUNICODE_STRING VariableName,
    PCUNICODE_STRING VariableValue
);

extern "C" NTSTATUS SCSetSystemEnvironmentValueEx(
    PCUNICODE_STRING VariableName,
    PCGUID VendorGuid,
    PVOID Buffer OPTIONAL,
    ULONG BufferLength, // 0 = delete variable
    ULONG Attributes // EFI_VARIABLE_*
);

extern "C" NTSTATUS SCSetSystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
);

extern "C" NTSTATUS SCSetSystemPowerState(
    POWER_ACTION SystemAction,
    SYSTEM_POWER_STATE LightestSystemState,
    ULONG Flags // POWER_ACTION_* flags
);

extern "C" NTSTATUS SCSetSystemTime(
    PLARGE_INTEGER SystemTime OPTIONAL,
    PLARGE_INTEGER PreviousTime OPTIONAL
);

extern "C" NTSTATUS SCSetThreadExecutionState(
    EXECUTION_STATE NewFlags, // ES_* flags
    EXECUTION_STATE * PreviousFlags
);

extern "C" NTSTATUS SCSetTimer(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
    PVOID TimerContext OPTIONAL,
    BOOLEAN ResumeTimer,
    LONG Period OPTIONAL,
    PBOOLEAN PreviousState OPTIONAL
);

extern "C" NTSTATUS SCSetTimer2(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PLARGE_INTEGER Period OPTIONAL,
    PT2_SET_PARAMETERS Parameters
);

extern "C" NTSTATUS SCSetTimerEx(
    HANDLE TimerHandle,
    TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
    PVOID TimerSetInformation,
    ULONG TimerSetInformationLength
);

extern "C" NTSTATUS SCSetTimerResolution(
    ULONG DesiredTime,
    BOOLEAN SetResolution,
    PULONG ActualTime
);

extern "C" NTSTATUS SCSetUuidSeed(
    PCHAR Seed
);

extern "C" NTSTATUS SCSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex OPTIONAL,
    ULONG Type,
    PVOID Data OPTIONAL,
    ULONG DataSize
);

extern "C" NTSTATUS SCSetVolumeInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FSINFOCLASS FsInformationClass
);

extern "C" NTSTATUS SCSetWnfProcessNotificationEvent(
    HANDLE NotificationEvent
);

extern "C" NTSTATUS SCShutdownSystem(
    SHUTDOWN_ACTION Action
);

extern "C" NTSTATUS SCShutdownWorkerFactory(
    HANDLE WorkerFactoryHandle,
    volatile LONG * PendingWorkerCount
);

extern "C" NTSTATUS SCSignalAndWaitForSingleObject(
    HANDLE SignalHandle,
    HANDLE WaitHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCSinglePhaseReject(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SCStartProfile(
    HANDLE ProfileHandle
);

extern "C" NTSTATUS SCStopProfile(
    HANDLE ProfileHandle
);

extern "C" NTSTATUS SCSubmitIoRing(
    HANDLE IoRingHandle,
    ULONG Flags,
    ULONG WaitOperations OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCSubscribeWnfStateChange(
    PCWNF_STATE_NAME StateName,
    WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
    ULONG EventMask,
    PULONG64 SubscriptionId OPTIONAL
);

extern "C" NTSTATUS SCSuspendProcess(
    HANDLE ProcessHandle
);

extern "C" NTSTATUS SCSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

extern "C" NTSTATUS SCSystemDebugControl(
    SYSDBG_COMMAND Command,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCTerminateEnclave(
    PVOID BaseAddress,
    ULONG Flags // TERMINATE_ENCLAVE_FLAG_*
);

extern "C" NTSTATUS SCTerminateJobObject(
    HANDLE JobHandle,
    NTSTATUS ExitStatus
);

extern "C" NTSTATUS SCTerminateProcess(
    HANDLE ProcessHandle OPTIONAL,
    NTSTATUS ExitStatus
);

extern "C" NTSTATUS SCTerminateThread(
    HANDLE ThreadHandle OPTIONAL,
    NTSTATUS ExitStatus
);

extern "C" NTSTATUS SCTestAlert(VOID);

extern "C" NTSTATUS SCThawRegistry(VOID);

extern "C" NTSTATUS SCThawTransactions(VOID);

extern "C" NTSTATUS SCTraceControl(
    ETWTRACECONTROLCODE FunctionCode,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SCTraceEvent(
    HANDLE TraceHandle,
    ULONG Flags,
    ULONG FieldSize,
    PVOID Fields
);

extern "C" NTSTATUS SCTranslateFilePath(
    PFILE_PATH InputFilePath,
    ULONG OutputType,
    PFILE_PATH OutputFilePath,
    PULONG OutputFilePathLength OPTIONAL
);

extern "C" NTSTATUS SCUmsThreadYield(
    PVOID SchedulerParam
);

extern "C" NTSTATUS SCUnloadDriver(
    PUNICODE_STRING DriverServiceName
);

extern "C" NTSTATUS SCUnloadKey(
    POBJECT_ATTRIBUTES TargetKey
);

extern "C" NTSTATUS SCUnloadKey2(
    POBJECT_ATTRIBUTES TargetKey,
    ULONG Flags
);

extern "C" NTSTATUS SCUnloadKeyEx(
    POBJECT_ATTRIBUTES TargetKey,
    HANDLE Event OPTIONAL
);

extern "C" NTSTATUS SCUnlockFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER ByteOffset,
    PLARGE_INTEGER Length,
    ULONG Key
);

extern "C" NTSTATUS SCUnlockVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG MapType
);

extern "C" NTSTATUS SCUnsubscribeWnfStateChange(
    PCWNF_STATE_NAME StateName
);

extern "C" NTSTATUS SCUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL
);

extern "C" NTSTATUS SCUnmapViewOfSectionEx(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SCUpdateWnfStateData(
    PCWNF_STATE_NAME StateName,
    const VOID * Buffer OPTIONAL,
    ULONG Length OPTIONAL,
    PCWNF_TYPE_ID TypeId OPTIONAL,
    const VOID * ExplicitScope OPTIONAL,
    WNF_CHANGE_STAMP MatchingChangeStamp,
    LOGICAL CheckStamp
);

extern "C" NTSTATUS SCVdmControl(
    VDMSERVICECLASS Service,
    PVOID ServiceData
);

extern "C" NTSTATUS SCWaitForAlertByThreadId(
    PVOID Address OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCWaitForDebugEvent(
    HANDLE DebugObjectHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL,
    PDBGUI_WAIT_STATE_CHANGE WaitStateChange
);

extern "C" NTSTATUS SCWaitForKeyedEvent(
    HANDLE KeyedEventHandle OPTIONAL,
    PVOID KeyValue,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCWaitForMultipleObjects(
    ULONG Count,
    HANDLE Handles[],
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCWaitForMultipleObjects32(
    ULONG Count,
    LONG Handles[],
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SCWaitForWorkViaWorkerFactory(
    HANDLE WorkerFactoryHandle,
    PFILE_IO_COMPLETION_INFORMATION MiniPackets,
    ULONG Count,
    PULONG PacketsReturned,
    PWORKER_FACTORY_DEFERRED_WORK DeferredWork
);

extern "C" NTSTATUS SCWaitHighEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SCWaitLowEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SCWorkerFactoryWorkerReady(
    HANDLE WorkerFactoryHandle
);

extern "C" NTSTATUS SCWriteFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset OPTIONAL,
    PULONG Key OPTIONAL
);

extern "C" NTSTATUS SCWriteFileGather(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_SEGMENT_ELEMENT SegmentArray,
    ULONG Length,
    PLARGE_INTEGER ByteOffset OPTIONAL,
    PULONG Key OPTIONAL
);

extern "C" NTSTATUS SCWriteRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten OPTIONAL
);

extern "C" NTSTATUS SCWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

extern "C" NTSTATUS SCYieldExecution(VOID);

#endif
