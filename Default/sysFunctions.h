#pragma once
#include "../syscaller.h"
#include "sysTypes.h"
#include "sysExternals.h"

#ifdef _WIN64 /* only compile on 64bit systems */

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS SCAcceptConnectPort(
    PHANDLE PortHandle,
    PVOID PortContext OPTIONAL,
    PPORT_MESSAGE ConnectionRequest,
    BOOLEAN AcceptConnection,
    PPORT_VIEW ServerView OPTIONAL,
    PREMOTE_PORT_VIEW ClientView OPTIONAL
);

NTSTATUS SCAccessCheck(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus
);

NTSTATUS SCAccessCheckAndAuditAlarm(
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

NTSTATUS SCAccessCheckByType(
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

NTSTATUS SCAccessCheckByTypeAndAuditAlarm(
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

NTSTATUS SCAccessCheckByTypeResultList(
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

NTSTATUS SCAccessCheckByTypeResultListAndAuditAlarm(
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

NTSTATUS SCAccessCheckByTypeResultListAndAuditAlarmByHandle(
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

NTSTATUS SCAcquireCrossVmMutant(
    HANDLE CrossVmMutant,
    PLARGE_INTEGER Timeout
);

NTSTATUS SCAcquireProcessActivityReference(
    PHANDLE ActivityReferenceHandle,
    HANDLE ParentProcessHandle,
    PROCESS_ACTIVITY_TYPE Reserved
);

NTSTATUS SCAddAtom(
    PCWSTR AtomName OPTIONAL,
    ULONG Length,
    PRTL_ATOM Atom OPTIONAL
);

NTSTATUS SCAddAtomEx(
    PCWSTR AtomName OPTIONAL,
    ULONG Length,
    PRTL_ATOM Atom OPTIONAL,
    ULONG Flags
);

NTSTATUS SCAddBootEntry(
    PBOOT_ENTRY BootEntry,
    PULONG Id OPTIONAL
);

NTSTATUS SCAddDriverEntry(
    PEFI_DRIVER_ENTRY DriverEntry,
    PULONG Id OPTIONAL
);

NTSTATUS SCAdjustGroupsToken(
    HANDLE TokenHandle,
    BOOLEAN ResetToDefault,
    PTOKEN_GROUPS NewState OPTIONAL,
    ULONG BufferLength OPTIONAL,
    PTOKEN_GROUPS PreviousState OPTIONAL,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState OPTIONAL,
    ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState OPTIONAL,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCAdjustTokenClaimsAndDeviceGroups(
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

NTSTATUS SCAlertResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount OPTIONAL
);

NTSTATUS SCAlertThread(
    HANDLE ThreadHandle
);

NTSTATUS SCAlertThreadByThreadId(
    HANDLE ThreadId
);

NTSTATUS SCAllocateLocallyUniqueId(
    PLUID Luid
);

NTSTATUS SCAllocateReserveObject(
    PHANDLE MemoryReserveHandle,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    MEMORY_RESERVE_TYPE Type
);

NTSTATUS SCAllocateUserPhysicalPages(
    HANDLE ProcessHandle,
    PSIZE_T NumberOfPages,
    PULONG_PTR UserPfnArray
);

NTSTATUS SCAllocateUserPhysicalPagesEx(
    HANDLE ProcessHandle,
    PULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray,
    PMEM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount
);

NTSTATUS SCAllocateUuids(
    PULARGE_INTEGER Time,
    PULONG Range,
    PULONG Sequence,
    PCHAR Seed
);

NTSTATUS SCAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
);

NTSTATUS SCAllocateVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount
);

NTSTATUS SCAlpcAcceptConnectPort(
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

NTSTATUS SCAlpcCancelMessage(
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_CONTEXT_ATTR MessageContext
);

NTSTATUS SCAlpcConnectPort(
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

NTSTATUS SCAlpcConnectPortEx(
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

NTSTATUS SCAlpcCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL
);

NTSTATUS SCAlpcCreatePortSection(
    HANDLE PortHandle,
    ULONG Flags,
    HANDLE SectionHandle OPTIONAL,
    SIZE_T SectionSize,
    PALPC_HANDLE AlpcSectionHandle,
    PSIZE_T ActualSectionSize
);

NTSTATUS SCAlpcCreateResourceReserve(
    HANDLE PortHandle,
    ULONG Flags,
    SIZE_T MessageSize,
    PALPC_HANDLE ResourceId
);

NTSTATUS SCAlpcCreateSectionView(
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_DATA_VIEW_ATTR ViewAttributes
);

NTSTATUS SCAlpcCreateSecurityContext(
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_SECURITY_ATTR SecurityAttribute
);

NTSTATUS SCAlpcDeletePortSection(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE SectionHandle
);

NTSTATUS SCAlpcDeleteResourceReserve(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE ResourceId
);

NTSTATUS SCAlpcDeleteSectionView(
    HANDLE PortHandle,
    ULONG Flags,
    PVOID ViewBase
);

NTSTATUS SCAlpcDeleteSecurityContext(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE ContextHandle
);

NTSTATUS SCAlpcDisconnectPort(
    HANDLE PortHandle,
    ULONG Flags
);

NTSTATUS SCAlpcImpersonateClientContainerOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG Flags
);

NTSTATUS SCAlpcImpersonateClientOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    PVOID Flags
);

NTSTATUS SCAlpcOpenSenderProcess(
    PHANDLE ProcessHandle,
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ULONG Flags,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCAlpcOpenSenderThread(
    PHANDLE ThreadHandle,
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ULONG Flags,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCAlpcQueryInformation(
    HANDLE PortHandle OPTIONAL,
    ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCAlpcQueryInformationMessage(
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
    PVOID MessageInformation,
    ULONG Length,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCAlpcRevokeSecurityContext(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE ContextHandle
);

NTSTATUS SCAlpcSendWaitReceivePort(
    HANDLE PortHandle,
    ULONG Flags,
    PPORT_MESSAGE SendMessage OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
    PPORT_MESSAGE ReceiveMessage OPTIONAL,
    PSIZE_T BufferLength OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCAlpcSetInformation(
    HANDLE PortHandle,
    ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation OPTIONAL,
    ULONG Length
);

NTSTATUS SCApphelpCacheControl(
    ULONG Command,
    PVOID Buffer OPTIONAL,
    ULONG BufferSize
);

NTSTATUS SCAreMappedFilesTheSame(
    PVOID File1MappedAsAnImage,
    PVOID File2MappedAsFile
);

NTSTATUS SCAssignProcessToJobObject(
    HANDLE JobHandle,
    HANDLE ProcessHandle
);

NTSTATUS SCAssociateWaitCompletionPacket(
    HANDLE WaitCompletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID KeyContext OPTIONAL,
    PVOID ApcContext OPTIONAL,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled OPTIONAL
);

NTSTATUS SCCallEnclave(
    PENCLAVE_ROUTINE Routine,
    PVOID Reserved,
    ULONG Flags,
    PVOID * RoutineParamReturn
);

NTSTATUS SCCallbackReturn(
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputLength,
    NTSTATUS Status
);

NTSTATUS SCCancelIoFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
);

NTSTATUS SCCancelIoFileEx(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock
);

NTSTATUS SCCancelSynchronousIoFile(
    HANDLE ThreadHandle,
    PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock
);

NTSTATUS SCCancelTimer(
    HANDLE TimerHandle,
    PBOOLEAN CurrentState OPTIONAL
);

NTSTATUS SCCancelTimer2(
    HANDLE TimerHandle,
    PT2_CANCEL_PARAMETERS Parameters
);

NTSTATUS SCCancelWaitCompletionPacket(
    HANDLE WaitCompletionPacketHandle,
    BOOLEAN RemoveSignaledPacket
);

NTSTATUS SCChangeProcessState(
    HANDLE ProcessStateChangeHandle,
    HANDLE ProcessHandle,
    PROCESS_STATE_CHANGE_TYPE StateChangeType,
    PVOID ExtendedInformation OPTIONAL,
    SIZE_T ExtendedInformationLength OPTIONAL,
    ULONG64 Reserved OPTIONAL
);

NTSTATUS SCChangeThreadState(
    HANDLE ThreadStateChangeHandle,
    HANDLE ThreadHandle,
    THREAD_STATE_CHANGE_TYPE StateChangeType,
    PVOID ExtendedInformation OPTIONAL,
    SIZE_T ExtendedInformationLength OPTIONAL,
    ULONG64 Reserved OPTIONAL
);

NTSTATUS SCClearEvent(
    HANDLE EventHandle
);

NTSTATUS SCClose(
    HANDLE Handle
);

NTSTATUS SCCloseObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    BOOLEAN GenerateOnClose
);

NTSTATUS SCCommitComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCCommitEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCCommitRegistryTransaction(
    HANDLE RegistryTransactionHandle,
    ULONG Flags /* reserved */
);

NTSTATUS SCCommitTransaction(
    HANDLE TransactionHandle,
    BOOLEAN Wait
);

NTSTATUS SCCompactKeys(
    ULONG Count,
    HANDLE KeyArray[]
);

NTSTATUS SCCompareObjects(
    HANDLE FirstObjectHandle,
    HANDLE SecondObjectHandle
);

NTSTATUS SCCompareSigningLevels(
    SE_SIGNING_LEVEL FirstSigningLevel,
    SE_SIGNING_LEVEL SecondSigningLevel
);

NTSTATUS SCCompareTokens(
    HANDLE FirstTokenHandle,
    HANDLE SecondTokenHandle,
    PBOOLEAN Equal
);

NTSTATUS SCCompleteConnectPort(
    HANDLE PortHandle
);

NTSTATUS SCCompressKey(
    HANDLE KeyHandle
);

NTSTATUS SCConnectPort(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    PPORT_VIEW ClientView OPTIONAL,
    PREMOTE_PORT_VIEW ServerView OPTIONAL,
    PULONG MaxMessageLength OPTIONAL,
    PVOID ConnectionInformation OPTIONAL,
    PULONG ConnectionInformationLength OPTIONAL
);

NTSTATUS SCContinue(
    PCONTEXT ContextRecord,
    BOOLEAN TestAlert
);

NTSTATUS SCContinueEx(
    PCONTEXT ContextRecord,
    PVOID ContinueArgument /* can be PKCONTINUE_ARGUMENT or BOOLEAN */
);

NTSTATUS SCConvertBetweenAuxiliaryCounterAndPerformanceCounter(
    BOOLEAN ConvertAuxiliaryToPerformanceCounter,
    PULONG64 PerformanceOrAuxiliaryCounterValue,
    PULONG64 ConvertedValue,
    PULONG64 ConversionError OPTIONAL
);

NTSTATUS SCCopyFileChunk(
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

NTSTATUS SCCreateCpuPartition(
    PHANDLE CpuPartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

NTSTATUS SCCreateCrossVmEvent(
    PHANDLE CrossVmEvent,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CrossVmEventFlags,
    LPCGUID VMID,
    LPCGUID ServiceID
);

NTSTATUS SCCreateCrossVmMutant(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CrossVmEventFlags,
    LPCGUID VMID,
    LPCGUID ServiceID
);

NTSTATUS SCCreateDebugObject(
    PHANDLE DebugObjectHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Flags
);

NTSTATUS SCCreateDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCCreateDirectoryObjectEx(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ShadowDirectoryHandle,
    ULONG Flags
);

NTSTATUS SCCreateEnclave(
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

NTSTATUS SCCreateEnlistment(
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    HANDLE TransactionHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    NOTIFICATION_MASK NotificationMask,
    PVOID EnlistmentKey OPTIONAL
);

NTSTATUS SCCreateEvent(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    EVENT_TYPE EventType,
    BOOLEAN InitialState
);

NTSTATUS SCCreateEventPair(
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

NTSTATUS SCCreateFile(
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

NTSTATUS SCCreateIRTimer(
    PHANDLE TimerHandle,
    PVOID Reserved,
    ACCESS_MASK DesiredAccess
);

NTSTATUS SCCreateIoCompletion(
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG NumberOfConcurrentThreads OPTIONAL
);

NTSTATUS SCCreateIoRing(
    PHANDLE IoRingHandle,
    ULONG CreateParametersLength,
    PVOID CreateParameters,
    ULONG OutputParametersLength,
    PVOID OutputParameters
);

NTSTATUS SCCreateJobObject(
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

NTSTATUS SCCreateJobSet(
    ULONG NumJob,
    PJOB_SET_ARRAY UserJobSet,
    ULONG Flags
);

NTSTATUS SCCreateKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class OPTIONAL,
    ULONG CreateOptions,
    PULONG Disposition OPTIONAL
);

NTSTATUS SCCreateKeyTransacted(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class OPTIONAL,
    ULONG CreateOptions,
    HANDLE TransactionHandle,
    PULONG Disposition OPTIONAL
);

NTSTATUS SCCreateKeyedEvent(
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Flags
);

NTSTATUS SCCreateLowBoxToken(
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

NTSTATUS SCCreateMailslotFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CreateOptions,
    ULONG MailslotQuota,
    ULONG MaximumMessageSize,
    PLARGE_INTEGER ReadTimeout
);

NTSTATUS SCCreateMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    BOOLEAN InitialOwner
);

NTSTATUS SCCreateNamedPipeFile(
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

NTSTATUS SCCreatePagingFile(
    PUNICODE_STRING PageFileName,
    PLARGE_INTEGER MinimumSize,
    PLARGE_INTEGER MaximumSize,
    ULONG Priority
);

NTSTATUS SCCreatePartition(
    HANDLE ParentPartitionHandle OPTIONAL,
    PHANDLE PartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG PreferredNode
);

NTSTATUS SCCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG MaxConnectionInfoLength,
    ULONG MaxMessageLength,
    ULONG MaxPoolUsage OPTIONAL
);

NTSTATUS SCCreatePrivateNamespace(
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor
);

NTSTATUS SCCreateProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE TokenHandle OPTIONAL
);

NTSTATUS SCCreateProcessEx(
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

NTSTATUS SCCreateProcessStateChange(
    PHANDLE ProcessStateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    ULONG64 Reserved OPTIONAL
);

NTSTATUS SCCreateProfile(
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

NTSTATUS SCCreateProfileEx(
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

NTSTATUS SCCreateRegistryTransaction(
    PHANDLE RegistryTransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions
);

NTSTATUS SCCreateResourceManager(
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID RmGuid,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    PUNICODE_STRING Description OPTIONAL
);

NTSTATUS SCCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

NTSTATUS SCCreateSectionEx(
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

NTSTATUS SCCreateSemaphore(
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    LONG InitialCount,
    LONG MaximumCount
);

NTSTATUS SCCreateSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING LinkTarget
);

NTSTATUS SCCreateThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    CLIENT_ID * ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended
);

NTSTATUS SCCreateThreadEx(
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

NTSTATUS SCCreateThreadStateChange(
    PHANDLE ThreadStateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ThreadHandle,
    ULONG64 Reserved OPTIONAL
);

NTSTATUS SCCreateTimer(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    TIMER_TYPE TimerType
);

NTSTATUS SCCreateTimer2(
    PHANDLE TimerHandle,
    PVOID Reserved1 OPTIONAL,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Attributes,
    ACCESS_MASK DesiredAccess
);

NTSTATUS SCCreateToken(
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

NTSTATUS SCCreateTokenEx(
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

NTSTATUS SCCreateTransaction(
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

NTSTATUS SCCreateTransactionManager(
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PUNICODE_STRING LogFileName OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    ULONG CommitStrength OPTIONAL
);

NTSTATUS SCCreateUserProcess(
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

NTSTATUS SCCreateWaitCompletionPacket(
    PHANDLE WaitCompletionPacketHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

NTSTATUS SCCreateWaitablePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG MaxConnectionInfoLength,
    ULONG MaxMessageLength,
    ULONG MaxPoolUsage OPTIONAL
);

NTSTATUS SCCreateWnfStateName(
    PWNF_STATE_NAME StateName,
    WNF_STATE_NAME_LIFETIME NameLifetime,
    WNF_DATA_SCOPE DataScope,
    BOOLEAN PersistData,
    PCWNF_TYPE_ID TypeId OPTIONAL,
    ULONG MaximumStateSize,
    PSECURITY_DESCRIPTOR SecurityDescriptor
);

NTSTATUS SCCreateWorkerFactory(
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

NTSTATUS SCDebugActiveProcess(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
);

NTSTATUS SCDebugContinue(
    HANDLE DebugObjectHandle,
    CLIENT_ID * ClientId,
    NTSTATUS ContinueStatus
);

NTSTATUS SCDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
);

NTSTATUS SCDeleteAtom(
    PRTL_ATOM Atom
);

NTSTATUS SCDeleteBootEntry(
    ULONG Id
);

NTSTATUS SCDeleteDriverEntry(
    ULONG Id
);

NTSTATUS SCDeleteFile(
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCDeleteKey(
    HANDLE KeyHandle
);

NTSTATUS SCDeleteObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    BOOLEAN GenerateOnClose
);

NTSTATUS SCDeletePrivateNamespace(
    HANDLE NamespaceHandle
);

NTSTATUS SCDeleteValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName
);

NTSTATUS SCDeleteWnfStateData(
    PCWNF_STATE_NAME StateName,
    const VOID * ExplicitScope OPTIONAL
);

NTSTATUS SCDeleteWnfStateName(
    PCWNF_STATE_NAME StateName
);

NTSTATUS SCDeviceIoControlFile(
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

NTSTATUS SCDirectGraphicsCall(
    ULONG InputBufferLength,
    PVOID InputBuffer OPTIONAL,
    ULONG OutputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    PULONG ReturnLength
);

NTSTATUS SCDisableLastKnownGood(VOID);

NTSTATUS SCDisplayString(
    PUNICODE_STRING String
);

NTSTATUS SCDrawText(
    PUNICODE_STRING Text
);

NTSTATUS SCDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle OPTIONAL,
    PHANDLE TargetHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

NTSTATUS SCDuplicateToken(
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE Type,
    PHANDLE NewTokenHandle
);

NTSTATUS SCEnableLastKnownGood(VOID);

NTSTATUS SCEnumerateBootEntries(
    PVOID Buffer OPTIONAL,
    PULONG BufferLength
);

NTSTATUS SCEnumerateDriverEntries(
    PVOID Buffer OPTIONAL,
    PULONG BufferLength
);

NTSTATUS SCEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation OPTIONAL,
    ULONG Length,
    PULONG ResultLength
);

NTSTATUS SCEnumerateSystemEnvironmentValuesEx(
    ULONG InformationClass,
    PVOID Buffer,
    PULONG BufferLength
);

NTSTATUS SCEnumerateTransactionObject(
    HANDLE RootObjectHandle OPTIONAL,
    KTMOBJECT_TYPE QueryType,
    PKTMOBJECT_CURSOR ObjectCursor,
    ULONG ObjectCursorLength,
    PULONG ReturnLength
);

NTSTATUS SCEnumerateValueKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation OPTIONAL,
    ULONG Length,
    PULONG ResultLength
);

NTSTATUS SCExtendSection(
    HANDLE SectionHandle,
    PLARGE_INTEGER NewSectionSize
);

NTSTATUS SCFilterBootOption(
    FILTER_BOOT_OPTION_OPERATION FilterOperation,
    ULONG ObjectType,
    ULONG ElementType,
    PVOID Data OPTIONAL,
    ULONG DataSize
);

NTSTATUS SCFilterToken(
    HANDLE ExistingTokenHandle,
    ULONG Flags,
    PTOKEN_GROUPS SidsToDisable OPTIONAL,
    PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
    PTOKEN_GROUPS RestrictedSids OPTIONAL,
    PHANDLE NewTokenHandle
);

NTSTATUS SCFilterTokenEx(
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

NTSTATUS SCFindAtom(
    PCWSTR AtomName OPTIONAL,
    ULONG Length,
    PRTL_ATOM Atom OPTIONAL
);

NTSTATUS SCFlushBuffersFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
);

NTSTATUS SCFlushBuffersFileEx(
    HANDLE FileHandle,
    ULONG Flags,
    PVOID Parameters,
    ULONG ParametersSize,
    PIO_STATUS_BLOCK IoStatusBlock
);

NTSTATUS SCFlushInstallUILanguage(
    LANGID InstallUILanguage,
    ULONG SetCommittedFlag
);

NTSTATUS SCFlushInstructionCache(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    SIZE_T Length
);

NTSTATUS SCFlushKey(
    HANDLE KeyHandle
);

NTSTATUS SCFlushProcessWriteBuffers(VOID);

NTSTATUS SCFlushVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    PIO_STATUS_BLOCK IoStatus
);

NTSTATUS SCFlushWriteBuffer(VOID);

NTSTATUS SCFreeUserPhysicalPages(
    HANDLE ProcessHandle,
    PULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray
);

NTSTATUS SCFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

NTSTATUS SCFreezeRegistry(
    ULONG TimeOutInSeconds
);

NTSTATUS SCFreezeTransactions(
    PLARGE_INTEGER FreezeTimeout,
    PLARGE_INTEGER ThawTimeout
);

NTSTATUS SCFsControlFile(
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

NTSTATUS SCGetCachedSigningLevel(
    HANDLE File,
    PULONG Flags,
    PSE_SIGNING_LEVEL SigningLevel,
    PUCHAR Thumbprint OPTIONAL,
    PULONG ThumbprintSize OPTIONAL,
    PULONG ThumbprintAlgorithm OPTIONAL
);

NTSTATUS SCGetCompleteWnfStateSubscription(
    PWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
    ULONG64 * OldSubscriptionId OPTIONAL,
    ULONG OldDescriptorEventMask,
    ULONG OldDescriptorStatus,
    PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
    ULONG DescriptorSize
);

NTSTATUS SCGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

ULONG SCGetCurrentProcessorNumber(VOID);

ULONG SCGetCurrentProcessorNumberEx(
    PPROCESSOR_NUMBER ProcessorNumber OPTIONAL
);

NTSTATUS SCGetDevicePowerState(
    HANDLE Device,
    PDEVICE_POWER_STATE State
);

NTSTATUS SCGetMUIRegistryInfo(
    ULONG Flags,
    PULONG DataSize,
    PVOID Data
);

NTSTATUS SCGetNextProcess(
    HANDLE ProcessHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
);

NTSTATUS SCGetNextThread(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
);

NTSTATUS SCGetNlsSectionPtr(
    ULONG SectionType,
    ULONG SectionData,
    PVOID ContextData,
    PVOID * SectionPointer,
    PULONG SectionSize
);

NTSTATUS SCGetNotificationResourceManager(
    HANDLE ResourceManagerHandle,
    PTRANSACTION_NOTIFICATION TransactionNotification,
    ULONG NotificationLength,
    PLARGE_INTEGER Timeout OPTIONAL,
    PULONG ReturnLength OPTIONAL,
    ULONG Asynchronous,
    ULONG_PTR AsynchronousContext OPTIONAL
);

NTSTATUS SCGetWriteWatch(
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID BaseAddress,
    SIZE_T RegionSize,
    PVOID * UserAddressArray,
    PULONG_PTR EntriesInUserAddressArray,
    PULONG Granularity
);

NTSTATUS SCImpersonateAnonymousToken(
    HANDLE ThreadHandle
);

NTSTATUS SCImpersonateClientOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message
);

NTSTATUS SCImpersonateThread(
    HANDLE ServerThreadHandle,
    HANDLE ClientThreadHandle,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos
);

NTSTATUS SCInitializeEnclave(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID EnclaveInformation,
    ULONG EnclaveInformationLength,
    PULONG EnclaveError OPTIONAL
);

NTSTATUS SCInitializeNlsFiles(
    PVOID * BaseAddress,
    PLCID DefaultLocaleId,
    PLARGE_INTEGER DefaultCasingTableSize,
    PULONG CurrentNLSVersion OPTIONAL
);

NTSTATUS SCInitializeRegistry(
    USHORT BootCondition
);

NTSTATUS SCInitiatePowerAction(
    POWER_ACTION SystemAction,
    SYSTEM_POWER_STATE LightestSystemState,
    ULONG Flags,
    BOOLEAN Asynchronous
);

NTSTATUS SCIsProcessInJob(
    HANDLE ProcessHandle,
    HANDLE JobHandle OPTIONAL
);

NTSTATUS SCIsSystemResumeAutomatic(VOID);

NTSTATUS SCIsUILanguageComitted(VOID);

NTSTATUS SCListenPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ConnectionRequest
);

NTSTATUS SCLoadDriver(
    PUNICODE_STRING DriverServiceName
);

NTSTATUS SCLoadEnclaveData(
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

NTSTATUS SCLoadKey(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile
);

NTSTATUS SCLoadKey2(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags
);

NTSTATUS SCLoadKey3(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    PCM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount,
    ACCESS_MASK DesiredAccess OPTIONAL,
    PHANDLE RootHandle OPTIONAL,
    PVOID Reserved OPTIONAL
);

NTSTATUS SCLoadKeyEx(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    HANDLE TrustClassKey OPTIONAL,
    HANDLE Event OPTIONAL,
    ACCESS_MASK DesiredAccess OPTIONAL,
    PHANDLE RootHandle OPTIONAL,
    PVOID Reserved OPTIONAL /* previously PIO_STATUS_BLOCK */
);

NTSTATUS SCLockFile(
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

NTSTATUS SCLockProductActivationKeys(
    ULONG * pPrivateVer OPTIONAL,
    ULONG * pSafeMode OPTIONAL
);

NTSTATUS SCLockRegistryKey(
    HANDLE KeyHandle
);

NTSTATUS SCLockVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG MapType
);

NTSTATUS SCMakePermanentObject(
    HANDLE Handle
);

NTSTATUS SCMakeTemporaryObject(
    HANDLE Handle
);

NTSTATUS SCManageHotPatch(
    HANDLE ProcessHandle,
    ULONG Operation,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength
);

NTSTATUS SCManagePartition(
    HANDLE TargetHandle,
    HANDLE SourceHandle OPTIONAL,
    PARTITION_INFORMATION_CLASS PartitionInformationClass,
    PVOID PartitionInformation,
    ULONG PartitionInformationLength
);

NTSTATUS SCMapCMFModule(
    ULONG What,
    ULONG Index,
    PULONG CacheIndexOut OPTIONAL,
    PULONG CacheFlagsOut OPTIONAL,
    PULONG ViewSizeOut OPTIONAL,
    PVOID * BaseAddress OPTIONAL
);

NTSTATUS SCMapUserPhysicalPages(
    PVOID VirtualAddress,
    SIZE_T NumberOfPages,
    PULONG_PTR UserPfnArray OPTIONAL
);

NTSTATUS SCMapUserPhysicalPagesScatter(
    PVOID * VirtualAddresses,
    SIZE_T NumberOfPages,
    PULONG_PTR UserPfnArray OPTIONAL
);

NTSTATUS SCMapViewOfSection(
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

NTSTATUS SCMapViewOfSectionEx(
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

NTSTATUS SCModifyBootEntry(
    PBOOT_ENTRY BootEntry
);

NTSTATUS SCModifyDriverEntry(
    PEFI_DRIVER_ENTRY DriverEntry
);

NTSTATUS SCNotifyChangeDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, /* FILE_NOTIFY_INFORMATION */
    ULONG Length,
    ULONG CompletionFilter,
    BOOLEAN WatchTree
);

NTSTATUS SCNotifyChangeDirectoryFileEx(
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

NTSTATUS SCNotifyChangeKey(
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

NTSTATUS SCNotifyChangeMultipleKeys(
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

NTSTATUS SCNotifyChangeSession(
    HANDLE SessionHandle,
    ULONG ChangeSequenceNumber,
    PLARGE_INTEGER ChangeTimeStamp,
    IO_SESSION_EVENT Event,
    IO_SESSION_STATE NewState,
    IO_SESSION_STATE PreviousState,
    PVOID Payload OPTIONAL,
    ULONG PayloadSize
);

NTSTATUS SCOpenCpuPartition(
    PHANDLE CpuPartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

NTSTATUS SCOpenEnlistment(
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    LPGUID EnlistmentGuid,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

NTSTATUS SCOpenEvent(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenEventPair(
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

NTSTATUS SCOpenIoCompletion(
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenJobObject(
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenKeyEx(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions
);

NTSTATUS SCOpenKeyTransacted(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE TransactionHandle
);

NTSTATUS SCOpenKeyTransactedEx(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions,
    HANDLE TransactionHandle
);

NTSTATUS SCOpenKeyedEvent(
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenObjectAuditAlarm(
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

NTSTATUS SCOpenPartition(
    PHANDLE PartitionHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenPrivateNamespace(
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor
);

NTSTATUS SCOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID * ClientId OPTIONAL
);

NTSTATUS SCOpenProcessToken(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle
);

NTSTATUS SCOpenProcessTokenEx(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    PHANDLE TokenHandle
);

NTSTATUS SCOpenRegistryTransaction(
    HANDLE * RegistryTransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjAttributes
);

NTSTATUS SCOpenResourceManager(
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID ResourceManagerGuid OPTIONAL,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

NTSTATUS SCOpenSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenSemaphore(
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenSession(
    PHANDLE SessionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID * ClientId OPTIONAL
);

NTSTATUS SCOpenThreadToken(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    PHANDLE TokenHandle
);

NTSTATUS SCOpenThreadTokenEx(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    ULONG HandleAttributes,
    PHANDLE TokenHandle
);

NTSTATUS SCOpenTimer(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SCOpenTransaction(
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    LPGUID Uow,
    HANDLE TmHandle OPTIONAL
);

NTSTATUS SCOpenTransactionManager(
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PUNICODE_STRING LogFileName OPTIONAL,
    LPGUID TmIdentity OPTIONAL,
    ULONG OpenOptions OPTIONAL
);

NTSTATUS SCPlugPlayControl(
    PLUGPLAY_CONTROL_CLASS PnPControlClass,
    PVOID PnPControlData OPTIONAL,
    ULONG PnPControlDataLength
);

NTSTATUS SCPowerInformation(
    POWER_INFORMATION_LEVEL InformationLevel,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength
);

NTSTATUS SCPrePrepareComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCPrePrepareEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCPrepareComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCPrepareEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCPrivilegeCheck(
    HANDLE ClientToken,
    PPRIVILEGE_SET RequiredPrivileges,
    PBOOLEAN Result
);

NTSTATUS SCPrivilegeObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    PPRIVILEGE_SET Privileges,
    BOOLEAN AccessGranted
);

NTSTATUS SCPrivilegedServiceAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PUNICODE_STRING ServiceName,
    HANDLE ClientToken,
    PPRIVILEGE_SET Privileges,
    BOOLEAN AccessGranted
);

NTSTATUS SCPropagationComplete(
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    ULONG BufferLength,
    PVOID Buffer
);

NTSTATUS SCPropagationFailed(
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    NTSTATUS PropStatus
);

NTSTATUS SCProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

NTSTATUS SCPssCaptureVaSpaceBulk(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    PNTPSS_MEMORY_BULK_INFORMATION BulkInformation,
    SIZE_T BulkInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

NTSTATUS SCPulseEvent(
    HANDLE EventHandle,
    PLONG PreviousState OPTIONAL
);

NTSTATUS SCQueryAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
);

NTSTATUS SCQueryAuxiliaryCounterFrequency(
    PULONG64 AuxiliaryCounterFrequency
);

NTSTATUS SCQueryBootEntryOrder(
    PULONG Ids OPTIONAL,
    PULONG Count
);

NTSTATUS SCQueryBootOptions(
    PBOOT_OPTIONS BootOptions OPTIONAL,
    PULONG BootOptionsLength
);

NTSTATUS SCQueryDebugFilterState(
    ULONG ComponentId,
    ULONG Level
);

NTSTATUS SCQueryDefaultLocale(
    BOOLEAN UserProfile,
    PLCID DefaultLocaleId
);

NTSTATUS SCQueryDefaultUILanguage(
    LANGID * DefaultUILanguageId
);

NTSTATUS SCQueryDirectoryFile(
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

NTSTATUS SCQueryDirectoryFileEx(
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

NTSTATUS SCQueryDirectoryObject(
    HANDLE DirectoryHandle,
    PVOID Buffer OPTIONAL,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryDriverEntryOrder(
    PULONG Ids OPTIONAL,
    PULONG Count
);

NTSTATUS SCQueryEaFile(
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

NTSTATUS SCQueryEvent(
    HANDLE EventHandle,
    EVENT_INFORMATION_CLASS EventInformationClass,
    PVOID EventInformation,
    ULONG EventInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryFullAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_NETWORK_OPEN_INFORMATION FileInformation
);

NTSTATUS SCQueryInformationAtom(
    PRTL_ATOM Atom,
    ATOM_INFORMATION_CLASS AtomInformationClass,
    PVOID AtomInformation,
    ULONG AtomInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationByName(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS SCQueryInformationCpuPartition(
    HANDLE PartitionHandle OPTIONAL,
    CPU_PARTITION_INFORMATION_CLASS PartitionInformationClass,
    PVOID PartitionInformation,
    ULONG PartitionInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationEnlistment(
    HANDLE EnlistmentHandle,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS SCQueryInformationJobObject(
    HANDLE JobHandle OPTIONAL,
    JOBOBJECTINFOCLASS JobObjectInformationClass,
    PVOID JobObjectInformation,
    ULONG JobObjectInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationPort(
    HANDLE PortHandle,
    PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationResourceManager(
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationTransaction(
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationTransactionManager(
    HANDLE TransactionManagerHandle,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    PVOID TransactionManagerInformation,
    ULONG TransactionManagerInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInformationWorkerFactory(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryInstallUILanguage(
    LANGID * InstallUILanguageId
);

NTSTATUS SCQueryIntervalProfile(
    KPROFILE_SOURCE ProfileSource,
    PULONG Interval
);

NTSTATUS SCQueryIoCompletion(
    HANDLE IoCompletionHandle,
    IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    PVOID IoCompletionInformation,
    ULONG IoCompletionInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryIoRingCapabilities(
    SIZE_T IoRingCapabilitiesLength,
    PVOID IoRingCapabilities
);

NTSTATUS SCQueryKey(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength OPTIONAL
);

NTSTATUS SCQueryLicenseValue(
    PUNICODE_STRING ValueName,
    PULONG Type OPTIONAL,
    PVOID Data OPTIONAL,
    ULONG DataSize,
    PULONG ResultDataSize
);

NTSTATUS SCQueryMultipleValueKey(
    HANDLE KeyHandle,
    PKEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount,
    PVOID ValueBuffer,
    PULONG BufferLength,
    PULONG RequiredBufferLength OPTIONAL
);

NTSTATUS SCQueryMutant(
    HANDLE MutantHandle,
    MUTANT_INFORMATION_CLASS MutantInformationClass,
    PVOID MutantInformation,
    ULONG MutantInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation OPTIONAL,
    ULONG ObjectInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryOpenSubKeys(
    POBJECT_ATTRIBUTES TargetKey,
    PULONG HandleCount
);

NTSTATUS SCQueryOpenSubKeysEx(
    POBJECT_ATTRIBUTES TargetKey,
    ULONG BufferLength,
    PVOID Buffer,
    PULONG RequiredSize
);

NTSTATUS SCQueryPerformanceCounter(
    PLARGE_INTEGER PerformanceCounter,
    PLARGE_INTEGER PerformanceFrequency OPTIONAL
);

NTSTATUS SCQueryPortInformationProcess(VOID);

NTSTATUS SCQueryQuotaInformationFile(
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

NTSTATUS SCQuerySection(
    HANDLE SectionHandle,
    SECTION_INFORMATION_CLASS SectionInformationClass,
    PVOID SectionInformation,
    SIZE_T SectionInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

NTSTATUS SCQuerySecurityAttributesToken(
    HANDLE TokenHandle,
    PUNICODE_STRING Attributes,
    ULONG NumberOfAttributes,
    PVOID Buffer, /* PTOKEN_SECURITY_ATTRIBUTES_INFORMATION */
    ULONG Length,
    PULONG ReturnLength
);

NTSTATUS SCQuerySecurityObject(
    HANDLE Handle,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG Length,
    PULONG LengthNeeded
);

NTSTATUS SCQuerySecurityPolicy(
    PCUNICODE_STRING Policy,
    PCUNICODE_STRING KeyName,
    PCUNICODE_STRING ValueName,
    SECURE_SETTING_VALUE_TYPE ValueType,
    PVOID Value OPTIONAL,
    PULONG ValueSize
);

NTSTATUS SCQuerySemaphore(
    HANDLE SemaphoreHandle,
    SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    PVOID SemaphoreInformation,
    ULONG SemaphoreInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQuerySymbolicLinkObject(
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength OPTIONAL
);

NTSTATUS SCQuerySystemEnvironmentValue(
    PUNICODE_STRING VariableName,
    PWSTR VariableValue,
    USHORT ValueLength,
    PUSHORT ReturnLength OPTIONAL
);

NTSTATUS SCQuerySystemEnvironmentValueEx(
    PCUNICODE_STRING VariableName,
    PCGUID VendorGuid,
    PVOID Buffer OPTIONAL,
    PULONG BufferLength,
    PULONG Attributes OPTIONAL /* EFI_VARIABLE_* */
);

NTSTATUS SCQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSTATUS SCQuerySystemInformationEx(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryTimer(
    HANDLE TimerHandle,
    TIMER_INFORMATION_CLASS TimerInformationClass,
    PVOID TimerInformation,
    ULONG TimerInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCQueryTimerResolution(
    PULONG MaximumTime,
    PULONG MinimumTime,
    PULONG CurrentTime
);

NTSTATUS SCQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);

NTSTATUS SCQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

NTSTATUS SCQueryVolumeInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FSINFOCLASS FsInformationClass
);

NTSTATUS SCQueryWnfStateData(
    PCWNF_STATE_NAME StateName,
    PCWNF_TYPE_ID TypeId OPTIONAL,
    const VOID * ExplicitScope OPTIONAL,
    PWNF_CHANGE_STAMP ChangeStamp,
    PVOID Buffer OPTIONAL,
    PULONG BufferSize
);

NTSTATUS SCQueryWnfStateNameInformation(
    PCWNF_STATE_NAME StateName,
    WNF_STATE_NAME_INFORMATION NameInfoClass,
    const VOID * ExplicitScope OPTIONAL,
    PVOID InfoBuffer,
    ULONG InfoBufferSize
);

NTSTATUS SCQueueApcThread(
    HANDLE ThreadHandle,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL
);

NTSTATUS SCQueueApcThreadEx(
    HANDLE ThreadHandle,
    HANDLE ReserveHandle OPTIONAL,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL
);

NTSTATUS SCQueueApcThreadEx2(
    HANDLE ThreadHandle,
    HANDLE ReserveHandle OPTIONAL,
    ULONG ApcFlags,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL
);

NTSTATUS SCRaiseException(
    PEXCEPTION_RECORD ExceptionRecord,
    PCONTEXT ContextRecord,
    BOOLEAN FirstChance
);

NTSTATUS SCRaiseHardError(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters,
    ULONG ValidResponseOptions,
    PULONG Response
);

NTSTATUS SCReadFile(
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

NTSTATUS SCReadFileScatter(
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

NTSTATUS SCReadOnlyEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCReadRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead OPTIONAL
);

NTSTATUS SCReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead OPTIONAL
);

NTSTATUS SCReadVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead OPTIONAL,
    ULONG Flags
);

NTSTATUS SCRecoverEnlistment(
    HANDLE EnlistmentHandle,
    PVOID EnlistmentKey OPTIONAL
);

NTSTATUS SCRecoverResourceManager(
    HANDLE ResourceManagerHandle
);

NTSTATUS SCRecoverTransactionManager(
    HANDLE TransactionManagerHandle
);

NTSTATUS SCRegisterProtocolAddressInformation(
    HANDLE ResourceManager,
    PCRM_PROTOCOL_ID ProtocolId,
    ULONG ProtocolInformationSize,
    PVOID ProtocolInformation,
    ULONG CreateOptions
);

NTSTATUS SCRegisterThreadTerminatePort(
    HANDLE PortHandle
);

NTSTATUS SCReleaseKeyedEvent(
    HANDLE KeyedEventHandle OPTIONAL,
    PVOID KeyValue,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCReleaseMutant(
    HANDLE MutantHandle,
    PLONG PreviousCount OPTIONAL
);

NTSTATUS SCReleaseSemaphore(
    HANDLE SemaphoreHandle,
    LONG ReleaseCount,
    PLONG PreviousCount OPTIONAL
);

NTSTATUS SCReleaseWorkerFactoryWorker(
    HANDLE WorkerFactoryHandle
);

NTSTATUS SCRemoveIoCompletion(
    HANDLE IoCompletionHandle,
    PVOID * KeyContext,
    PVOID * ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCRemoveIoCompletionEx(
    HANDLE IoCompletionHandle,
    PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
    ULONG Count,
    PULONG NumEntriesRemoved,
    PLARGE_INTEGER Timeout OPTIONAL,
    BOOLEAN Alertable
);

NTSTATUS SCRemoveProcessDebug(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
);

NTSTATUS SCRenameKey(
    HANDLE KeyHandle,
    PUNICODE_STRING NewName
);

NTSTATUS SCRenameTransactionManager(
    PUNICODE_STRING LogFileName,
    LPGUID ExistingTransactionManagerGuid
);

NTSTATUS SCReplaceKey(
    POBJECT_ATTRIBUTES NewFile,
    HANDLE TargetHandle,
    POBJECT_ATTRIBUTES OldFile
);

NTSTATUS SCReplacePartitionUnit(
    PUNICODE_STRING TargetInstancePath,
    PUNICODE_STRING SpareInstancePath,
    ULONG Flags
);

NTSTATUS SCReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage
);

NTSTATUS SCReplyWaitReceivePort(
    HANDLE PortHandle,
    PVOID * PortContext OPTIONAL,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage
);

NTSTATUS SCReplyWaitReceivePortEx(
    HANDLE PortHandle,
    PVOID * PortContext OPTIONAL,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCReplyWaitReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage
);

NTSTATUS SCRequestPort(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage
);

NTSTATUS SCRequestWaitReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage
);

NTSTATUS SCResetEvent(
    HANDLE EventHandle,
    PLONG PreviousState OPTIONAL
);

NTSTATUS SCResetWriteWatch(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    SIZE_T RegionSize
);

NTSTATUS SCRestoreKey(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Flags
);

NTSTATUS SCResumeProcess(
    HANDLE ProcessHandle
);

NTSTATUS SCResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

NTSTATUS SCRevertContainerImpersonation(VOID);

NTSTATUS SCRollbackComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCRollbackEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCRollbackRegistryTransaction(
    HANDLE RegistryTransactionHandle,
    ULONG Flags /* reserved */
);

NTSTATUS SCRollbackTransaction(
    HANDLE TransactionHandle,
    BOOLEAN Wait
);

NTSTATUS SCRollforwardTransactionManager(
    HANDLE TransactionManagerHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCSaveKey(
    HANDLE KeyHandle,
    HANDLE FileHandle
);

NTSTATUS SCSaveKeyEx(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Format
);

NTSTATUS SCSaveMergedKeys(
    HANDLE HighPrecedenceKeyHandle,
    HANDLE LowPrecedenceKeyHandle,
    HANDLE FileHandle
);

NTSTATUS SCSecureConnectPort(
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

NTSTATUS SCSerializeBoot(VOID);

NTSTATUS SCSetBootEntryOrder(
    PULONG Ids,
    ULONG Count
);

NTSTATUS SCSetBootOptions(
    PBOOT_OPTIONS BootOptions,
    ULONG FieldsToChange
);

NTSTATUS SCSetCachedSigningLevel(
    ULONG Flags,
    SE_SIGNING_LEVEL InputSigningLevel,
    PHANDLE SourceFiles,
    ULONG SourceFileCount,
    HANDLE TargetFile OPTIONAL
);

NTSTATUS SCSetCachedSigningLevel2(
    ULONG Flags,
    SE_SIGNING_LEVEL InputSigningLevel,
    PHANDLE SourceFiles,
    ULONG SourceFileCount,
    HANDLE TargetFile OPTIONAL,
    SE_SET_FILE_CACHE_INFORMATION * CacheInformation OPTIONAL
);

NTSTATUS SCSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

NTSTATUS SCSetDebugFilterState(
    ULONG ComponentId,
    ULONG Level,
    BOOLEAN State
);

NTSTATUS SCSetDefaultHardErrorPort(
    HANDLE DefaultHardErrorPort
);

NTSTATUS SCSetDefaultLocale(
    BOOLEAN UserProfile,
    LCID DefaultLocaleId
);

NTSTATUS SCSetDefaultUILanguage(
    LANGID DefaultUILanguageId
);

NTSTATUS SCSetDriverEntryOrder(
    PULONG Ids,
    ULONG Count
);

NTSTATUS SCSetEaFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length
);

NTSTATUS SCSetEvent(
    HANDLE EventHandle,
    PLONG PreviousState OPTIONAL
);

NTSTATUS SCSetEventBoostPriority(
    HANDLE EventHandle
);

NTSTATUS SCSetHighEventPair(
    HANDLE EventPairHandle
);

NTSTATUS SCSetHighWaitLowEventPair(
    HANDLE EventPairHandle
);

NTSTATUS SCSetIRTimer(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime OPTIONAL
);

NTSTATUS SCSetInformationCpuPartition(
    HANDLE CpuPartitionHandle,
    ULONG CpuPartitionInformationClass,
    PVOID CpuPartitionInformation,
    ULONG CpuPartitionInformationLength,
    PVOID Reserved1 OPTIONAL,
    ULONG Reserved2 OPTIONAL,
    ULONG Reserved3 OPTIONAL
);

NTSTATUS SCSetInformationDebugObject(
    HANDLE DebugObjectHandle,
    DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
    PVOID DebugInformation,
    ULONG DebugInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCSetInformationEnlistment(
    HANDLE EnlistmentHandle OPTIONAL,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength
);

NTSTATUS SCSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS SCSetInformationIoRing(
    HANDLE IoRingHandle,
    ULONG IoRingInformationClass,
    ULONG IoRingInformationLength,
    PVOID IoRingInformation
);

NTSTATUS SCSetInformationJobObject(
    HANDLE JobHandle,
    JOBOBJECTINFOCLASS JobObjectInformationClass,
    PVOID JobObjectInformation,
    ULONG JobObjectInformationLength
);

NTSTATUS SCSetInformationKey(
    HANDLE KeyHandle,
    KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    PVOID KeySetInformation,
    ULONG KeySetInformationLength
);

NTSTATUS SCSetInformationObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength
);

NTSTATUS SCSetInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

NTSTATUS SCSetInformationResourceManager(
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength
);

NTSTATUS SCSetInformationSymbolicLink(
    HANDLE LinkHandle,
    SYMBOLIC_LINK_INFO_CLASS SymbolicLinkInformationClass,
    PVOID SymbolicLinkInformation,
    ULONG SymbolicLinkInformationLength
);

NTSTATUS SCSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

NTSTATUS SCSetInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength
);

NTSTATUS SCSetInformationTransaction(
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength
);

NTSTATUS SCSetInformationTransactionManager(
    HANDLE TmHandle OPTIONAL,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    PVOID TransactionManagerInformation,
    ULONG TransactionManagerInformationLength
);

NTSTATUS SCSetInformationVirtualMemory(
    HANDLE ProcessHandle,
    VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    SIZE_T NumberOfEntries,
    PMEMORY_RANGE_ENTRY VirtualAddresses,
    PVOID VmInformation,
    ULONG VmInformationLength
);

NTSTATUS SCSetInformationWorkerFactory(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
);

NTSTATUS SCSetIntervalProfile(
    ULONG Interval,
    KPROFILE_SOURCE Source
);

NTSTATUS SCSetIoCompletion(
    HANDLE IoCompletionHandle,
    PVOID KeyContext OPTIONAL,
    PVOID ApcContext OPTIONAL,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

NTSTATUS SCSetIoCompletionEx(
    HANDLE IoCompletionHandle,
    HANDLE IoCompletionPacketHandle,
    PVOID KeyContext OPTIONAL,
    PVOID ApcContext OPTIONAL,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

NTSTATUS SCSetLdtEntries(
    ULONG Selector0,
    ULONG Entry0Low,
    ULONG Entry0Hi,
    ULONG Selector1,
    ULONG Entry1Low,
    ULONG Entry1Hi
);

NTSTATUS SCSetLowEventPair(
    HANDLE EventPairHandle
);

NTSTATUS SCSetLowWaitHighEventPair(
    HANDLE EventPairHandle
);

NTSTATUS SCSetQuotaInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length
);

NTSTATUS SCSetSecurityObject(
    HANDLE Handle,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor
);

NTSTATUS SCSetSystemEnvironmentValue(
    PCUNICODE_STRING VariableName,
    PCUNICODE_STRING VariableValue
);

NTSTATUS SCSetSystemEnvironmentValueEx(
    PCUNICODE_STRING VariableName,
    PCGUID VendorGuid,
    PVOID Buffer OPTIONAL,
    ULONG BufferLength, /* 0 = delete variable */
    ULONG Attributes /* EFI_VARIABLE_* */
);

NTSTATUS SCSetSystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
);

NTSTATUS SCSetSystemPowerState(
    POWER_ACTION SystemAction,
    SYSTEM_POWER_STATE LightestSystemState,
    ULONG Flags /* POWER_ACTION_* flags */
);

NTSTATUS SCSetSystemTime(
    PLARGE_INTEGER SystemTime OPTIONAL,
    PLARGE_INTEGER PreviousTime OPTIONAL
);

NTSTATUS SCSetThreadExecutionState(
    EXECUTION_STATE NewFlags, /* ES_* flags */
    EXECUTION_STATE * PreviousFlags
);

NTSTATUS SCSetTimer(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
    PVOID TimerContext OPTIONAL,
    BOOLEAN ResumeTimer,
    LONG Period OPTIONAL,
    PBOOLEAN PreviousState OPTIONAL
);

NTSTATUS SCSetTimer2(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PLARGE_INTEGER Period OPTIONAL,
    PT2_SET_PARAMETERS Parameters
);

NTSTATUS SCSetTimerEx(
    HANDLE TimerHandle,
    TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
    PVOID TimerSetInformation,
    ULONG TimerSetInformationLength
);

NTSTATUS SCSetTimerResolution(
    ULONG DesiredTime,
    BOOLEAN SetResolution,
    PULONG ActualTime
);

NTSTATUS SCSetUuidSeed(
    PCHAR Seed
);

NTSTATUS SCSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex OPTIONAL,
    ULONG Type,
    PVOID Data OPTIONAL,
    ULONG DataSize
);

NTSTATUS SCSetVolumeInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FSINFOCLASS FsInformationClass
);

NTSTATUS SCSetWnfProcessNotificationEvent(
    HANDLE NotificationEvent
);

NTSTATUS SCShutdownSystem(
    SHUTDOWN_ACTION Action
);

NTSTATUS SCShutdownWorkerFactory(
    HANDLE WorkerFactoryHandle,
    volatile LONG * PendingWorkerCount
);

NTSTATUS SCSignalAndWaitForSingleObject(
    HANDLE SignalHandle,
    HANDLE WaitHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCSinglePhaseReject(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

NTSTATUS SCStartProfile(
    HANDLE ProfileHandle
);

NTSTATUS SCStopProfile(
    HANDLE ProfileHandle
);

NTSTATUS SCSubmitIoRing(
    HANDLE IoRingHandle,
    ULONG Flags,
    ULONG WaitOperations OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCSubscribeWnfStateChange(
    PCWNF_STATE_NAME StateName,
    WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
    ULONG EventMask,
    PULONG64 SubscriptionId OPTIONAL
);

NTSTATUS SCSuspendProcess(
    HANDLE ProcessHandle
);

NTSTATUS SCSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

NTSTATUS SCSystemDebugControl(
    SYSDBG_COMMAND Command,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCTerminateEnclave(
    PVOID BaseAddress,
    ULONG Flags /* TERMINATE_ENCLAVE_FLAG_* */
);

NTSTATUS SCTerminateJobObject(
    HANDLE JobHandle,
    NTSTATUS ExitStatus
);

NTSTATUS SCTerminateProcess(
    HANDLE ProcessHandle OPTIONAL,
    NTSTATUS ExitStatus
);

NTSTATUS SCTerminateThread(
    HANDLE ThreadHandle OPTIONAL,
    NTSTATUS ExitStatus
);

NTSTATUS SCTestAlert(VOID);

NTSTATUS SCThawRegistry(VOID);

NTSTATUS SCThawTransactions(VOID);

NTSTATUS SCTraceControl(
    ETWTRACECONTROLCODE FunctionCode,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SCTraceEvent(
    HANDLE TraceHandle,
    ULONG Flags,
    ULONG FieldSize,
    PVOID Fields
);

NTSTATUS SCTranslateFilePath(
    PFILE_PATH InputFilePath,
    ULONG OutputType,
    PFILE_PATH OutputFilePath,
    PULONG OutputFilePathLength OPTIONAL
);

NTSTATUS SCUmsThreadYield(
    PVOID SchedulerParam
);

NTSTATUS SCUnloadDriver(
    PUNICODE_STRING DriverServiceName
);

NTSTATUS SCUnloadKey(
    POBJECT_ATTRIBUTES TargetKey
);

NTSTATUS SCUnloadKey2(
    POBJECT_ATTRIBUTES TargetKey,
    ULONG Flags
);

NTSTATUS SCUnloadKeyEx(
    POBJECT_ATTRIBUTES TargetKey,
    HANDLE Event OPTIONAL
);

NTSTATUS SCUnlockFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER ByteOffset,
    PLARGE_INTEGER Length,
    ULONG Key
);

NTSTATUS SCUnlockVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG MapType
);

NTSTATUS SCUnsubscribeWnfStateChange(
    PCWNF_STATE_NAME StateName
);

NTSTATUS SCUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL
);

NTSTATUS SCUnmapViewOfSectionEx(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    ULONG Flags
);

NTSTATUS SCUpdateWnfStateData(
    PCWNF_STATE_NAME StateName,
    const VOID * Buffer OPTIONAL,
    ULONG Length OPTIONAL,
    PCWNF_TYPE_ID TypeId OPTIONAL,
    const VOID * ExplicitScope OPTIONAL,
    WNF_CHANGE_STAMP MatchingChangeStamp,
    LOGICAL CheckStamp
);

NTSTATUS SCVdmControl(
    VDMSERVICECLASS Service,
    PVOID ServiceData
);

NTSTATUS SCWaitForAlertByThreadId(
    PVOID Address OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCWaitForDebugEvent(
    HANDLE DebugObjectHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL,
    PDBGUI_WAIT_STATE_CHANGE WaitStateChange
);

NTSTATUS SCWaitForKeyedEvent(
    HANDLE KeyedEventHandle OPTIONAL,
    PVOID KeyValue,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCWaitForMultipleObjects(
    ULONG Count,
    HANDLE Handles[],
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCWaitForMultipleObjects32(
    ULONG Count,
    LONG Handles[],
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS SCWaitForWorkViaWorkerFactory(
    HANDLE WorkerFactoryHandle,
    PFILE_IO_COMPLETION_INFORMATION MiniPackets,
    ULONG Count,
    PULONG PacketsReturned,
    PWORKER_FACTORY_DEFERRED_WORK DeferredWork
);

NTSTATUS SCWaitHighEventPair(
    HANDLE EventPairHandle
);

NTSTATUS SCWaitLowEventPair(
    HANDLE EventPairHandle
);

NTSTATUS SCWorkerFactoryWorkerReady(
    HANDLE WorkerFactoryHandle
);

NTSTATUS SCWriteFile(
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

NTSTATUS SCWriteFileGather(
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

NTSTATUS SCWriteRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten OPTIONAL
);

NTSTATUS SCWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS SCYieldExecution(VOID);

#ifdef __cplusplus
}
#endif

#endif
