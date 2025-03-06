#pragma once
#include "../syscaller.h"
#include "sysNtTypes.h"
#include "sysNtExternals.h"

#ifdef _WIN64 // Only compile on 64bit systems.

extern "C" NTSTATUS SysAcceptConnectPort(
    PHANDLE PortHandle,
    PVOID PortContext OPTIONAL,
    PPORT_MESSAGE ConnectionRequest,
    BOOLEAN AcceptConnection,
    PPORT_VIEW ServerView OPTIONAL,
    PREMOTE_PORT_VIEW ClientView OPTIONAL
);

extern "C" NTSTATUS SysAccessCheck(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus
);

extern "C" NTSTATUS SysAccessCheckAndAuditAlarm(
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

extern "C" NTSTATUS SysAccessCheckByType(
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

extern "C" NTSTATUS SysAccessCheckByTypeAndAuditAlarm(
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

extern "C" NTSTATUS SysAccessCheckByTypeResultList(
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

extern "C" NTSTATUS SysAccessCheckByTypeResultListAndAuditAlarm(
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

extern "C" NTSTATUS SysAccessCheckByTypeResultListAndAuditAlarmByHandle(
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

extern "C" NTSTATUS SysAcquireCrossVmMutant(
    HANDLE CrossVmMutant,
    PLARGE_INTEGER Timeout
);

extern "C" NTSTATUS SysAcquireProcessActivityReference(
    PHANDLE ActivityReferenceHandle,
    HANDLE ParentProcessHandle,
    PROCESS_ACTIVITY_TYPE Reserved
);

extern "C" NTSTATUS SysAddAtom(
    PCWSTR AtomName OPTIONAL,
    ULONG Length,
    PRTL_ATOM Atom OPTIONAL
);

extern "C" NTSTATUS SysAddAtomEx(
    PCWSTR AtomName OPTIONAL,
    ULONG Length,
    PRTL_ATOM Atom OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SysAddBootEntry(
    PBOOT_ENTRY BootEntry,
    PULONG Id OPTIONAL
);

extern "C" NTSTATUS SysAddDriverEntry(
    PEFI_DRIVER_ENTRY DriverEntry,
    PULONG Id OPTIONAL
);

extern "C" NTSTATUS SysAdjustGroupsToken(
    HANDLE TokenHandle,
    BOOLEAN ResetToDefault,
    PTOKEN_GROUPS NewState OPTIONAL,
    ULONG BufferLength OPTIONAL,
    PTOKEN_GROUPS PreviousState OPTIONAL,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState OPTIONAL,
    ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState OPTIONAL,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysAdjustTokenClaimsAndDeviceGroups(
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

extern "C" NTSTATUS SysAlertResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount OPTIONAL
);

extern "C" NTSTATUS SysAlertThread(
    HANDLE ThreadHandle
);

extern "C" NTSTATUS SysAlertThreadByThreadId(
    HANDLE ThreadId
);

extern "C" NTSTATUS SysAllocateLocallyUniqueId(
    PLUID Luid
);

extern "C" NTSTATUS SysAllocateReserveObject(
    PHANDLE MemoryReserveHandle,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    MEMORY_RESERVE_TYPE Type
);

extern "C" NTSTATUS SysAllocateUserPhysicalPages(
    HANDLE ProcessHandle,
    PSIZE_T NumberOfPages,
    PULONG_PTR UserPfnArray
);

extern "C" NTSTATUS SysAllocateUserPhysicalPagesEx(
    HANDLE ProcessHandle,
    PULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray,
    PMEM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount
);

extern "C" NTSTATUS SysAllocateUuids(
    PULARGE_INTEGER Time,
    PULONG Range,
    PULONG Sequence,
    PCHAR Seed
);

extern "C" NTSTATUS SysAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
);

extern "C" NTSTATUS SysAllocateVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount
);

extern "C" NTSTATUS SysAlpcAcceptConnectPort(
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

extern "C" NTSTATUS SysAlpcCancelMessage(
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_CONTEXT_ATTR MessageContext
);

extern "C" NTSTATUS SysAlpcConnectPort(
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

extern "C" NTSTATUS SysAlpcConnectPortEx(
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

extern "C" NTSTATUS SysAlpcCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL
);

extern "C" NTSTATUS SysAlpcCreatePortSection(
    HANDLE PortHandle,
    ULONG Flags,
    HANDLE SectionHandle OPTIONAL,
    SIZE_T SectionSize,
    PALPC_HANDLE AlpcSectionHandle,
    PSIZE_T ActualSectionSize
);

extern "C" NTSTATUS SysAlpcCreateResourceReserve(
    HANDLE PortHandle,
    ULONG Flags,
    SIZE_T MessageSize,
    PALPC_HANDLE ResourceId
);

extern "C" NTSTATUS SysAlpcCreateSectionView(
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_DATA_VIEW_ATTR ViewAttributes
);

extern "C" NTSTATUS SysAlpcCreateSecurityContext(
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_SECURITY_ATTR SecurityAttribute
);

extern "C" NTSTATUS SysAlpcDeletePortSection(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE SectionHandle
);

extern "C" NTSTATUS SysAlpcDeleteResourceReserve(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE ResourceId
);

extern "C" NTSTATUS SysAlpcDeleteSectionView(
    HANDLE PortHandle,
    ULONG Flags,
    PVOID ViewBase
);

extern "C" NTSTATUS SysAlpcDeleteSecurityContext(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE ContextHandle
);

extern "C" NTSTATUS SysAlpcDisconnectPort(
    HANDLE PortHandle,
    ULONG Flags
);

extern "C" NTSTATUS SysAlpcImpersonateClientContainerOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG Flags
);

extern "C" NTSTATUS SysAlpcImpersonateClientOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    PVOID Flags
);

extern "C" NTSTATUS SysAlpcOpenSenderProcess(
    PHANDLE ProcessHandle,
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ULONG Flags,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysAlpcOpenSenderThread(
    PHANDLE ThreadHandle,
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ULONG Flags,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysAlpcQueryInformation(
    HANDLE PortHandle OPTIONAL,
    ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysAlpcQueryInformationMessage(
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
    PVOID MessageInformation,
    ULONG Length,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysAlpcRevokeSecurityContext(
    HANDLE PortHandle,
    ULONG Flags,
    ALPC_HANDLE ContextHandle
);

extern "C" NTSTATUS SysAlpcSendWaitReceivePort(
    HANDLE PortHandle,
    ULONG Flags,
    PPORT_MESSAGE SendMessage OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
    PPORT_MESSAGE ReceiveMessage OPTIONAL,
    PSIZE_T BufferLength OPTIONAL,
    PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysAlpcSetInformation(
    HANDLE PortHandle,
    ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation OPTIONAL,
    ULONG Length
);

extern "C" NTSTATUS SysApphelpCacheControl(
    ULONG Command,
    PVOID Buffer OPTIONAL,
    ULONG BufferSize
);

extern "C" NTSTATUS SysAreMappedFilesTheSame(
    PVOID File1MappedAsAnImage,
    PVOID File2MappedAsFile
);

extern "C" NTSTATUS SysAssignProcessToJobObject(
    HANDLE JobHandle,
    HANDLE ProcessHandle
);

extern "C" NTSTATUS SysAssociateWaitCompletionPacket(
    HANDLE WaitCompletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID KeyContext OPTIONAL,
    PVOID ApcContext OPTIONAL,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled OPTIONAL
);

extern "C" NTSTATUS SysCallEnclave(
    PENCLAVE_ROUTINE Routine,
    PVOID Reserved,
    ULONG Flags,
    PVOID * RoutineParamReturn
);

extern "C" NTSTATUS SysCallbackReturn(
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputLength,
    NTSTATUS Status
);

extern "C" NTSTATUS SysCancelIoFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SysCancelIoFileEx(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SysCancelSynchronousIoFile(
    HANDLE ThreadHandle,
    PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SysCancelTimer(
    HANDLE TimerHandle,
    PBOOLEAN CurrentState OPTIONAL
);

extern "C" NTSTATUS SysCancelTimer2(
    HANDLE TimerHandle,
    PT2_CANCEL_PARAMETERS Parameters
);

extern "C" NTSTATUS SysCancelWaitCompletionPacket(
    HANDLE WaitCompletionPacketHandle,
    BOOLEAN RemoveSignaledPacket
);

extern "C" NTSTATUS SysChangeProcessState(
    HANDLE ProcessStateChangeHandle,
    HANDLE ProcessHandle,
    PROCESS_STATE_CHANGE_TYPE StateChangeType,
    PVOID ExtendedInformation OPTIONAL,
    SIZE_T ExtendedInformationLength OPTIONAL,
    ULONG64 Reserved OPTIONAL
);

extern "C" NTSTATUS SysChangeThreadState(
    HANDLE ThreadStateChangeHandle,
    HANDLE ThreadHandle,
    THREAD_STATE_CHANGE_TYPE StateChangeType,
    PVOID ExtendedInformation OPTIONAL,
    SIZE_T ExtendedInformationLength OPTIONAL,
    ULONG64 Reserved OPTIONAL
);

extern "C" NTSTATUS SysClearEvent(
    HANDLE EventHandle
);

extern "C" NTSTATUS SysClose(
    HANDLE Handle
);

extern "C" NTSTATUS SysCloseObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    BOOLEAN GenerateOnClose
);

extern "C" NTSTATUS SysCommitComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysCommitEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysCommitRegistryTransaction(
    HANDLE RegistryTransactionHandle,
    ULONG Flags // Reserved
);

extern "C" NTSTATUS SysCommitTransaction(
    HANDLE TransactionHandle,
    BOOLEAN Wait
);

extern "C" NTSTATUS SysCompactKeys(
    ULONG Count,
    HANDLE KeyArray[]
);

extern "C" NTSTATUS SysCompareObjects(
    HANDLE FirstObjectHandle,
    HANDLE SecondObjectHandle
);

extern "C" NTSTATUS SysCompareSigningLevels(
    SE_SIGNING_LEVEL FirstSigningLevel,
    SE_SIGNING_LEVEL SecondSigningLevel
);

extern "C" NTSTATUS SysCompareTokens(
    HANDLE FirstTokenHandle,
    HANDLE SecondTokenHandle,
    PBOOLEAN Equal
);

extern "C" NTSTATUS SysCompleteConnectPort(
    HANDLE PortHandle
);

extern "C" NTSTATUS SysCompressKey(
    HANDLE KeyHandle
);

extern "C" NTSTATUS SysConnectPort(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    PPORT_VIEW ClientView OPTIONAL,
    PREMOTE_PORT_VIEW ServerView OPTIONAL,
    PULONG MaxMessageLength OPTIONAL,
    PVOID ConnectionInformation OPTIONAL,
    PULONG ConnectionInformationLength OPTIONAL
);

extern "C" NTSTATUS SysContinue(
    PCONTEXT ContextRecord,
    BOOLEAN TestAlert
);

extern "C" NTSTATUS SysContinueEx(
    PCONTEXT ContextRecord,
    PVOID ContinueArgument // Can be PKCONTINUE_ARGUMENT or BOOLEAN
);

extern "C" NTSTATUS SysConvertBetweenAuxiliaryCounterAndPerformanceCounter(
    BOOLEAN ConvertAuxiliaryToPerformanceCounter,
    PULONG64 PerformanceOrAuxiliaryCounterValue,
    PULONG64 ConvertedValue,
    PULONG64 ConversionError OPTIONAL
);

extern "C" NTSTATUS SysCopyFileChunk(
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

extern "C" NTSTATUS SysCreateCpuPartition(
    PHANDLE CpuPartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SysCreateCrossVmEvent(
    PHANDLE CrossVmEvent,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CrossVmEventFlags,
    LPCGUID VMID,
    LPCGUID ServiceID
);

extern "C" NTSTATUS SysCreateCrossVmMutant(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CrossVmEventFlags,
    LPCGUID VMID,
    LPCGUID ServiceID
);

extern "C" NTSTATUS SysCreateDebugObject(
    PHANDLE DebugObjectHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SysCreateDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysCreateDirectoryObjectEx(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ShadowDirectoryHandle,
    ULONG Flags
);

extern "C" NTSTATUS SysCreateEnclave(
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

extern "C" NTSTATUS SysCreateEnlistment(
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    HANDLE TransactionHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    NOTIFICATION_MASK NotificationMask,
    PVOID EnlistmentKey OPTIONAL
);

extern "C" NTSTATUS SysCreateEvent(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    EVENT_TYPE EventType,
    BOOLEAN InitialState
);

extern "C" NTSTATUS SysCreateEventPair(
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SysCreateFile(
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

extern "C" NTSTATUS SysCreateIRTimer(
    PHANDLE TimerHandle,
    PVOID Reserved,
    ACCESS_MASK DesiredAccess
);

extern "C" NTSTATUS SysCreateIoCompletion(
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG NumberOfConcurrentThreads OPTIONAL
);

extern "C" NTSTATUS SysCreateIoRing(
    PHANDLE IoRingHandle,
    ULONG CreateParametersLength,
    PVOID CreateParameters,
    ULONG OutputParametersLength,
    PVOID OutputParameters
);

extern "C" NTSTATUS SysCreateJobObject(
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SysCreateJobSet(
    ULONG NumJob,
    PJOB_SET_ARRAY UserJobSet,
    ULONG Flags
);

extern "C" NTSTATUS SysCreateKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class OPTIONAL,
    ULONG CreateOptions,
    PULONG Disposition OPTIONAL
);

extern "C" NTSTATUS SysCreateKeyTransacted(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class OPTIONAL,
    ULONG CreateOptions,
    HANDLE TransactionHandle,
    PULONG Disposition OPTIONAL
);

extern "C" NTSTATUS SysCreateKeyedEvent(
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SysCreateLowBoxToken(
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

extern "C" NTSTATUS SysCreateMailslotFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CreateOptions,
    ULONG MailslotQuota,
    ULONG MaximumMessageSize,
    PLARGE_INTEGER ReadTimeout
);

extern "C" NTSTATUS SysCreateMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    BOOLEAN InitialOwner
);

extern "C" NTSTATUS SysCreateNamedPipeFile(
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

extern "C" NTSTATUS SysCreatePagingFile(
    PUNICODE_STRING PageFileName,
    PLARGE_INTEGER MinimumSize,
    PLARGE_INTEGER MaximumSize,
    ULONG Priority
);

extern "C" NTSTATUS SysCreatePartition(
    HANDLE ParentPartitionHandle OPTIONAL,
    PHANDLE PartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG PreferredNode
);

extern "C" NTSTATUS SysCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG MaxConnectionInfoLength,
    ULONG MaxMessageLength,
    ULONG MaxPoolUsage OPTIONAL
);

extern "C" NTSTATUS SysCreatePrivateNamespace(
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor
);

extern "C" NTSTATUS SysCreateProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE TokenHandle OPTIONAL
);

extern "C" NTSTATUS SysCreateProcessEx(
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

extern "C" NTSTATUS SysCreateProcessStateChange(
    PHANDLE ProcessStateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    ULONG64 Reserved OPTIONAL
);

extern "C" NTSTATUS SysCreateProfile(
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

extern "C" NTSTATUS SysCreateProfileEx(
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

extern "C" NTSTATUS SysCreateRegistryTransaction(
    PHANDLE RegistryTransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions
);

extern "C" NTSTATUS SysCreateResourceManager(
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID RmGuid,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    PUNICODE_STRING Description OPTIONAL
);

extern "C" NTSTATUS SysCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

extern "C" NTSTATUS SysCreateSectionEx(
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

extern "C" NTSTATUS SysCreateSemaphore(
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    LONG InitialCount,
    LONG MaximumCount
);

extern "C" NTSTATUS SysCreateSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING LinkTarget
);

extern "C" NTSTATUS SysCreateThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    CLIENT_ID * ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended
);

extern "C" NTSTATUS SysCreateThreadEx(
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

extern "C" NTSTATUS SysCreateThreadStateChange(
    PHANDLE ThreadStateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ThreadHandle,
    ULONG64 Reserved OPTIONAL
);

extern "C" NTSTATUS SysCreateTimer(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    TIMER_TYPE TimerType
);

extern "C" NTSTATUS SysCreateTimer2(
    PHANDLE TimerHandle,
    PVOID Reserved1 OPTIONAL,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Attributes,
    ACCESS_MASK DesiredAccess
);

extern "C" NTSTATUS SysCreateToken(
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

extern "C" NTSTATUS SysCreateTokenEx(
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

extern "C" NTSTATUS SysCreateTransaction(
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

extern "C" NTSTATUS SysCreateTransactionManager(
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PUNICODE_STRING LogFileName OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    ULONG CommitStrength OPTIONAL
);

extern "C" NTSTATUS SysCreateUserProcess(
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

extern "C" NTSTATUS SysCreateWaitCompletionPacket(
    PHANDLE WaitCompletionPacketHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SysCreateWaitablePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG MaxConnectionInfoLength,
    ULONG MaxMessageLength,
    ULONG MaxPoolUsage OPTIONAL
);

extern "C" NTSTATUS SysCreateWnfStateName(
    PWNF_STATE_NAME StateName,
    WNF_STATE_NAME_LIFETIME NameLifetime,
    WNF_DATA_SCOPE DataScope,
    BOOLEAN PersistData,
    PCWNF_TYPE_ID TypeId OPTIONAL,
    ULONG MaximumStateSize,
    PSECURITY_DESCRIPTOR SecurityDescriptor
);

extern "C" NTSTATUS SysCreateWorkerFactory(
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

extern "C" NTSTATUS SysDebugActiveProcess(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
);

extern "C" NTSTATUS SysDebugContinue(
    HANDLE DebugObjectHandle,
    CLIENT_ID * ClientId,
    NTSTATUS ContinueStatus
);

extern "C" NTSTATUS SysDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
);

extern "C" NTSTATUS SysDeleteAtom(
    PRTL_ATOM Atom
);

extern "C" NTSTATUS SysDeleteBootEntry(
    ULONG Id
);

extern "C" NTSTATUS SysDeleteDriverEntry(
    ULONG Id
);

extern "C" NTSTATUS SysDeleteFile(
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysDeleteKey(
    HANDLE KeyHandle
);

extern "C" NTSTATUS SysDeleteObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    BOOLEAN GenerateOnClose
);

extern "C" NTSTATUS SysDeletePrivateNamespace(
    HANDLE NamespaceHandle
);

extern "C" NTSTATUS SysDeleteValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName
);

extern "C" NTSTATUS SysDeleteWnfStateData(
    PCWNF_STATE_NAME StateName,
    const VOID * ExplicitScope OPTIONAL
);

extern "C" NTSTATUS SysDeleteWnfStateName(
    PCWNF_STATE_NAME StateName
);

extern "C" NTSTATUS SysDeviceIoControlFile(
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

extern "C" NTSTATUS SysDirectGraphicsCall(
    ULONG InputBufferLength,
    PVOID InputBuffer OPTIONAL,
    ULONG OutputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    PULONG ReturnLength
);

extern "C" NTSTATUS SysDisableLastKnownGood(VOID);

extern "C" NTSTATUS SysDisplayString(
    PUNICODE_STRING String
);

extern "C" NTSTATUS SysDrawText(
    PUNICODE_STRING Text
);

extern "C" NTSTATUS SysDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle OPTIONAL,
    PHANDLE TargetHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

extern "C" NTSTATUS SysDuplicateToken(
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE Type,
    PHANDLE NewTokenHandle
);

extern "C" NTSTATUS SysEnableLastKnownGood(VOID);

extern "C" NTSTATUS SysEnumerateBootEntries(
    PVOID Buffer OPTIONAL,
    PULONG BufferLength
);

extern "C" NTSTATUS SysEnumerateDriverEntries(
    PVOID Buffer OPTIONAL,
    PULONG BufferLength
);

extern "C" NTSTATUS SysEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation OPTIONAL,
    ULONG Length,
    PULONG ResultLength
);

extern "C" NTSTATUS SysEnumerateSystemEnvironmentValuesEx(
    ULONG InformationClass,
    PVOID Buffer,
    PULONG BufferLength
);

extern "C" NTSTATUS SysEnumerateTransactionObject(
    HANDLE RootObjectHandle OPTIONAL,
    KTMOBJECT_TYPE QueryType,
    PKTMOBJECT_CURSOR ObjectCursor,
    ULONG ObjectCursorLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS SysEnumerateValueKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation OPTIONAL,
    ULONG Length,
    PULONG ResultLength
);

extern "C" NTSTATUS SysExtendSection(
    HANDLE SectionHandle,
    PLARGE_INTEGER NewSectionSize
);

extern "C" NTSTATUS SysFilterBootOption(
    FILTER_BOOT_OPTION_OPERATION FilterOperation,
    ULONG ObjectType,
    ULONG ElementType,
    PVOID Data OPTIONAL,
    ULONG DataSize
);

extern "C" NTSTATUS SysFilterToken(
    HANDLE ExistingTokenHandle,
    ULONG Flags,
    PTOKEN_GROUPS SidsToDisable OPTIONAL,
    PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
    PTOKEN_GROUPS RestrictedSids OPTIONAL,
    PHANDLE NewTokenHandle
);

extern "C" NTSTATUS SysFilterTokenEx(
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

extern "C" NTSTATUS SysFindAtom(
    PCWSTR AtomName OPTIONAL,
    ULONG Length,
    PRTL_ATOM Atom OPTIONAL
);

extern "C" NTSTATUS SysFlushBuffersFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SysFlushBuffersFileEx(
    HANDLE FileHandle,
    ULONG Flags,
    PVOID Parameters,
    ULONG ParametersSize,
    PIO_STATUS_BLOCK IoStatusBlock
);

extern "C" NTSTATUS SysFlushInstallUILanguage(
    LANGID InstallUILanguage,
    ULONG SetCommittedFlag
);

extern "C" NTSTATUS SysFlushInstructionCache(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    SIZE_T Length
);

extern "C" NTSTATUS SysFlushKey(
    HANDLE KeyHandle
);

extern "C" NTSTATUS SysFlushProcessWriteBuffers(VOID);

extern "C" NTSTATUS SysFlushVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    PIO_STATUS_BLOCK IoStatus
);

extern "C" NTSTATUS SysFlushWriteBuffer(VOID);

extern "C" NTSTATUS SysFreeUserPhysicalPages(
    HANDLE ProcessHandle,
    PULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray
);

extern "C" NTSTATUS SysFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

extern "C" NTSTATUS SysFreezeRegistry(
    ULONG TimeOutInSeconds
);

extern "C" NTSTATUS SysFreezeTransactions(
    PLARGE_INTEGER FreezeTimeout,
    PLARGE_INTEGER ThawTimeout
);

extern "C" NTSTATUS SysFsControlFile(
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

extern "C" NTSTATUS SysGetCachedSigningLevel(
    HANDLE File,
    PULONG Flags,
    PSE_SIGNING_LEVEL SigningLevel,
    PUCHAR Thumbprint OPTIONAL,
    PULONG ThumbprintSize OPTIONAL,
    PULONG ThumbprintAlgorithm OPTIONAL
);

extern "C" NTSTATUS SysGetCompleteWnfStateSubscription(
    PWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
    ULONG64 * OldSubscriptionId OPTIONAL,
    ULONG OldDescriptorEventMask,
    ULONG OldDescriptorStatus,
    PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
    ULONG DescriptorSize
);

extern "C" NTSTATUS SysGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

extern "C" ULONG SysGetCurrentProcessorNumber(VOID);

extern "C" NTSTATUS SysGetCurrentProcessorNumberEx(
    PPROCESSOR_NUMBER ProcessorNumber OPTIONAL
);

extern "C" NTSTATUS SysGetDevicePowerState(
    HANDLE Device,
    PDEVICE_POWER_STATE State
);

extern "C" NTSTATUS SysGetMUIRegistryInfo(
    ULONG Flags,
    PULONG DataSize,
    PVOID Data
);

extern "C" NTSTATUS SysGetNextProcess(
    HANDLE ProcessHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
);

extern "C" NTSTATUS SysGetNextThread(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
);

extern "C" NTSTATUS SysGetNlsSectionPtr(
    ULONG SectionType,
    ULONG SectionData,
    PVOID ContextData,
    PVOID * SectionPointer,
    PULONG SectionSize
);

extern "C" NTSTATUS SysGetNotificationResourceManager(
    HANDLE ResourceManagerHandle,
    PTRANSACTION_NOTIFICATION TransactionNotification,
    ULONG NotificationLength,
    PLARGE_INTEGER Timeout OPTIONAL,
    PULONG ReturnLength OPTIONAL,
    ULONG Asynchronous,
    ULONG_PTR AsynchronousContext OPTIONAL
);

extern "C" NTSTATUS SysGetWriteWatch(
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID BaseAddress,
    SIZE_T RegionSize,
    PVOID * UserAddressArray,
    PULONG_PTR EntriesInUserAddressArray,
    PULONG Granularity
);

extern "C" NTSTATUS SysImpersonateAnonymousToken(
    HANDLE ThreadHandle
);

extern "C" NTSTATUS SysImpersonateClientOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message
);

extern "C" NTSTATUS SysImpersonateThread(
    HANDLE ServerThreadHandle,
    HANDLE ClientThreadHandle,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos
);

extern "C" NTSTATUS SysInitializeEnclave(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID EnclaveInformation,
    ULONG EnclaveInformationLength,
    PULONG EnclaveError OPTIONAL
);

extern "C" NTSTATUS SysInitializeNlsFiles(
    PVOID * BaseAddress,
    PLCID DefaultLocaleId,
    PLARGE_INTEGER DefaultCasingTableSize,
    PULONG CurrentNLSVersion OPTIONAL
);

extern "C" NTSTATUS SysInitializeRegistry(
    USHORT BootCondition
);

extern "C" NTSTATUS SysInitiatePowerAction(
    POWER_ACTION SystemAction,
    SYSTEM_POWER_STATE LightestSystemState,
    ULONG Flags,
    BOOLEAN Asynchronous
);

extern "C" NTSTATUS SysIsProcessInJob(
    HANDLE ProcessHandle,
    HANDLE JobHandle OPTIONAL
);

extern "C" NTSTATUS SysIsSystemResumeAutomatic(VOID);

extern "C" NTSTATUS SysIsUILanguageCommitted(VOID);

extern "C" NTSTATUS SysListenPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ConnectionRequest
);

extern "C" NTSTATUS SysLoadDriver(
    PUNICODE_STRING DriverServiceName
);

extern "C" NTSTATUS SysLoadEnclaveData(
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

extern "C" NTSTATUS SysLoadKey(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile
);

extern "C" NTSTATUS SysLoadKey2(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags
);

extern "C" NTSTATUS SysLoadKey3(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    PCM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount,
    ACCESS_MASK DesiredAccess OPTIONAL,
    PHANDLE RootHandle OPTIONAL,
    PVOID Reserved OPTIONAL
);

extern "C" NTSTATUS SysLoadKeyEx(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    HANDLE TrustClassKey OPTIONAL,
    HANDLE Event OPTIONAL,
    ACCESS_MASK DesiredAccess OPTIONAL,
    PHANDLE RootHandle OPTIONAL,
    PVOID Reserved OPTIONAL // previously PIO_STATUS_BLOCK
);

extern "C" NTSTATUS SysLockFile(
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

extern "C" NTSTATUS SysLockProductActivationKeys(
    ULONG * pPrivateVer OPTIONAL,
    ULONG * pSafeMode OPTIONAL
);

extern "C" NTSTATUS SysLockRegistryKey(
    HANDLE KeyHandle
);

extern "C" NTSTATUS SysLockVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG MapType
);

extern "C" NTSTATUS SysMakePermanentObject(
    HANDLE Handle
);

extern "C" NTSTATUS SysMakeTemporaryObject(
    HANDLE Handle
);

extern "C" NTSTATUS SysManageHotPatch(
    HANDLE ProcessHandle,
    ULONG Operation,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength
);

extern "C" NTSTATUS SysManagePartition(
    HANDLE TargetHandle,
    HANDLE SourceHandle OPTIONAL,
    PARTITION_INFORMATION_CLASS PartitionInformationClass,
    PVOID PartitionInformation,
    ULONG PartitionInformationLength
);

extern "C" NTSTATUS SysMapCMFModule(
    ULONG What,
    ULONG Index,
    PULONG CacheIndexOut OPTIONAL,
    PULONG CacheFlagsOut OPTIONAL,
    PULONG ViewSizeOut OPTIONAL,
    PVOID * BaseAddress OPTIONAL
);

extern "C" NTSTATUS SysMapUserPhysicalPages(
    PVOID VirtualAddress,
    SIZE_T NumberOfPages,
    PULONG_PTR UserPfnArray OPTIONAL
);

extern "C" NTSTATUS SysMapUserPhysicalPagesScatter(
    PVOID * VirtualAddresses,
    SIZE_T NumberOfPages,
    PULONG_PTR UserPfnArray OPTIONAL
);

extern "C" NTSTATUS SysMapViewOfSection(
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

extern "C" NTSTATUS SysMapViewOfSectionEx(
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

extern "C" NTSTATUS SysModifyBootEntry(
    PBOOT_ENTRY BootEntry
);

extern "C" NTSTATUS SysModifyDriverEntry(
    PEFI_DRIVER_ENTRY DriverEntry
);

extern "C" NTSTATUS SysNotifyChangeDirectoryFile(
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

extern "C" NTSTATUS SysNotifyChangeDirectoryFileEx(
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

extern "C" NTSTATUS SysNotifyChangeKey(
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

extern "C" NTSTATUS SysNotifyChangeMultipleKeys(
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

extern "C" NTSTATUS SysNotifyChangeSession(
    HANDLE SessionHandle,
    ULONG ChangeSequenceNumber,
    PLARGE_INTEGER ChangeTimeStamp,
    IO_SESSION_EVENT Event,
    IO_SESSION_STATE NewState,
    IO_SESSION_STATE PreviousState,
    PVOID Payload OPTIONAL,
    ULONG PayloadSize
);

extern "C" NTSTATUS SysOpenCpuPartition(
    PHANDLE CpuPartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SysOpenEnlistment(
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    LPGUID EnlistmentGuid,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SysOpenEvent(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenEventPair(
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

extern "C" NTSTATUS SysOpenIoCompletion(
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenJobObject(
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenKeyEx(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions
);

extern "C" NTSTATUS SysOpenKeyTransacted(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE TransactionHandle
);

extern "C" NTSTATUS SysOpenKeyTransactedEx(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions,
    HANDLE TransactionHandle
);

extern "C" NTSTATUS SysOpenKeyedEvent(
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenObjectAuditAlarm(
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

extern "C" NTSTATUS SysOpenPartition(
    PHANDLE PartitionHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenPrivateNamespace(
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor
);

extern "C" NTSTATUS SysOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID * ClientId OPTIONAL
);

extern "C" NTSTATUS SysOpenProcessToken(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle
);

extern "C" NTSTATUS SysOpenProcessTokenEx(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    PHANDLE TokenHandle
);

extern "C" NTSTATUS SysOpenRegistryTransaction(
    HANDLE * RegistryTransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjAttributes
);

extern "C" NTSTATUS SysOpenResourceManager(
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID ResourceManagerGuid OPTIONAL,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
);

extern "C" NTSTATUS SysOpenSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenSemaphore(
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenSession(
    PHANDLE SessionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID * ClientId OPTIONAL
);

extern "C" NTSTATUS SysOpenThreadToken(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    PHANDLE TokenHandle
);

extern "C" NTSTATUS SysOpenThreadTokenEx(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    ULONG HandleAttributes,
    PHANDLE TokenHandle
);

extern "C" NTSTATUS SysOpenTimer(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysOpenTransaction(
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    LPGUID Uow,
    HANDLE TmHandle OPTIONAL
);

extern "C" NTSTATUS SysOpenTransactionManager(
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PUNICODE_STRING LogFileName OPTIONAL,
    LPGUID TmIdentity OPTIONAL,
    ULONG OpenOptions OPTIONAL
);

extern "C" NTSTATUS SysPlugPlayControl(
    PLUGPLAY_CONTROL_CLASS PnPControlClass,
    PVOID PnPControlData OPTIONAL,
    ULONG PnPControlDataLength
);

extern "C" NTSTATUS SysPowerInformation(
    POWER_INFORMATION_LEVEL InformationLevel,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength
);

extern "C" NTSTATUS SysPrePrepareComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysPrePrepareEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysPrepareComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysPrepareEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysPrivilegeCheck(
    HANDLE ClientToken,
    PPRIVILEGE_SET RequiredPrivileges,
    PBOOLEAN Result
);

extern "C" NTSTATUS SysPrivilegeObjectAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PVOID HandleId OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    PPRIVILEGE_SET Privileges,
    BOOLEAN AccessGranted
);

extern "C" NTSTATUS SysPrivilegedServiceAuditAlarm(
    PUNICODE_STRING SubsystemName,
    PUNICODE_STRING ServiceName,
    HANDLE ClientToken,
    PPRIVILEGE_SET Privileges,
    BOOLEAN AccessGranted
);

extern "C" NTSTATUS SysPropagationComplete(
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    ULONG BufferLength,
    PVOID Buffer
);

extern "C" NTSTATUS SysPropagationFailed(
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    NTSTATUS PropStatus
);

extern "C" NTSTATUS SysProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

extern "C" NTSTATUS SysPssCaptureVaSpaceBulk(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    PNTPSS_MEMORY_BULK_INFORMATION BulkInformation,
    SIZE_T BulkInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysPulseEvent(
    HANDLE EventHandle,
    PLONG PreviousState OPTIONAL
);

extern "C" NTSTATUS SysQueryAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
);

extern "C" NTSTATUS SysQueryAuxiliaryCounterFrequency(
    PULONG64 AuxiliaryCounterFrequency
);

extern "C" NTSTATUS SysQueryBootEntryOrder(
    PULONG Ids OPTIONAL,
    PULONG Count
);

extern "C" NTSTATUS SysQueryBootOptions(
    PBOOT_OPTIONS BootOptions OPTIONAL,
    PULONG BootOptionsLength
);

extern "C" NTSTATUS SysQueryDebugFilterState(
    ULONG ComponentId,
    ULONG Level
);

extern "C" NTSTATUS SysQueryDefaultLocale(
    BOOLEAN UserProfile,
    PLCID DefaultLocaleId
);

extern "C" NTSTATUS SysQueryDefaultUILanguage(
    LANGID * DefaultUILanguageId
);

extern "C" NTSTATUS SysQueryDirectoryFile(
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

extern "C" NTSTATUS SysQueryDirectoryFileEx(
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

extern "C" NTSTATUS SysQueryDirectoryObject(
    HANDLE DirectoryHandle,
    PVOID Buffer OPTIONAL,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryDriverEntryOrder(
    PULONG Ids OPTIONAL,
    PULONG Count
);

extern "C" NTSTATUS SysQueryEaFile(
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

extern "C" NTSTATUS SysQueryEvent(
    HANDLE EventHandle,
    EVENT_INFORMATION_CLASS EventInformationClass,
    PVOID EventInformation,
    ULONG EventInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationAtom(
    PRTL_ATOM Atom,
    ATOM_INFORMATION_CLASS AtomInformationClass,
    PVOID AtomInformation,
    ULONG AtomInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationByName(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

extern "C" NTSTATUS SysQueryInformationCpuPartition(
    HANDLE PartitionHandle OPTIONAL,
    CPU_PARTITION_INFORMATION_CLASS PartitionInformationClass,
    PVOID PartitionInformation,
    ULONG PartitionInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationEnlistment(
    HANDLE EnlistmentHandle,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

extern "C" NTSTATUS SysQueryInformationJobObject(
    HANDLE JobHandle OPTIONAL,
    JOBOBJECTINFOCLASS JobObjectInformationClass,
    PVOID JobObjectInformation,
    ULONG JobObjectInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationPort(
    HANDLE PortHandle,
    PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationResourceManager(
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationTransaction(
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationTransactionManager(
    HANDLE TransactionManagerHandle,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    PVOID TransactionManagerInformation,
    ULONG TransactionManagerInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInformationWorkerFactory(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryInstallUILanguage(
    LANGID * InstallUILanguageId
);

extern "C" NTSTATUS SysQueryIntervalProfile(
    KPROFILE_SOURCE ProfileSource,
    PULONG Interval
);

extern "C" NTSTATUS SysQueryIoCompletion(
    HANDLE IoCompletionHandle,
    IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    PVOID IoCompletionInformation,
    ULONG IoCompletionInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryIoRingCapabilities(
    SIZE_T IoRingCapabilitiesLength,
    PVOID IoRingCapabilities
);

extern "C" NTSTATUS SysQueryKey(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength OPTIONAL
);

extern "C" NTSTATUS SysQueryLicenseValue(
    PUNICODE_STRING ValueName,
    PULONG Type OPTIONAL,
    PVOID Data OPTIONAL,
    ULONG DataSize,
    PULONG ResultDataSize
);

extern "C" NTSTATUS SysQueryMultipleValueKey(
    HANDLE KeyHandle,
    PKEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount,
    PVOID ValueBuffer,
    PULONG BufferLength,
    PULONG RequiredBufferLength OPTIONAL
);

extern "C" NTSTATUS SysQueryMutant(
    HANDLE MutantHandle,
    MUTANT_INFORMATION_CLASS MutantInformationClass,
    PVOID MutantInformation,
    ULONG MutantInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation OPTIONAL,
    ULONG ObjectInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryOpenSubKeys(
    POBJECT_ATTRIBUTES TargetKey,
    PULONG HandleCount
);

extern "C" NTSTATUS SysQueryOpenSubKeysEx(
    POBJECT_ATTRIBUTES TargetKey,
    ULONG BufferLength,
    PVOID Buffer,
    PULONG RequiredSize
);

extern "C" NTSTATUS SysQueryPerformanceCounter(
    PLARGE_INTEGER PerformanceCounter,
    PLARGE_INTEGER PerformanceFrequency OPTIONAL
);

extern "C" NTSTATUS SysQueryPortInformationProcess(VOID);

extern "C" NTSTATUS SysQueryQuotaInformationFile(
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

extern "C" NTSTATUS SysQuerySection(
    HANDLE SectionHandle,
    SECTION_INFORMATION_CLASS SectionInformationClass,
    PVOID SectionInformation,
    SIZE_T SectionInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQuerySecurityAttributesToken(
    HANDLE TokenHandle,
    PUNICODE_STRING Attributes,
    ULONG NumberOfAttributes,
    PVOID Buffer, // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION
    ULONG Length,
    PULONG ReturnLength
);

extern "C" NTSTATUS SysQuerySecurityObject(
    HANDLE Handle,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG Length,
    PULONG LengthNeeded
);

extern "C" NTSTATUS SysQuerySecurityPolicy(
    PCUNICODE_STRING Policy,
    PCUNICODE_STRING KeyName,
    PCUNICODE_STRING ValueName,
    SECURE_SETTING_VALUE_TYPE ValueType,
    PVOID Value OPTIONAL,
    PULONG ValueSize
);

extern "C" NTSTATUS SysQuerySemaphore(
    HANDLE SemaphoreHandle,
    SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    PVOID SemaphoreInformation,
    ULONG SemaphoreInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQuerySymbolicLinkObject(
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength OPTIONAL
);

extern "C" NTSTATUS SysQuerySystemEnvironmentValue(
    PUNICODE_STRING VariableName,
    PWSTR VariableValue,
    USHORT ValueLength,
    PUSHORT ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQuerySystemEnvironmentValueEx(
    PCUNICODE_STRING VariableName,
    PCGUID VendorGuid,
    PVOID Buffer OPTIONAL,
    PULONG BufferLength,
    PULONG Attributes OPTIONAL // EFI_VARIABLE_*
);

extern "C" NTSTATUS SysQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS SysQuerySystemInformationEx(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryTimer(
    HANDLE TimerHandle,
    TIMER_INFORMATION_CLASS TimerInformationClass,
    PVOID TimerInformation,
    ULONG TimerInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryTimerResolution(
    PULONG MaximumTime,
    PULONG MinimumTime,
    PULONG CurrentTime
);

extern "C" NTSTATUS SysQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);

extern "C" NTSTATUS SysQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysQueryVolumeInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FSINFOCLASS FsInformationClass
);

extern "C" NTSTATUS SysQueryWnfStateData(
    PCWNF_STATE_NAME StateName,
    PCWNF_TYPE_ID TypeId OPTIONAL,
    const VOID * ExplicitScope OPTIONAL,
    PWNF_CHANGE_STAMP ChangeStamp,
    PVOID Buffer OPTIONAL,
    PULONG BufferSize
);

extern "C" NTSTATUS SysQueryWnfStateNameInformation(
    PCWNF_STATE_NAME StateName,
    WNF_STATE_NAME_INFORMATION NameInfoClass,
    const VOID * ExplicitScope OPTIONAL,
    PVOID InfoBuffer,
    ULONG InfoBufferSize
);

extern "C" NTSTATUS SysQueueApcThread(
    HANDLE ThreadHandle,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL
);

extern "C" NTSTATUS SysQueueApcThreadEx(
    HANDLE ThreadHandle,
    HANDLE ReserveHandle OPTIONAL,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL
);

extern "C" NTSTATUS SysQueueApcThreadEx2(
    HANDLE ThreadHandle,
    HANDLE ReserveHandle OPTIONAL,
    ULONG ApcFlags,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL
);

extern "C" NTSTATUS SysRaiseException(
    PEXCEPTION_RECORD ExceptionRecord,
    PCONTEXT ContextRecord,
    BOOLEAN FirstChance
);

extern "C" NTSTATUS SysRaiseHardError(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters,
    ULONG ValidResponseOptions,
    PULONG Response
);

extern "C" NTSTATUS SysReadFile(
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

extern "C" NTSTATUS SysReadFileScatter(
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

extern "C" NTSTATUS SysReadOnlyEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysReadRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead OPTIONAL
);

extern "C" NTSTATUS SysReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead OPTIONAL
);

extern "C" NTSTATUS SysReadVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SysRecoverEnlistment(
    HANDLE EnlistmentHandle,
    PVOID EnlistmentKey OPTIONAL
);

extern "C" NTSTATUS SysRecoverResourceManager(
    HANDLE ResourceManagerHandle
);

extern "C" NTSTATUS SysRecoverTransactionManager(
    HANDLE TransactionManagerHandle
);

extern "C" NTSTATUS SysRegisterProtocolAddressInformation(
    HANDLE ResourceManager,
    PCRM_PROTOCOL_ID ProtocolId,
    ULONG ProtocolInformationSize,
    PVOID ProtocolInformation,
    ULONG CreateOptions
);

extern "C" NTSTATUS SysRegisterThreadTerminatePort(
    HANDLE PortHandle
);

extern "C" NTSTATUS SysReleaseKeyedEvent(
    HANDLE KeyedEventHandle OPTIONAL,
    PVOID KeyValue,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysReleaseMutant(
    HANDLE MutantHandle,
    PLONG PreviousCount OPTIONAL
);

extern "C" NTSTATUS SysReleaseSemaphore(
    HANDLE SemaphoreHandle,
    LONG ReleaseCount,
    PLONG PreviousCount OPTIONAL
);

extern "C" NTSTATUS SysReleaseWorkerFactoryWorker(
    HANDLE WorkerFactoryHandle
);

extern "C" NTSTATUS SysRemoveIoCompletion(
    HANDLE IoCompletionHandle,
    PVOID * KeyContext,
    PVOID * ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysRemoveIoCompletionEx(
    HANDLE IoCompletionHandle,
    PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
    ULONG Count,
    PULONG NumEntriesRemoved,
    PLARGE_INTEGER Timeout OPTIONAL,
    BOOLEAN Alertable
);

extern "C" NTSTATUS SysRemoveProcessDebug(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
);

extern "C" NTSTATUS SysRenameKey(
    HANDLE KeyHandle,
    PUNICODE_STRING NewName
);

extern "C" NTSTATUS SysRenameTransactionManager(
    PUNICODE_STRING LogFileName,
    LPGUID ExistingTransactionManagerGuid
);

extern "C" NTSTATUS SysReplaceKey(
    POBJECT_ATTRIBUTES NewFile,
    HANDLE TargetHandle,
    POBJECT_ATTRIBUTES OldFile
);

extern "C" NTSTATUS SysReplacePartitionUnit(
    PUNICODE_STRING TargetInstancePath,
    PUNICODE_STRING SpareInstancePath,
    ULONG Flags
);

extern "C" NTSTATUS SysReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage
);

extern "C" NTSTATUS SysReplyWaitReceivePort(
    HANDLE PortHandle,
    PVOID * PortContext OPTIONAL,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage
);

extern "C" NTSTATUS SysReplyWaitReceivePortEx(
    HANDLE PortHandle,
    PVOID * PortContext OPTIONAL,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysReplyWaitReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage
);

extern "C" NTSTATUS SysRequestPort(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage
);

extern "C" NTSTATUS SysRequestWaitReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage
);

extern "C" NTSTATUS SysResetEvent(
    HANDLE EventHandle,
    PLONG PreviousState OPTIONAL
);

extern "C" NTSTATUS SysResetWriteWatch(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    SIZE_T RegionSize
);

extern "C" NTSTATUS SysRestoreKey(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Flags
);

extern "C" NTSTATUS SysResumeProcess(
    HANDLE ProcessHandle
);

extern "C" NTSTATUS SysResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

extern "C" NTSTATUS SysRevertContainerImpersonation(VOID);

extern "C" NTSTATUS SysRollbackComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysRollbackEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysRollbackRegistryTransaction(
    HANDLE RegistryTransactionHandle,
    ULONG Flags // Reserved
);

extern "C" NTSTATUS SysRollbackTransaction(
    HANDLE TransactionHandle,
    BOOLEAN Wait
);

extern "C" NTSTATUS SysRollforwardTransactionManager(
    HANDLE TransactionManagerHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysSaveKey(
    HANDLE KeyHandle,
    HANDLE FileHandle
);

extern "C" NTSTATUS SysSaveKeyEx(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Format
);

extern "C" NTSTATUS SysSaveMergedKeys(
    HANDLE HighPrecedenceKeyHandle,
    HANDLE LowPrecedenceKeyHandle,
    HANDLE FileHandle
);

extern "C" NTSTATUS SysSecureConnectPort(
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

extern "C" NTSTATUS SysSerializeBoot(VOID);

extern "C" NTSTATUS SysSetBootEntryOrder(
    PULONG Ids,
    ULONG Count
);

extern "C" NTSTATUS SysSetBootOptions(
    PBOOT_OPTIONS BootOptions,
    ULONG FieldsToChange
);

extern "C" NTSTATUS SysSetCachedSigningLevel(
    ULONG Flags,
    SE_SIGNING_LEVEL InputSigningLevel,
    PHANDLE SourceFiles,
    ULONG SourceFileCount,
    HANDLE TargetFile OPTIONAL
);

extern "C" NTSTATUS SysSetCachedSigningLevel2(
    ULONG Flags,
    SE_SIGNING_LEVEL InputSigningLevel,
    PHANDLE SourceFiles,
    ULONG SourceFileCount,
    HANDLE TargetFile OPTIONAL,
    SE_SET_FILE_CACHE_INFORMATION * CacheInformation OPTIONAL
);

extern "C" NTSTATUS SysSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

extern "C" NTSTATUS SysSetDebugFilterState(
    ULONG ComponentId,
    ULONG Level,
    BOOLEAN State
);

extern "C" NTSTATUS SysSetDefaultHardErrorPort(
    HANDLE DefaultHardErrorPort
);

extern "C" NTSTATUS SysSetDefaultLocale(
    BOOLEAN UserProfile,
    LCID DefaultLocaleId
);

extern "C" NTSTATUS SysSetDefaultUILanguage(
    LANGID DefaultUILanguageId
);

extern "C" NTSTATUS SysSetDriverEntryOrder(
    PULONG Ids,
    ULONG Count
);

extern "C" NTSTATUS SysSetEaFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length
);

extern "C" NTSTATUS SysSetEvent(
    HANDLE EventHandle,
    PLONG PreviousState OPTIONAL
);

extern "C" NTSTATUS SysSetEventBoostPriority(
    HANDLE EventHandle
);

extern "C" NTSTATUS SysSetHighEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SysSetHighWaitLowEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SysSetIRTimer(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime OPTIONAL
);

extern "C" NTSTATUS SysSetInformationCpuPartition(
    HANDLE CpuPartitionHandle,
    ULONG CpuPartitionInformationClass,
    PVOID CpuPartitionInformation,
    ULONG CpuPartitionInformationLength,
    PVOID Reserved1 OPTIONAL,
    ULONG Reserved2 OPTIONAL,
    ULONG Reserved3 OPTIONAL
);

extern "C" NTSTATUS SysSetInformationDebugObject(
    HANDLE DebugObjectHandle,
    DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
    PVOID DebugInformation,
    ULONG DebugInformationLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysSetInformationEnlistment(
    HANDLE EnlistmentHandle OPTIONAL,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength
);

extern "C" NTSTATUS SysSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

extern "C" NTSTATUS SysSetInformationIoRing(
    HANDLE IoRingHandle,
    ULONG IoRingInformationClass,
    ULONG IoRingInformationLength,
    PVOID IoRingInformation
);

extern "C" NTSTATUS SysSetInformationJobObject(
    HANDLE JobHandle,
    JOBOBJECTINFOCLASS JobObjectInformationClass,
    PVOID JobObjectInformation,
    ULONG JobObjectInformationLength
);

extern "C" NTSTATUS SysSetInformationKey(
    HANDLE KeyHandle,
    KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    PVOID KeySetInformation,
    ULONG KeySetInformationLength
);

extern "C" NTSTATUS SysSetInformationObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength
);

extern "C" NTSTATUS SysSetInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

extern "C" NTSTATUS SysSetInformationResourceManager(
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength
);

extern "C" NTSTATUS SysSetInformationSymbolicLink(
    HANDLE LinkHandle,
    SYMBOLIC_LINK_INFO_CLASS SymbolicLinkInformationClass,
    PVOID SymbolicLinkInformation,
    ULONG SymbolicLinkInformationLength
);

extern "C" NTSTATUS SysSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

extern "C" NTSTATUS SysSetInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength
);

extern "C" NTSTATUS SysSetInformationTransaction(
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength
);

extern "C" NTSTATUS SysSetInformationTransactionManager(
    HANDLE TmHandle OPTIONAL,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    PVOID TransactionManagerInformation,
    ULONG TransactionManagerInformationLength
);

extern "C" NTSTATUS SysSetInformationVirtualMemory(
    HANDLE ProcessHandle,
    VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    SIZE_T NumberOfEntries,
    PMEMORY_RANGE_ENTRY VirtualAddresses,
    PVOID VmInformation,
    ULONG VmInformationLength
);

extern "C" NTSTATUS SysSetInformationWorkerFactory(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
);

extern "C" NTSTATUS SysSetIntervalProfile(
    ULONG Interval,
    KPROFILE_SOURCE Source
);

extern "C" NTSTATUS SysSetIoCompletion(
    HANDLE IoCompletionHandle,
    PVOID KeyContext OPTIONAL,
    PVOID ApcContext OPTIONAL,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

extern "C" NTSTATUS SysSetIoCompletionEx(
    HANDLE IoCompletionHandle,
    HANDLE IoCompletionPacketHandle,
    PVOID KeyContext OPTIONAL,
    PVOID ApcContext OPTIONAL,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

extern "C" NTSTATUS SysSetLdtEntries(
    ULONG Selector0,
    ULONG Entry0Low,
    ULONG Entry0Hi,
    ULONG Selector1,
    ULONG Entry1Low,
    ULONG Entry1Hi
);

extern "C" NTSTATUS SysSetLowEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SysSetLowWaitHighEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SysSetQuotaInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length
);

extern "C" NTSTATUS SysSetSecurityObject(
    HANDLE Handle,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor
);

extern "C" NTSTATUS SysSetSystemEnvironmentValue(
    PCUNICODE_STRING VariableName,
    PCUNICODE_STRING VariableValue
);

extern "C" NTSTATUS SysSetSystemEnvironmentValueEx(
    PCUNICODE_STRING VariableName,
    PCGUID VendorGuid,
    PVOID Buffer OPTIONAL,
    ULONG BufferLength, // 0 = delete variable
    ULONG Attributes // EFI_VARIABLE_*
);

extern "C" NTSTATUS SysSetSystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
);

extern "C" NTSTATUS SysSetSystemPowerState(
    POWER_ACTION SystemAction,
    SYSTEM_POWER_STATE LightestSystemState,
    ULONG Flags // POWER_ACTION_* flags
);

extern "C" NTSTATUS SysSetSystemTime(
    PLARGE_INTEGER SystemTime OPTIONAL,
    PLARGE_INTEGER PreviousTime OPTIONAL
);

extern "C" NTSTATUS SysSetThreadExecutionState(
    EXECUTION_STATE NewFlags, // ES_* flags
    EXECUTION_STATE * PreviousFlags
);

extern "C" NTSTATUS SysSetTimer(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
    PVOID TimerContext OPTIONAL,
    BOOLEAN ResumeTimer,
    LONG Period OPTIONAL,
    PBOOLEAN PreviousState OPTIONAL
);

extern "C" NTSTATUS SysSetTimer2(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PLARGE_INTEGER Period OPTIONAL,
    PT2_SET_PARAMETERS Parameters
);

extern "C" NTSTATUS SysSetTimerEx(
    HANDLE TimerHandle,
    TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
    PVOID TimerSetInformation,
    ULONG TimerSetInformationLength
);

extern "C" NTSTATUS SysSetTimerResolution(
    ULONG DesiredTime,
    BOOLEAN SetResolution,
    PULONG ActualTime
);

extern "C" NTSTATUS SysSetUuidSeed(
    PCHAR Seed
);

extern "C" NTSTATUS SysSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex OPTIONAL,
    ULONG Type,
    PVOID Data OPTIONAL,
    ULONG DataSize
);

extern "C" NTSTATUS SysSetVolumeInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FSINFOCLASS FsInformationClass
);

extern "C" NTSTATUS SysSetWnfProcessNotificationEvent(
    HANDLE NotificationEvent
);

extern "C" NTSTATUS SysShutdownSystem(
    SHUTDOWN_ACTION Action
);

extern "C" NTSTATUS SysShutdownWorkerFactory(
    HANDLE WorkerFactoryHandle,
    volatile LONG * PendingWorkerCount
);

extern "C" NTSTATUS SysSignalAndWaitForSingleObject(
    HANDLE SignalHandle,
    HANDLE WaitHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysSinglePhaseReject(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL
);

extern "C" NTSTATUS SysStartProfile(
    HANDLE ProfileHandle
);

extern "C" NTSTATUS SysStopProfile(
    HANDLE ProfileHandle
);

extern "C" NTSTATUS SysSubmitIoRing(
    HANDLE IoRingHandle,
    ULONG Flags,
    ULONG WaitOperations OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysSubscribeWnfStateChange(
    PCWNF_STATE_NAME StateName,
    WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
    ULONG EventMask,
    PULONG64 SubscriptionId OPTIONAL
);

extern "C" NTSTATUS SysSuspendProcess(
    HANDLE ProcessHandle
);

extern "C" NTSTATUS SysSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

extern "C" NTSTATUS SysSystemDebugControl(
    SYSDBG_COMMAND Command,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysTerminateEnclave(
    PVOID BaseAddress,
    ULONG Flags // TERMINATE_ENCLAVE_FLAG_*
);

extern "C" NTSTATUS SysTerminateJobObject(
    HANDLE JobHandle,
    NTSTATUS ExitStatus
);

extern "C" NTSTATUS SysTerminateProcess(
    HANDLE ProcessHandle OPTIONAL,
    NTSTATUS ExitStatus
);

extern "C" NTSTATUS SysTerminateThread(
    HANDLE ThreadHandle OPTIONAL,
    NTSTATUS ExitStatus
);

extern "C" NTSTATUS SysTestAlert(VOID);

extern "C" NTSTATUS SysThawRegistry(VOID);

extern "C" NTSTATUS SysThawTransactions(VOID);

extern "C" NTSTATUS SysTraceControl(
    ETWTRACECONTROLCODE FunctionCode,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength,
    PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS SysTraceEvent(
    HANDLE TraceHandle,
    ULONG Flags,
    ULONG FieldSize,
    PVOID Fields
);

extern "C" NTSTATUS SysTranslateFilePath(
    PFILE_PATH InputFilePath,
    ULONG OutputType,
    PFILE_PATH OutputFilePath,
    PULONG OutputFilePathLength OPTIONAL
);

extern "C" NTSTATUS SysUmsThreadYield(
    PVOID SchedulerParam
);

extern "C" NTSTATUS SysUnloadDriver(
    PUNICODE_STRING DriverServiceName
);

extern "C" NTSTATUS SysUnloadKey(
    POBJECT_ATTRIBUTES TargetKey
);

extern "C" NTSTATUS SysUnloadKey2(
    POBJECT_ATTRIBUTES TargetKey,
    ULONG Flags
);

extern "C" NTSTATUS SysUnloadKeyEx(
    POBJECT_ATTRIBUTES TargetKey,
    HANDLE Event OPTIONAL
);

extern "C" NTSTATUS SysUnlockFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER ByteOffset,
    PLARGE_INTEGER Length,
    ULONG Key
);

extern "C" NTSTATUS SysUnlockVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG MapType
);

extern "C" NTSTATUS SysUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL
);

extern "C" NTSTATUS SysUnmapViewOfSectionEx(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    ULONG Flags
);

extern "C" NTSTATUS SysUpdateWnfStateData(
    PCWNF_STATE_NAME StateName,
    const VOID * Buffer OPTIONAL,
    ULONG Length OPTIONAL,
    PCWNF_TYPE_ID TypeId OPTIONAL,
    const VOID * ExplicitScope OPTIONAL,
    WNF_CHANGE_STAMP MatchingChangeStamp,
    LOGICAL CheckStamp
);

extern "C" NTSTATUS SysVdmControl(
    VDMSERVICECLASS Service,
    PVOID ServiceData
);

extern "C" NTSTATUS SysWaitForAlertByThreadId(
    PVOID Address OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysWaitForDebugEvent(
    HANDLE DebugObjectHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL,
    PDBGUI_WAIT_STATE_CHANGE WaitStateChange
);

extern "C" NTSTATUS SysWaitForKeyedEvent(
    HANDLE KeyedEventHandle OPTIONAL,
    PVOID KeyValue,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysWaitForMultipleObjects(
    ULONG Count,
    HANDLE Handles[],
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysWaitForMultipleObjects32(
    ULONG Count,
    LONG Handles[],
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL
);

extern "C" NTSTATUS SysWaitForWorkViaWorkerFactory(
    HANDLE WorkerFactoryHandle,
    PFILE_IO_COMPLETION_INFORMATION MiniPackets,
    ULONG Count,
    PULONG PacketsReturned,
    PWORKER_FACTORY_DEFERRED_WORK DeferredWork
);

extern "C" NTSTATUS SysWaitHighEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SysWaitLowEventPair(
    HANDLE EventPairHandle
);

extern "C" NTSTATUS SysWorkerFactoryWorkerReady(
    HANDLE WorkerFactoryHandle
);

extern "C" NTSTATUS SysWriteFile(
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

extern "C" NTSTATUS SysWriteFileGather(
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

extern "C" NTSTATUS SysWriteRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten OPTIONAL
);

extern "C" NTSTATUS SysWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

extern "C" NTSTATUS SysYieldExecution(VOID);

#endif
