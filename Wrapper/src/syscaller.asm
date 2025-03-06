.code

SysAcceptConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAcceptConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SysAcceptConnectPort ENDP

SysAccessCheck PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheck syscall offset (<syscall_id>)
    syscall
    ret
SysAccessCheck ENDP

SysAccessCheckAndAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckAndAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SysAccessCheckAndAuditAlarm ENDP

SysAccessCheckByType PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByType syscall offset (<syscall_id>)
    syscall
    ret
SysAccessCheckByType ENDP

SysAccessCheckByTypeAndAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByTypeAndAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SysAccessCheckByTypeAndAuditAlarm ENDP

SysAccessCheckByTypeResultList PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByTypeResultList syscall offset (<syscall_id>)
    syscall
    ret
SysAccessCheckByTypeResultList ENDP

SysAccessCheckByTypeResultListAndAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByTypeResultListAndAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SysAccessCheckByTypeResultListAndAuditAlarm ENDP

SysAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByTypeResultListAndAuditAlarmByHandle syscall offset (<syscall_id>)
    syscall
    ret
SysAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

SysAcquireCrossVmMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAcquireCrossVmMutant syscall offset (<syscall_id>)
    syscall
    ret
SysAcquireCrossVmMutant ENDP

SysAcquireProcessActivityReference PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAcquireProcessActivityReference syscall offset (<syscall_id>)
    syscall
    ret
SysAcquireProcessActivityReference ENDP

SysAddAtom PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAddAtom syscall offset (<syscall_id>)
    syscall
    ret
SysAddAtom ENDP

SysAddAtomEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAddAtomEx syscall offset (<syscall_id>)
    syscall
    ret
SysAddAtomEx ENDP

SysAddBootEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAddBootEntry syscall offset (<syscall_id>)
    syscall
    ret
SysAddBootEntry ENDP

SysAddDriverEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAddDriverEntry syscall offset (<syscall_id>)
    syscall
    ret
SysAddDriverEntry ENDP

SysAdjustGroupsToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAdjustGroupsToken syscall offset (<syscall_id>)
    syscall
    ret
SysAdjustGroupsToken ENDP

SysAdjustPrivilegesToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAdjustPrivilegesToken syscall offset (<syscall_id>)
    syscall
    ret
SysAdjustPrivilegesToken ENDP

SysAdjustTokenClaimsAndDeviceGroups PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAdjustTokenClaimsAndDeviceGroups syscall offset (<syscall_id>)
    syscall
    ret
SysAdjustTokenClaimsAndDeviceGroups ENDP

SysAlertResumeThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlertResumeThread syscall offset (<syscall_id>)
    syscall
    ret
SysAlertResumeThread ENDP

SysAlertThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlertThread syscall offset (<syscall_id>)
    syscall
    ret
SysAlertThread ENDP

SysAlertThreadByThreadId PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlertThreadByThreadId syscall offset (<syscall_id>)
    syscall
    ret
SysAlertThreadByThreadId ENDP

SysAllocateLocallyUniqueId PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateLocallyUniqueId syscall offset (<syscall_id>)
    syscall
    ret
SysAllocateLocallyUniqueId ENDP

SysAllocateReserveObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateReserveObject syscall offset (<syscall_id>)
    syscall
    ret
SysAllocateReserveObject ENDP

SysAllocateUserPhysicalPages PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateUserPhysicalPages syscall offset (<syscall_id>)
    syscall
    ret
SysAllocateUserPhysicalPages ENDP

SysAllocateUserPhysicalPagesEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateUserPhysicalPagesEx syscall offset (<syscall_id>)
    syscall
    ret
SysAllocateUserPhysicalPagesEx ENDP

SysAllocateUuids PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateUuids syscall offset (<syscall_id>)
    syscall
    ret
SysAllocateUuids ENDP

SysAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysAllocateVirtualMemory ENDP

SysAllocateVirtualMemoryEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateVirtualMemoryEx syscall offset (<syscall_id>)
    syscall
    ret
SysAllocateVirtualMemoryEx ENDP

SysAlpcAcceptConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcAcceptConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcAcceptConnectPort ENDP

SysAlpcCancelMessage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCancelMessage syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcCancelMessage ENDP

SysAlpcConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcConnectPort ENDP

SysAlpcConnectPortEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcConnectPortEx syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcConnectPortEx ENDP

SysAlpcCreatePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreatePort syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcCreatePort ENDP

SysAlpcCreatePortSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreatePortSection syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcCreatePortSection ENDP

SysAlpcCreateResourceReserve PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreateResourceReserve syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcCreateResourceReserve ENDP

SysAlpcCreateSectionView PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreateSectionView syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcCreateSectionView ENDP

SysAlpcCreateSecurityContext PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreateSecurityContext syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcCreateSecurityContext ENDP

SysAlpcDeletePortSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDeletePortSection syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcDeletePortSection ENDP

SysAlpcDeleteResourceReserve PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDeleteResourceReserve syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcDeleteResourceReserve ENDP

SysAlpcDeleteSectionView PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDeleteSectionView syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcDeleteSectionView ENDP

SysAlpcDeleteSecurityContext PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDeleteSecurityContext syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcDeleteSecurityContext ENDP

SysAlpcDisconnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDisconnectPort syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcDisconnectPort ENDP

SysAlpcImpersonateClientContainerOfPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcImpersonateClientContainerOfPort syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcImpersonateClientContainerOfPort ENDP

SysAlpcImpersonateClientOfPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcImpersonateClientOfPort syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcImpersonateClientOfPort ENDP

SysAlpcOpenSenderProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcOpenSenderProcess syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcOpenSenderProcess ENDP

SysAlpcOpenSenderThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcOpenSenderThread syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcOpenSenderThread ENDP

SysAlpcQueryInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcQueryInformation syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcQueryInformation ENDP

SysAlpcQueryInformationMessage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcQueryInformationMessage syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcQueryInformationMessage ENDP

SysAlpcRevokeSecurityContext PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcRevokeSecurityContext syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcRevokeSecurityContext ENDP

SysAlpcSendWaitReceivePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcSendWaitReceivePort syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcSendWaitReceivePort ENDP

SysAlpcSetInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcSetInformation syscall offset (<syscall_id>)
    syscall
    ret
SysAlpcSetInformation ENDP

SysApphelpCacheControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwApphelpCacheControl syscall offset (<syscall_id>)
    syscall
    ret
SysApphelpCacheControl ENDP

SysAreMappedFilesTheSame PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAreMappedFilesTheSame syscall offset (<syscall_id>)
    syscall
    ret
SysAreMappedFilesTheSame ENDP

SysAssignProcessToJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAssignProcessToJobObject syscall offset (<syscall_id>)
    syscall
    ret
SysAssignProcessToJobObject ENDP

SysAssociateWaitCompletionPacket PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAssociateWaitCompletionPacket syscall offset (<syscall_id>)
    syscall
    ret
SysAssociateWaitCompletionPacket ENDP

SysCallEnclave PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCallEnclave syscall offset (<syscall_id>)
    syscall
    ret
SysCallEnclave ENDP

SysCallbackReturn PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCallbackReturn syscall offset (<syscall_id>)
    syscall
    ret
SysCallbackReturn ENDP

SysCancelIoFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelIoFile syscall offset (<syscall_id>)
    syscall
    ret
SysCancelIoFile ENDP

SysCancelIoFileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelIoFileEx syscall offset (<syscall_id>)
    syscall
    ret
SysCancelIoFileEx ENDP

SysCancelSynchronousIoFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelSynchronousIoFile syscall offset (<syscall_id>)
    syscall
    ret
SysCancelSynchronousIoFile ENDP

SysCancelTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelTimer syscall offset (<syscall_id>)
    syscall
    ret
SysCancelTimer ENDP

SysCancelTimer2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelTimer2 syscall offset (<syscall_id>)
    syscall
    ret
SysCancelTimer2 ENDP

SysCancelWaitCompletionPacket PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelWaitCompletionPacket syscall offset (<syscall_id>)
    syscall
    ret
SysCancelWaitCompletionPacket ENDP

SysChangeProcessState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwChangeProcessState syscall offset (<syscall_id>)
    syscall
    ret
SysChangeProcessState ENDP

SysChangeThreadState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwChangeThreadState syscall offset (<syscall_id>)
    syscall
    ret
SysChangeThreadState ENDP

SysClearEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwClearEvent syscall offset (<syscall_id>)
    syscall
    ret
SysClearEvent ENDP

SysClose PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwClose syscall offset (<syscall_id>)
    syscall
    ret
SysClose ENDP

SysCloseObjectAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCloseObjectAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SysCloseObjectAuditAlarm ENDP

SysCommitComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCommitComplete syscall offset (<syscall_id>)
    syscall
    ret
SysCommitComplete ENDP

SysCommitEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCommitEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysCommitEnlistment ENDP

SysCommitRegistryTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCommitRegistryTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysCommitRegistryTransaction ENDP

SysCommitTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCommitTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysCommitTransaction ENDP

SysCompactKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompactKeys syscall offset (<syscall_id>)
    syscall
    ret
SysCompactKeys ENDP

SysCompareObjects PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompareObjects syscall offset (<syscall_id>)
    syscall
    ret
SysCompareObjects ENDP

SysCompareSigningLevels PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompareSigningLevels syscall offset (<syscall_id>)
    syscall
    ret
SysCompareSigningLevels ENDP

SysCompareTokens PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompareTokens syscall offset (<syscall_id>)
    syscall
    ret
SysCompareTokens ENDP

SysCompleteConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompleteConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SysCompleteConnectPort ENDP

SysCompressKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompressKey syscall offset (<syscall_id>)
    syscall
    ret
SysCompressKey ENDP

SysConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SysConnectPort ENDP

SysContinue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwContinue syscall offset (<syscall_id>)
    syscall
    ret
SysContinue ENDP

SysContinueEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwContinueEx syscall offset (<syscall_id>)
    syscall
    ret
SysContinueEx ENDP

SysConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter syscall offset (<syscall_id>)
    syscall
    ret
SysConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

SysCopyFileChunk PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCopyFileChunk syscall offset (<syscall_id>)
    syscall
    ret
SysCopyFileChunk ENDP

SysCreateCpuPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateCpuPartition syscall offset (<syscall_id>)
    syscall
    ret
SysCreateCpuPartition ENDP

SysCreateCrossVmEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateCrossVmEvent syscall offset (<syscall_id>)
    syscall
    ret
SysCreateCrossVmEvent ENDP

SysCreateCrossVmMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateCrossVmMutant syscall offset (<syscall_id>)
    syscall
    ret
SysCreateCrossVmMutant ENDP

SysCreateDebugObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateDebugObject syscall offset (<syscall_id>)
    syscall
    ret
SysCreateDebugObject ENDP

SysCreateDirectoryObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateDirectoryObject syscall offset (<syscall_id>)
    syscall
    ret
SysCreateDirectoryObject ENDP

SysCreateDirectoryObjectEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateDirectoryObjectEx syscall offset (<syscall_id>)
    syscall
    ret
SysCreateDirectoryObjectEx ENDP

SysCreateEnclave PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateEnclave syscall offset (<syscall_id>)
    syscall
    ret
SysCreateEnclave ENDP

SysCreateEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysCreateEnlistment ENDP

SysCreateEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateEvent syscall offset (<syscall_id>)
    syscall
    ret
SysCreateEvent ENDP

SysCreateEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateEventPair syscall offset (<syscall_id>)
    syscall
    ret
SysCreateEventPair ENDP

SysCreateFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateFile syscall offset (<syscall_id>)
    syscall
    ret
SysCreateFile ENDP

SysCreateIRTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateIRTimer syscall offset (<syscall_id>)
    syscall
    ret
SysCreateIRTimer ENDP

SysCreateIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SysCreateIoCompletion ENDP

SysCreateIoRing PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateIoRing syscall offset (<syscall_id>)
    syscall
    ret
SysCreateIoRing ENDP

SysCreateJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateJobObject syscall offset (<syscall_id>)
    syscall
    ret
SysCreateJobObject ENDP

SysCreateJobSet PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateJobSet syscall offset (<syscall_id>)
    syscall
    ret
SysCreateJobSet ENDP

SysCreateKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateKey syscall offset (<syscall_id>)
    syscall
    ret
SysCreateKey ENDP

SysCreateKeyTransacted PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateKeyTransacted syscall offset (<syscall_id>)
    syscall
    ret
SysCreateKeyTransacted ENDP

SysCreateKeyedEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateKeyedEvent syscall offset (<syscall_id>)
    syscall
    ret
SysCreateKeyedEvent ENDP

SysCreateLowBoxToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateLowBoxToken syscall offset (<syscall_id>)
    syscall
    ret
SysCreateLowBoxToken ENDP

SysCreateMailslotFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateMailslotFile syscall offset (<syscall_id>)
    syscall
    ret
SysCreateMailslotFile ENDP

SysCreateMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateMutant syscall offset (<syscall_id>)
    syscall
    ret
SysCreateMutant ENDP

SysCreateNamedPipeFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateNamedPipeFile syscall offset (<syscall_id>)
    syscall
    ret
SysCreateNamedPipeFile ENDP

SysCreatePagingFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreatePagingFile syscall offset (<syscall_id>)
    syscall
    ret
SysCreatePagingFile ENDP

SysCreatePartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreatePartition syscall offset (<syscall_id>)
    syscall
    ret
SysCreatePartition ENDP

SysCreatePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreatePort syscall offset (<syscall_id>)
    syscall
    ret
SysCreatePort ENDP

SysCreatePrivateNamespace PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreatePrivateNamespace syscall offset (<syscall_id>)
    syscall
    ret
SysCreatePrivateNamespace ENDP

SysCreateProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProcess syscall offset (<syscall_id>)
    syscall
    ret
SysCreateProcess ENDP

SysCreateProcessEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProcessEx syscall offset (<syscall_id>)
    syscall
    ret
SysCreateProcessEx ENDP

SysCreateProcessStateChange PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProcessStateChange syscall offset (<syscall_id>)
    syscall
    ret
SysCreateProcessStateChange ENDP

SysCreateProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProfile syscall offset (<syscall_id>)
    syscall
    ret
SysCreateProfile ENDP

SysCreateProfileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProfileEx syscall offset (<syscall_id>)
    syscall
    ret
SysCreateProfileEx ENDP

SysCreateRegistryTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateRegistryTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysCreateRegistryTransaction ENDP

SysCreateResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SysCreateResourceManager ENDP

SysCreateSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateSection syscall offset (<syscall_id>)
    syscall
    ret
SysCreateSection ENDP

SysCreateSectionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateSectionEx syscall offset (<syscall_id>)
    syscall
    ret
SysCreateSectionEx ENDP

SysCreateSemaphore PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateSemaphore syscall offset (<syscall_id>)
    syscall
    ret
SysCreateSemaphore ENDP

SysCreateSymbolicLinkObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateSymbolicLinkObject syscall offset (<syscall_id>)
    syscall
    ret
SysCreateSymbolicLinkObject ENDP

SysCreateThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateThread syscall offset (<syscall_id>)
    syscall
    ret
SysCreateThread ENDP

SysCreateThreadEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateThreadEx syscall offset (<syscall_id>)
    syscall
    ret
SysCreateThreadEx ENDP

SysCreateThreadStateChange PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateThreadStateChange syscall offset (<syscall_id>)
    syscall
    ret
SysCreateThreadStateChange ENDP

SysCreateTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTimer syscall offset (<syscall_id>)
    syscall
    ret
SysCreateTimer ENDP

SysCreateTimer2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTimer2 syscall offset (<syscall_id>)
    syscall
    ret
SysCreateTimer2 ENDP

SysCreateToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateToken syscall offset (<syscall_id>)
    syscall
    ret
SysCreateToken ENDP

SysCreateTokenEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTokenEx syscall offset (<syscall_id>)
    syscall
    ret
SysCreateTokenEx ENDP

SysCreateTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysCreateTransaction ENDP

SysCreateTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SysCreateTransactionManager ENDP

SysCreateUserProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateUserProcess syscall offset (<syscall_id>)
    syscall
    ret
SysCreateUserProcess ENDP

SysCreateWaitCompletionPacket PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateWaitCompletionPacket syscall offset (<syscall_id>)
    syscall
    ret
SysCreateWaitCompletionPacket ENDP

SysCreateWaitablePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateWaitablePort syscall offset (<syscall_id>)
    syscall
    ret
SysCreateWaitablePort ENDP

SysCreateWnfStateName PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateWnfStateName syscall offset (<syscall_id>)
    syscall
    ret
SysCreateWnfStateName ENDP

SysCreateWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SysCreateWorkerFactory ENDP

SysDebugActiveProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDebugActiveProcess syscall offset (<syscall_id>)
    syscall
    ret
SysDebugActiveProcess ENDP

SysDebugContinue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDebugContinue syscall offset (<syscall_id>)
    syscall
    ret
SysDebugContinue ENDP

SysDelayExecution PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDelayExecution syscall offset (<syscall_id>)
    syscall
    ret
SysDelayExecution ENDP

SysDeleteAtom PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteAtom syscall offset (<syscall_id>)
    syscall
    ret
SysDeleteAtom ENDP

SysDeleteBootEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteBootEntry syscall offset (<syscall_id>)
    syscall
    ret
SysDeleteBootEntry ENDP

SysDeleteDriverEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteDriverEntry syscall offset (<syscall_id>)
    syscall
    ret
SysDeleteDriverEntry ENDP

SysDeleteFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteFile syscall offset (<syscall_id>)
    syscall
    ret
SysDeleteFile ENDP

SysDeleteKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteKey syscall offset (<syscall_id>)
    syscall
    ret
SysDeleteKey ENDP

SysDeleteObjectAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteObjectAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SysDeleteObjectAuditAlarm ENDP

SysDeletePrivateNamespace PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeletePrivateNamespace syscall offset (<syscall_id>)
    syscall
    ret
SysDeletePrivateNamespace ENDP

SysDeleteValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteValueKey syscall offset (<syscall_id>)
    syscall
    ret
SysDeleteValueKey ENDP

SysDeleteWnfStateData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteWnfStateData syscall offset (<syscall_id>)
    syscall
    ret
SysDeleteWnfStateData ENDP

SysDeleteWnfStateName PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteWnfStateName syscall offset (<syscall_id>)
    syscall
    ret
SysDeleteWnfStateName ENDP

SysDeviceIoControlFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeviceIoControlFile syscall offset (<syscall_id>)
    syscall
    ret
SysDeviceIoControlFile ENDP

SysDirectGraphicsCall PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDirectGraphicsCall syscall offset (<syscall_id>)
    syscall
    ret
SysDirectGraphicsCall ENDP

SysDisableLastKnownGood PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDisableLastKnownGood syscall offset (<syscall_id>)
    syscall
    ret
SysDisableLastKnownGood ENDP

SysDisplayString PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDisplayString syscall offset (<syscall_id>)
    syscall
    ret
SysDisplayString ENDP

SysDrawText PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDrawText syscall offset (<syscall_id>)
    syscall
    ret
SysDrawText ENDP

SysDuplicateObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDuplicateObject syscall offset (<syscall_id>)
    syscall
    ret
SysDuplicateObject ENDP

SysDuplicateToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDuplicateToken syscall offset (<syscall_id>)
    syscall
    ret
SysDuplicateToken ENDP

SysEnableLastKnownGood PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnableLastKnownGood syscall offset (<syscall_id>)
    syscall
    ret
SysEnableLastKnownGood ENDP

SysEnumerateBootEntries PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateBootEntries syscall offset (<syscall_id>)
    syscall
    ret
SysEnumerateBootEntries ENDP

SysEnumerateDriverEntries PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateDriverEntries syscall offset (<syscall_id>)
    syscall
    ret
SysEnumerateDriverEntries ENDP

SysEnumerateKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateKey syscall offset (<syscall_id>)
    syscall
    ret
SysEnumerateKey ENDP

SysEnumerateSystemEnvironmentValuesEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateSystemEnvironmentValuesEx syscall offset (<syscall_id>)
    syscall
    ret
SysEnumerateSystemEnvironmentValuesEx ENDP

SysEnumerateTransactionObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateTransactionObject syscall offset (<syscall_id>)
    syscall
    ret
SysEnumerateTransactionObject ENDP

SysEnumerateValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateValueKey syscall offset (<syscall_id>)
    syscall
    ret
SysEnumerateValueKey ENDP

SysExtendSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwExtendSection syscall offset (<syscall_id>)
    syscall
    ret
SysExtendSection ENDP

SysFilterBootOption PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFilterBootOption syscall offset (<syscall_id>)
    syscall
    ret
SysFilterBootOption ENDP

SysFilterToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFilterToken syscall offset (<syscall_id>)
    syscall
    ret
SysFilterToken ENDP

SysFilterTokenEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFilterTokenEx syscall offset (<syscall_id>)
    syscall
    ret
SysFilterTokenEx ENDP

SysFindAtom PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFindAtom syscall offset (<syscall_id>)
    syscall
    ret
SysFindAtom ENDP

SysFlushBuffersFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushBuffersFile syscall offset (<syscall_id>)
    syscall
    ret
SysFlushBuffersFile ENDP

SysFlushBuffersFileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushBuffersFileEx syscall offset (<syscall_id>)
    syscall
    ret
SysFlushBuffersFileEx ENDP

SysFlushInstallUILanguage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushInstallUILanguage syscall offset (<syscall_id>)
    syscall
    ret
SysFlushInstallUILanguage ENDP

SysFlushInstructionCache PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushInstructionCache syscall offset (<syscall_id>)
    syscall
    ret
SysFlushInstructionCache ENDP

SysFlushKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushKey syscall offset (<syscall_id>)
    syscall
    ret
SysFlushKey ENDP

SysFlushProcessWriteBuffers PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushProcessWriteBuffers syscall offset (<syscall_id>)
    syscall
    ret
SysFlushProcessWriteBuffers ENDP

SysFlushVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysFlushVirtualMemory ENDP

SysFlushWriteBuffer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushWriteBuffer syscall offset (<syscall_id>)
    syscall
    ret
SysFlushWriteBuffer ENDP

SysFreeUserPhysicalPages PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFreeUserPhysicalPages syscall offset (<syscall_id>)
    syscall
    ret
SysFreeUserPhysicalPages ENDP

SysFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFreeVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysFreeVirtualMemory ENDP

SysFreezeRegistry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFreezeRegistry syscall offset (<syscall_id>)
    syscall
    ret
SysFreezeRegistry ENDP

SysFreezeTransactions PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFreezeTransactions syscall offset (<syscall_id>)
    syscall
    ret
SysFreezeTransactions ENDP

SysFsControlFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFsControlFile syscall offset (<syscall_id>)
    syscall
    ret
SysFsControlFile ENDP

SysGetCachedSigningLevel PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetCachedSigningLevel syscall offset (<syscall_id>)
    syscall
    ret
SysGetCachedSigningLevel ENDP

SysGetCompleteWnfStateSubscription PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetCompleteWnfStateSubscription syscall offset (<syscall_id>)
    syscall
    ret
SysGetCompleteWnfStateSubscription ENDP

SysGetContextThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetContextThread syscall offset (<syscall_id>)
    syscall
    ret
SysGetContextThread ENDP

SysGetCurrentProcessorNumber PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetCurrentProcessorNumber syscall offset (<syscall_id>)
    syscall
    ret
SysGetCurrentProcessorNumber ENDP

SysGetCurrentProcessorNumberEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetCurrentProcessorNumberEx syscall offset (<syscall_id>)
    syscall
    ret
SysGetCurrentProcessorNumberEx ENDP

SysGetDevicePowerState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetDevicePowerState syscall offset (<syscall_id>)
    syscall
    ret
SysGetDevicePowerState ENDP

SysGetMUIRegistryInfo PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetMUIRegistryInfo syscall offset (<syscall_id>)
    syscall
    ret
SysGetMUIRegistryInfo ENDP

SysGetNextProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetNextProcess syscall offset (<syscall_id>)
    syscall
    ret
SysGetNextProcess ENDP

SysGetNextThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetNextThread syscall offset (<syscall_id>)
    syscall
    ret
SysGetNextThread ENDP

SysGetNlsSectionPtr PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetNlsSectionPtr syscall offset (<syscall_id>)
    syscall
    ret
SysGetNlsSectionPtr ENDP

SysGetNotificationResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetNotificationResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SysGetNotificationResourceManager ENDP

SysGetWriteWatch PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetWriteWatch syscall offset (<syscall_id>)
    syscall
    ret
SysGetWriteWatch ENDP

SysImpersonateAnonymousToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwImpersonateAnonymousToken syscall offset (<syscall_id>)
    syscall
    ret
SysImpersonateAnonymousToken ENDP

SysImpersonateClientOfPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwImpersonateClientOfPort syscall offset (<syscall_id>)
    syscall
    ret
SysImpersonateClientOfPort ENDP

SysImpersonateThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwImpersonateThread syscall offset (<syscall_id>)
    syscall
    ret
SysImpersonateThread ENDP

SysInitializeEnclave PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwInitializeEnclave syscall offset (<syscall_id>)
    syscall
    ret
SysInitializeEnclave ENDP

SysInitializeNlsFiles PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwInitializeNlsFiles syscall offset (<syscall_id>)
    syscall
    ret
SysInitializeNlsFiles ENDP

SysInitializeRegistry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwInitializeRegistry syscall offset (<syscall_id>)
    syscall
    ret
SysInitializeRegistry ENDP

SysInitiatePowerAction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwInitiatePowerAction syscall offset (<syscall_id>)
    syscall
    ret
SysInitiatePowerAction ENDP

SysIsProcessInJob PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwIsProcessInJob syscall offset (<syscall_id>)
    syscall
    ret
SysIsProcessInJob ENDP

SysIsSystemResumeAutomatic PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwIsSystemResumeAutomatic syscall offset (<syscall_id>)
    syscall
    ret
SysIsSystemResumeAutomatic ENDP

SysIsUILanguageComitted PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwIsUILanguageComitted syscall offset (<syscall_id>)
    syscall
    ret
SysIsUILanguageComitted ENDP

SysListenPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwListenPort syscall offset (<syscall_id>)
    syscall
    ret
SysListenPort ENDP

SysLoadDriver PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadDriver syscall offset (<syscall_id>)
    syscall
    ret
SysLoadDriver ENDP

SysLoadEnclaveData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadEnclaveData syscall offset (<syscall_id>)
    syscall
    ret
SysLoadEnclaveData ENDP

SysLoadKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadKey syscall offset (<syscall_id>)
    syscall
    ret
SysLoadKey ENDP

SysLoadKey2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadKey2 syscall offset (<syscall_id>)
    syscall
    ret
SysLoadKey2 ENDP

SysLoadKey3 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadKey3 syscall offset (<syscall_id>)
    syscall
    ret
SysLoadKey3 ENDP

SysLoadKeyEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadKeyEx syscall offset (<syscall_id>)
    syscall
    ret
SysLoadKeyEx ENDP

SysLockFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockFile syscall offset (<syscall_id>)
    syscall
    ret
SysLockFile ENDP

SysLockProductActivationKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockProductActivationKeys syscall offset (<syscall_id>)
    syscall
    ret
SysLockProductActivationKeys ENDP

SysLockRegistryKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockRegistryKey syscall offset (<syscall_id>)
    syscall
    ret
SysLockRegistryKey ENDP

SysLockVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysLockVirtualMemory ENDP

SysMakePermanentObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMakePermanentObject syscall offset (<syscall_id>)
    syscall
    ret
SysMakePermanentObject ENDP

SysMakeTemporaryObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMakeTemporaryObject syscall offset (<syscall_id>)
    syscall
    ret
SysMakeTemporaryObject ENDP

SysManageHotPatch PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwManageHotPatch syscall offset (<syscall_id>)
    syscall
    ret
SysManageHotPatch ENDP

SysManagePartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwManagePartition syscall offset (<syscall_id>)
    syscall
    ret
SysManagePartition ENDP

SysMapCMFModule PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMapCMFModule syscall offset (<syscall_id>)
    syscall
    ret
SysMapCMFModule ENDP

SysMapUserPhysicalPages PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMapUserPhysicalPages syscall offset (<syscall_id>)
    syscall
    ret
SysMapUserPhysicalPages ENDP

SysMapUserPhysicalPagesScatter PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockProductActivationKeys syscall offset (<syscall_id>)
    syscall
    ret
SysMapUserPhysicalPagesScatter ENDP

SysMapViewOfSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMapViewOfSection syscall offset (<syscall_id>)
    syscall
    ret
SysMapViewOfSection ENDP

SysMapViewOfSectionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMapViewOfSectionEx syscall offset (<syscall_id>)
    syscall
    ret
SysMapViewOfSectionEx ENDP

SysModifyBootEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwModifyBootEntry syscall offset (<syscall_id>)
    syscall
    ret
SysModifyBootEntry ENDP

SysModifyDriverEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwModifyDriverEntry syscall offset (<syscall_id>)
    syscall
    ret
SysModifyDriverEntry ENDP

SysNotifyChangeDirectoryFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeDirectoryFile syscall offset (<syscall_id>)
    syscall
    ret
SysNotifyChangeDirectoryFile ENDP

SysNotifyChangeDirectoryFileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeDirectoryFileEx syscall offset (<syscall_id>)
    syscall
    ret
SysNotifyChangeDirectoryFileEx ENDP

SysNotifyChangeKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeKey syscall offset (<syscall_id>)
    syscall
    ret
SysNotifyChangeKey ENDP

SysNotifyChangeMultipleKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeMultipleKeys syscall offset (<syscall_id>)
    syscall
    ret
SysNotifyChangeMultipleKeys ENDP

SysNotifyChangeSession PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeSession syscall offset (<syscall_id>)
    syscall
    ret
SysNotifyChangeSession ENDP

SysOpenCpuPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenCpuPartition syscall offset (<syscall_id>)
    syscall
    ret
SysOpenCpuPartition ENDP

SysOpenEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysOpenEnlistment ENDP

SysOpenEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenEvent syscall offset (<syscall_id>)
    syscall
    ret
SysOpenEvent ENDP

SysOpenEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenEventPair syscall offset (<syscall_id>)
    syscall
    ret
SysOpenEventPair ENDP

SysOpenFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenFile syscall offset (<syscall_id>)
    syscall
    ret
SysOpenFile ENDP

SysOpenIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SysOpenIoCompletion ENDP

SysOpenJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenJobObject syscall offset (<syscall_id>)
    syscall
    ret
SysOpenJobObject ENDP

SysOpenKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKey syscall offset (<syscall_id>)
    syscall
    ret
SysOpenKey ENDP

SysOpenKeyEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKeyEx syscall offset (<syscall_id>)
    syscall
    ret
SysOpenKeyEx ENDP

SysOpenKeyTransacted PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKeyTransacted syscall offset (<syscall_id>)
    syscall
    ret
SysOpenKeyTransacted ENDP

SysOpenKeyTransactedEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKeyTransactedEx syscall offset (<syscall_id>)
    syscall
    ret
SysOpenKeyTransactedEx ENDP

SysOpenKeyedEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKeyedEvent syscall offset (<syscall_id>)
    syscall
    ret
SysOpenKeyedEvent ENDP

SysOpenMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenMutant syscall offset (<syscall_id>)
    syscall
    ret
SysOpenMutant ENDP

SysOpenObjectAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenObjectAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SysOpenObjectAuditAlarm ENDP

SysOpenPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenPartition syscall offset (<syscall_id>)
    syscall
    ret
SysOpenPartition ENDP

SysOpenPrivateNamespace PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenPrivateNamespace syscall offset (<syscall_id>)
    syscall
    ret
SysOpenPrivateNamespace ENDP

SysOpenProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenProcess syscall offset (<syscall_id>)
    syscall
    ret
SysOpenProcess ENDP

SysOpenProcessToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenProcessToken syscall offset (<syscall_id>)
    syscall
    ret
SysOpenProcessToken ENDP

SysOpenProcessTokenEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenProcessTokenEx syscall offset (<syscall_id>)
    syscall
    ret
SysOpenProcessTokenEx ENDP

SysOpenRegistryTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenRegistryTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysOpenRegistryTransaction ENDP

SysOpenResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SysOpenResourceManager ENDP

SysOpenSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenSection syscall offset (<syscall_id>)
    syscall
    ret
SysOpenSection ENDP

SysOpenSemaphore PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenSemaphore syscall offset (<syscall_id>)
    syscall
    ret
SysOpenSemaphore ENDP

SysOpenSession PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenSession syscall offset (<syscall_id>)
    syscall
    ret
SysOpenSession ENDP

SysOpenSymbolicLinkObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenSymbolicLinkObject syscall offset (<syscall_id>)
    syscall
    ret
SysOpenSymbolicLinkObject ENDP

SysOpenThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenThread syscall offset (<syscall_id>)
    syscall
    ret
SysOpenThread ENDP

SysOpenThreadToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenThreadToken syscall offset (<syscall_id>)
    syscall
    ret
SysOpenThreadToken ENDP

SysOpenThreadTokenEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenThreadTokenEx syscall offset (<syscall_id>)
    syscall
    ret
SysOpenThreadTokenEx ENDP

SysOpenTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenTimer syscall offset (<syscall_id>)
    syscall
    ret
SysOpenTimer ENDP

SysOpenTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysOpenTransaction ENDP

SysOpenTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SysOpenTransactionManager ENDP

SysPlugPlayControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPlugPlayControl syscall offset (<syscall_id>)
    syscall
    ret
SysPlugPlayControl ENDP

SysPowerInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPowerInformation syscall offset (<syscall_id>)
    syscall
    ret
SysPowerInformation ENDP

SysPrePrepareComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrePrepareComplete syscall offset (<syscall_id>)
    syscall
    ret
SysPrePrepareComplete ENDP

SysPrePrepareEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrePrepareEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysPrePrepareEnlistment ENDP

SysPrepareComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrepareComplete syscall offset (<syscall_id>)
    syscall
    ret
SysPrepareComplete ENDP

SysPrepareEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrepareEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysPrepareEnlistment ENDP

SysPrivilegeCheck PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrivilegeCheck syscall offset (<syscall_id>)
    syscall
    ret
SysPrivilegeCheck ENDP

SysPrivilegeObjectAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrivilegeObjectAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SysPrivilegeObjectAuditAlarm ENDP

SysPrivilegedServiceAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrivilegedServiceAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SysPrivilegedServiceAuditAlarm ENDP

SysPropagationComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPropagationComplete syscall offset (<syscall_id>)
    syscall
    ret
SysPropagationComplete ENDP

SysPropagationFailed PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPropagationFailed syscall offset (<syscall_id>)
    syscall
    ret
SysPropagationFailed ENDP

SysProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwProtectVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysProtectVirtualMemory ENDP

SysPssCaptureVaSpaceBulk PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPssCaptureVaSpaceBulk syscall offset (<syscall_id>)
    syscall
    ret
SysPssCaptureVaSpaceBulk ENDP

SysPulseEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPulseEvent syscall offset (<syscall_id>)
    syscall
    ret
SysPulseEvent ENDP

SysQueryAttributesFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryAttributesFile syscall offset (<syscall_id>)
    syscall
    ret
SysQueryAttributesFile ENDP

SysQueryAuxiliaryCounterFrequency PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryAuxiliaryCounterFrequency syscall offset (<syscall_id>)
    syscall
    ret
SysQueryAuxiliaryCounterFrequency ENDP

SysQueryBootEntryOrder PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryBootEntryOrder syscall offset (<syscall_id>)
    syscall
    ret
SysQueryBootEntryOrder ENDP

SysQueryBootOptions PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryBootOptions syscall offset (<syscall_id>)
    syscall
    ret
SysQueryBootOptions ENDP

SysQueryDebugFilterState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDebugFilterState syscall offset (<syscall_id>)
    syscall
    ret
SysQueryDebugFilterState ENDP

SysQueryDefaultLocale PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDefaultLocale syscall offset (<syscall_id>)
    syscall
    ret
SysQueryDefaultLocale ENDP

SysQueryDefaultUILanguage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDefaultUILanguage syscall offset (<syscall_id>)
    syscall
    ret
SysQueryDefaultUILanguage ENDP

SysQueryDirectoryFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDirectoryFile syscall offset (<syscall_id>)
    syscall
    ret
SysQueryDirectoryFile ENDP

SysQueryDirectoryFileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDirectoryFileEx syscall offset (<syscall_id>)
    syscall
    ret
SysQueryDirectoryFileEx ENDP

SysQueryDirectoryObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDirectoryObject syscall offset (<syscall_id>)
    syscall
    ret
SysQueryDirectoryObject ENDP

SysQueryDriverEntryOrder PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDriverEntryOrder syscall offset (<syscall_id>)
    syscall
    ret
SysQueryDriverEntryOrder ENDP

SysQueryEaFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryEaFile syscall offset (<syscall_id>)
    syscall
    ret
SysQueryEaFile ENDP

SysQueryEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryEvent syscall offset (<syscall_id>)
    syscall
    ret
SysQueryEvent ENDP

SysQueryFullAttributesFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryFullAttributesFile syscall offset (<syscall_id>)
    syscall
    ret
SysQueryFullAttributesFile ENDP

SysQueryInformationAtom PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationAtom syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationAtom ENDP

SysQueryInformationByName PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationByName syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationByName ENDP

SysQueryInformationCpuPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationCpuPartition syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationCpuPartition ENDP

SysQueryInformationEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationEnlistment ENDP

SysQueryInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationFile ENDP

SysQueryInformationJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationJobObject syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationJobObject ENDP

SysQueryInformationPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationPort syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationPort ENDP

SysQueryInformationProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationProcess syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationProcess ENDP

SysQueryInformationResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationResourceManager ENDP

SysQueryInformationThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationThread syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationThread ENDP

SysQueryInformationToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationToken syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationToken ENDP

SysQueryInformationTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationTransaction ENDP

SysQueryInformationTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationTransactionManager ENDP

SysQueryInformationWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInformationWorkerFactory ENDP

SysQueryInstallUILanguage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInstallUILanguage syscall offset (<syscall_id>)
    syscall
    ret
SysQueryInstallUILanguage ENDP

SysQueryIntervalProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryIntervalProfile syscall offset (<syscall_id>)
    syscall
    ret
SysQueryIntervalProfile ENDP

SysQueryIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SysQueryIoCompletion ENDP

SysQueryIoRingCapabilities PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryIoRingCapabilities syscall offset (<syscall_id>)
    syscall
    ret
SysQueryIoRingCapabilities ENDP

SysQueryKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryKey syscall offset (<syscall_id>)
    syscall
    ret
SysQueryKey ENDP

SysQueryLicenseValue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryLicenseValue syscall offset (<syscall_id>)
    syscall
    ret
SysQueryLicenseValue ENDP

SysQueryMultipleValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryMultipleValueKey syscall offset (<syscall_id>)
    syscall
    ret
SysQueryMultipleValueKey ENDP

SysQueryMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryMutant syscall offset (<syscall_id>)
    syscall
    ret
SysQueryMutant ENDP

SysQueryObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryObject syscall offset (<syscall_id>)
    syscall
    ret
SysQueryObject ENDP

SysQueryOpenSubKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryOpenSubKeys syscall offset (<syscall_id>)
    syscall
    ret
SysQueryOpenSubKeys ENDP

SysQueryOpenSubKeysEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryOpenSubKeysEx syscall offset (<syscall_id>)
    syscall
    ret
SysQueryOpenSubKeysEx ENDP

SysQueryPerformanceCounter PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryPerformanceCounter syscall offset (<syscall_id>)
    syscall
    ret
SysQueryPerformanceCounter ENDP

SysQueryPortInformationProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryPortInformationProcess syscall offset (<syscall_id>)
    syscall
    ret
SysQueryPortInformationProcess ENDP

SysQueryQuotaInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryQuotaInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SysQueryQuotaInformationFile ENDP

SysQuerySection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySection syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySection ENDP

SysQuerySecurityAttributesToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySecurityAttributesToken syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySecurityAttributesToken ENDP

SysQuerySecurityObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySecurityObject syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySecurityObject ENDP

SysQuerySecurityPolicy PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySecurityPolicy syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySecurityPolicy ENDP

SysQuerySemaphore PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySemaphore syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySemaphore ENDP

SysQuerySymbolicLinkObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySymbolicLinkObject syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySymbolicLinkObject ENDP

SysQuerySystemEnvironmentValue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySystemEnvironmentValue syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySystemEnvironmentValue ENDP

SysQuerySystemEnvironmentValueEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySystemEnvironmentValueEx syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySystemEnvironmentValueEx ENDP

SysQuerySystemInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySystemInformation syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySystemInformation ENDP

SysQuerySystemInformationEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySystemInformationEx syscall offset (<syscall_id>)
    syscall
    ret
SysQuerySystemInformationEx ENDP

SysQueryTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryTimer syscall offset (<syscall_id>)
    syscall
    ret
SysQueryTimer ENDP

SysQueryTimerResolution PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryTimerResolution syscall offset (<syscall_id>)
    syscall
    ret
SysQueryTimerResolution ENDP

SysQueryValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryValueKey syscall offset (<syscall_id>)
    syscall
    ret
SysQueryValueKey ENDP

SysQueryVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysQueryVirtualMemory ENDP

SysQueryVolumeInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryVolumeInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SysQueryVolumeInformationFile ENDP

SysQueryWnfStateData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryWnfStateData syscall offset (<syscall_id>)
    syscall
    ret
SysQueryWnfStateData ENDP

SysQueryWnfStateNameInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryWnfStateNameInformation syscall offset (<syscall_id>)
    syscall
    ret
SysQueryWnfStateNameInformation ENDP

SysQueueApcThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueueApcThread syscall offset (<syscall_id>)
    syscall
    ret
SysQueueApcThread ENDP

SysQueueApcThreadEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueueApcThreadEx syscall offset (<syscall_id>)
    syscall
    ret
SysQueueApcThreadEx ENDP

SysQueueApcThreadEx2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueueApcThreadEx2 syscall offset (<syscall_id>)
    syscall
    ret
SysQueueApcThreadEx2 ENDP

SysRaiseException PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRaiseException syscall offset (<syscall_id>)
    syscall
    ret
SysRaiseException ENDP

SysRaiseHardError PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRaiseHardError syscall offset (<syscall_id>)
    syscall
    ret
SysRaiseHardError ENDP

SysReadFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadFile syscall offset (<syscall_id>)
    syscall
    ret
SysReadFile ENDP

SysReadFileScatter PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadFileScatter syscall offset (<syscall_id>)
    syscall
    ret
SysReadFileScatter ENDP

SysReadOnlyEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadOnlyEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysReadOnlyEnlistment ENDP

SysReadRequestData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadRequestData syscall offset (<syscall_id>)
    syscall
    ret
SysReadRequestData ENDP

SysReadVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysReadVirtualMemory ENDP

SysReadVirtualMemoryEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadVirtualMemoryEx syscall offset (<syscall_id>)
    syscall
    ret
SysReadVirtualMemoryEx ENDP

SysRecoverEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRecoverEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysRecoverEnlistment ENDP

SysRecoverResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRecoverResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SysRecoverResourceManager ENDP

SysRecoverTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRecoverTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SysRecoverTransactionManager ENDP

SysRegisterProtocolAddressInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRegisterProtocolAddressInformation syscall offset (<syscall_id>)
    syscall
    ret
SysRegisterProtocolAddressInformation ENDP

SysRegisterThreadTerminatePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRegisterThreadTerminatePort syscall offset (<syscall_id>)
    syscall
    ret
SysRegisterThreadTerminatePort ENDP

SysReleaseKeyedEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReleaseKeyedEvent syscall offset (<syscall_id>)
    syscall
    ret
SysReleaseKeyedEvent ENDP

SysReleaseMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReleaseMutant syscall offset (<syscall_id>)
    syscall
    ret
SysReleaseMutant ENDP

SysReleaseSemaphore PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReleaseSemaphore syscall offset (<syscall_id>)
    syscall
    ret
SysReleaseSemaphore ENDP

SysReleaseWorkerFactoryWorker PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReleaseWorkerFactoryWorker syscall offset (<syscall_id>)
    syscall
    ret
SysReleaseWorkerFactoryWorker ENDP

SysRemoveIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRemoveIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SysRemoveIoCompletion ENDP

SysRemoveIoCompletionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRemoveIoCompletionEx syscall offset (<syscall_id>)
    syscall
    ret
SysRemoveIoCompletionEx ENDP

SysRemoveProcessDebug PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRemoveProcessDebug syscall offset (<syscall_id>)
    syscall
    ret
SysRemoveProcessDebug ENDP

SysRenameKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRenameKey syscall offset (<syscall_id>)
    syscall
    ret
SysRenameKey ENDP

SysRenameTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRenameTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SysRenameTransactionManager ENDP

SysReplaceKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplaceKey syscall offset (<syscall_id>)
    syscall
    ret
SysReplaceKey ENDP

SysReplacePartitionUnit PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplacePartitionUnit syscall offset (<syscall_id>)
    syscall
    ret
SysReplacePartitionUnit ENDP

SysReplyPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplyPort syscall offset (<syscall_id>)
    syscall
    ret
SysReplyPort ENDP

SysReplyWaitReceivePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplyWaitReceivePort syscall offset (<syscall_id>)
    syscall
    ret
SysReplyWaitReceivePort ENDP

SysReplyWaitReceivePortEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplyWaitReceivePortEx syscall offset (<syscall_id>)
    syscall
    ret
SysReplyWaitReceivePortEx ENDP

SysReplyWaitReplyPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplyWaitReplyPort syscall offset (<syscall_id>)
    syscall
    ret
SysReplyWaitReplyPort ENDP

SysRequestPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRequestPort syscall offset (<syscall_id>)
    syscall
    ret
SysRequestPort ENDP

SysRequestWaitReplyPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRequestWaitReplyPort syscall offset (<syscall_id>)
    syscall
    ret
SysRequestWaitReplyPort ENDP

SysResetEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwResetEvent syscall offset (<syscall_id>)
    syscall
    ret
SysResetEvent ENDP

SysResetWriteWatch PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwResetWriteWatch syscall offset (<syscall_id>)
    syscall
    ret
SysResetWriteWatch ENDP

SysRestoreKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRestoreKey syscall offset (<syscall_id>)
    syscall
    ret
SysRestoreKey ENDP

SysResumeProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwResumeProcess syscall offset (<syscall_id>)
    syscall
    ret
SysResumeProcess ENDP

SysResumeThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwResumeThread syscall offset (<syscall_id>)
    syscall
    ret
SysResumeThread ENDP

SysRevertContainerImpersonation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRevertContainerImpersonation syscall offset (<syscall_id>)
    syscall
    ret
SysRevertContainerImpersonation ENDP

SysRollbackComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollbackComplete syscall offset (<syscall_id>)
    syscall
    ret
SysRollbackComplete ENDP

SysRollbackEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollbackEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysRollbackEnlistment ENDP

SysRollbackRegistryTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollbackRegistryTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysRollbackRegistryTransaction ENDP

SysRollbackTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollbackTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysRollbackTransaction ENDP

SysRollforwardTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollforwardTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SysRollforwardTransactionManager ENDP

SysSaveKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSaveKey syscall offset (<syscall_id>)
    syscall
    ret
SysSaveKey ENDP

SysSaveKeyEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSaveKeyEx syscall offset (<syscall_id>)
    syscall
    ret
SysSaveKeyEx ENDP

SysSaveMergedKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSaveMergedKeys syscall offset (<syscall_id>)
    syscall
    ret
SysSaveMergedKeys ENDP

SysSecureConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSecureConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SysSecureConnectPort ENDP

SysSerializeBoot PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSerializeBoot syscall offset (<syscall_id>)
    syscall
    ret
SysSerializeBoot ENDP

SysSetBootEntryOrder PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetBootEntryOrder syscall offset (<syscall_id>)
    syscall
    ret
SysSetBootEntryOrder ENDP

SysSetBootOptions PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetBootOptions syscall offset (<syscall_id>)
    syscall
    ret
SysSetBootOptions ENDP

SysSetCachedSigningLevel PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetCachedSigningLevel syscall offset (<syscall_id>)
    syscall
    ret
SysSetCachedSigningLevel ENDP

SysSetCachedSigningLevel2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetCachedSigningLevel2 syscall offset (<syscall_id>)
    syscall
    ret
SysSetCachedSigningLevel2 ENDP

SysSetContextThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetContextThread syscall offset (<syscall_id>)
    syscall
    ret
SysSetContextThread ENDP

SysSetDebugFilterState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDebugFilterState syscall offset (<syscall_id>)
    syscall
    ret
SysSetDebugFilterState ENDP

SysSetDefaultHardErrorPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDefaultHardErrorPort syscall offset (<syscall_id>)
    syscall
    ret
SysSetDefaultHardErrorPort ENDP

SysSetDefaultLocale PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDefaultLocale syscall offset (<syscall_id>)
    syscall
    ret
SysSetDefaultLocale ENDP

SysSetDefaultUILanguage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDefaultUILanguage syscall offset (<syscall_id>)
    syscall
    ret
SysSetDefaultUILanguage ENDP

SysSetDriverEntryOrder PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDriverEntryOrder syscall offset (<syscall_id>)
    syscall
    ret
SysSetDriverEntryOrder ENDP

SysSetEaFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetEaFile syscall offset (<syscall_id>)
    syscall
    ret
SysSetEaFile ENDP

SysSetEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetEvent syscall offset (<syscall_id>)
    syscall
    ret
SysSetEvent ENDP

SysSetEventBoostPriority PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetEventBoostPriority syscall offset (<syscall_id>)
    syscall
    ret
SysSetEventBoostPriority ENDP

SysSetHighEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetHighEventPair syscall offset (<syscall_id>)
    syscall
    ret
SysSetHighEventPair ENDP

SysSetHighWaitLowEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetHighWaitLowEventPair syscall offset (<syscall_id>)
    syscall
    ret
SysSetHighWaitLowEventPair ENDP

SysSetIRTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetIRTimer syscall offset (<syscall_id>)
    syscall
    ret
SysSetIRTimer ENDP

SysSetInformationCpuPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationCpuPartition syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationCpuPartition ENDP

SysSetInformationDebugObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationDebugObject syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationDebugObject ENDP

SysSetInformationEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationEnlistment ENDP

SysSetInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationFile ENDP

SysSetInformationIoRing PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationIoRing syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationIoRing ENDP

SysSetInformationJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationJobObject syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationJobObject ENDP

SysSetInformationKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationKey syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationKey ENDP

SysSetInformationObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationObject syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationObject ENDP

SysSetInformationProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationProcess syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationProcess ENDP

SysSetInformationResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationResourceManager ENDP

SysSetInformationSymbolicLink PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationSymbolicLink syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationSymbolicLink ENDP

SysSetInformationThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationThread syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationThread ENDP

SysSetInformationToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationToken syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationToken ENDP

SysSetInformationTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationTransaction syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationTransaction ENDP

SysSetInformationTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationTransactionManager ENDP

SysSetInformationVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationVirtualMemory ENDP

SysSetInformationWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SysSetInformationWorkerFactory ENDP

SysSetIntervalProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetIntervalProfile syscall offset (<syscall_id>)
    syscall
    ret
SysSetIntervalProfile ENDP

SysSetIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SysSetIoCompletion ENDP

SysSetIoCompletionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetIoCompletionEx syscall offset (<syscall_id>)
    syscall
    ret
SysSetIoCompletionEx ENDP

SysSetLdtEntries PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetLdtEntries syscall offset (<syscall_id>)
    syscall
    ret
SysSetLdtEntries ENDP

SysSetLowEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetLowEventPair syscall offset (<syscall_id>)
    syscall
    ret
SysSetLowEventPair ENDP

SysSetLowWaitHighEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetLowWaitHighEventPair syscall offset (<syscall_id>)
    syscall
    ret
SysSetLowWaitHighEventPair ENDP

SysSetQuotaInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetQuotaInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SysSetQuotaInformationFile ENDP

SysSetSecurityObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSecurityObject syscall offset (<syscall_id>)
    syscall
    ret
SysSetSecurityObject ENDP

SysSetSystemEnvironmentValue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemEnvironmentValue syscall offset (<syscall_id>)
    syscall
    ret
SysSetSystemEnvironmentValue ENDP

SysSetSystemEnvironmentValueEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemEnvironmentValueEx syscall offset (<syscall_id>)
    syscall
    ret
SysSetSystemEnvironmentValueEx ENDP

SysSetSystemInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemInformation syscall offset (<syscall_id>)
    syscall
    ret
SysSetSystemInformation ENDP

SysSetSystemPowerState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemPowerState syscall offset (<syscall_id>)
    syscall
    ret
SysSetSystemPowerState ENDP

SysSetSystemTime PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemTime syscall offset (<syscall_id>)
    syscall
    ret
SysSetSystemTime ENDP

SysSetThreadExecutionState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetThreadExecutionState syscall offset (<syscall_id>)
    syscall
    ret
SysSetThreadExecutionState ENDP

SysSetTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetTimer syscall offset (<syscall_id>)
    syscall
    ret
SysSetTimer ENDP

SysSetTimer2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetTimer2 syscall offset (<syscall_id>)
    syscall
    ret
SysSetTimer2 ENDP

SysSetTimerEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetTimerEx syscall offset (<syscall_id>)
    syscall
    ret
SysSetTimerEx ENDP

SysSetTimerResolution PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetTimerResolution syscall offset (<syscall_id>)
    syscall
    ret
SysSetTimerResolution ENDP

SysSetUuidSeed PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetUuidSeed syscall offset (<syscall_id>)
    syscall
    ret
SysSetUuidSeed ENDP

SysSetValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetValueKey syscall offset (<syscall_id>)
    syscall
    ret
SysSetValueKey ENDP

SysSetVolumeInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetVolumeInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SysSetVolumeInformationFile ENDP

SysSetWnfProcessNotificationEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetWnfProcessNotificationEvent syscall offset (<syscall_id>)
    syscall
    ret
SysSetWnfProcessNotificationEvent ENDP

SysShutdownSystem PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwShutdownSystem syscall offset (<syscall_id>)
    syscall
    ret
SysShutdownSystem ENDP

SysShutdownWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwShutdownWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SysShutdownWorkerFactory ENDP

SysSignalAndWaitForSingleObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSignalAndWaitForSingleObject syscall offset (<syscall_id>)
    syscall
    ret
SysSignalAndWaitForSingleObject ENDP

SysSinglePhaseReject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSinglePhaseReject syscall offset (<syscall_id>)
    syscall
    ret
SysSinglePhaseReject ENDP

SysStartProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwStartProfile syscall offset (<syscall_id>)
    syscall
    ret
SysStartProfile ENDP

SysStopProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwStopProfile syscall offset (<syscall_id>)
    syscall
    ret
SysStopProfile ENDP

SysSubmitIoRing PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSubmitIoRing syscall offset (<syscall_id>)
    syscall
    ret
SysSubmitIoRing ENDP

SysSubscribeWnfStateChange PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSubscribeWnfStateChange syscall offset (<syscall_id>)
    syscall
    ret
SysSubscribeWnfStateChange ENDP

SysSuspendProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSuspendProcess syscall offset (<syscall_id>)
    syscall
    ret
SysSuspendProcess ENDP

SysSuspendThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSuspendThread syscall offset (<syscall_id>)
    syscall
    ret
SysSuspendThread ENDP

SysSystemDebugControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSystemDebugControl syscall offset (<syscall_id>)
    syscall
    ret
SysSystemDebugControl ENDP

SysTerminateEnclave PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTerminateEnclave syscall offset (<syscall_id>)
    syscall
    ret
SysTerminateEnclave ENDP

SysTerminateJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTerminateJobObject syscall offset (<syscall_id>)
    syscall
    ret
SysTerminateJobObject ENDP

SysTerminateProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTerminateProcess syscall offset (<syscall_id>)
    syscall
    ret
SysTerminateProcess ENDP

SysTerminateThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTerminateThread syscall offset (<syscall_id>)
    syscall
    ret
SysTerminateThread ENDP

SysTestAlert PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTestAlert syscall offset (<syscall_id>)
    syscall
    ret
SysTestAlert ENDP

SysThawRegistry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwThawRegistry syscall offset (<syscall_id>)
    syscall
    ret
SysThawRegistry ENDP

SysThawTransactions PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwThawTransactions syscall offset (<syscall_id>)
    syscall
    ret
SysThawTransactions ENDP

SysTraceControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTraceControl syscall offset (<syscall_id>)
    syscall
    ret
SysTraceControl ENDP

SysTraceEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTraceEvent syscall offset (<syscall_id>)
    syscall
    ret
SysTraceEvent ENDP

SysTranslateFilePath PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTranslateFilePath syscall offset (<syscall_id>)
    syscall
    ret
SysTranslateFilePath ENDP

SysUmsThreadYield PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUmsThreadYield syscall offset (<syscall_id>)
    syscall
    ret
SysUmsThreadYield ENDP

SysUnloadDriver PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnloadDriver syscall offset (<syscall_id>)
    syscall
    ret
SysUnloadDriver ENDP

SysUnloadKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnloadKey syscall offset (<syscall_id>)
    syscall
    ret
SysUnloadKey ENDP

SysUnloadKey2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnloadKey2 syscall offset (<syscall_id>)
    syscall
    ret
SysUnloadKey2 ENDP

SysUnloadKeyEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnloadKeyEx syscall offset (<syscall_id>)
    syscall
    ret
SysUnloadKeyEx ENDP

SysUnlockFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnlockFile syscall offset (<syscall_id>)
    syscall
    ret
SysUnlockFile ENDP

SysUnlockVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnlockVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysUnlockVirtualMemory ENDP

SysUnmapViewOfSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnmapViewOfSection syscall offset (<syscall_id>)
    syscall
    ret
SysUnmapViewOfSection ENDP

SysUnmapViewOfSectionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnmapViewOfSectionEx syscall offset (<syscall_id>)
    syscall
    ret
SysUnmapViewOfSectionEx ENDP

SysUnsubscribeWnfStateChange PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnsubscribeWnfStateChange syscall offset (<syscall_id>)
    syscall
    ret
SysUnsubscribeWnfStateChange ENDP

SysUpdateWnfStateData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUpdateWnfStateData syscall offset (<syscall_id>)
    syscall
    ret
SysUpdateWnfStateData ENDP

SysVdmControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwVdmControl syscall offset (<syscall_id>)
    syscall
    ret
SysVdmControl ENDP

SysWaitForAlertByThreadId PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForAlertByThreadId syscall offset (<syscall_id>)
    syscall
    ret
SysWaitForAlertByThreadId ENDP

SysWaitForDebugEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForDebugEvent syscall offset (<syscall_id>)
    syscall
    ret
SysWaitForDebugEvent ENDP

SysWaitForKeyedEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForKeyedEvent syscall offset (<syscall_id>)
    syscall
    ret
SysWaitForKeyedEvent ENDP

SysWaitForMultipleObjects PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForMultipleObjects syscall offset (<syscall_id>)
    syscall
    ret
SysWaitForMultipleObjects ENDP

SysWaitForMultipleObjects32 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForMultipleObjects32 syscall offset (<syscall_id>)
    syscall
    ret
SysWaitForMultipleObjects32 ENDP

SysWaitForSingleObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForSingleObject syscall offset (<syscall_id>)
    syscall
    ret
SysWaitForSingleObject ENDP

SysWaitForWorkViaWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForWorkViaWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SysWaitForWorkViaWorkerFactory ENDP

SysWaitHighEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitHighEventPair syscall offset (<syscall_id>)
    syscall
    ret
SysWaitHighEventPair ENDP

SysWaitLowEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitLowEventPair syscall offset (<syscall_id>)
    syscall
    ret
SysWaitLowEventPair ENDP

SysWorkerFactoryWorkerReady PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWorkerFactoryWorkerReady syscall offset (<syscall_id>)
    syscall
    ret
SysWorkerFactoryWorkerReady ENDP

SysWriteFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWriteFile syscall offset (<syscall_id>)
    syscall
    ret
SysWriteFile ENDP

SysWriteFileGather PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWriteFileGather syscall offset (<syscall_id>)
    syscall
    ret
SysWriteFileGather ENDP

SysWriteRequestData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWriteRequestData syscall offset (<syscall_id>)
    syscall
    ret
SysWriteRequestData ENDP

SysWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWriteVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SysWriteVirtualMemory ENDP

SysYieldExecution PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwYieldExecution syscall offset (<syscall_id>)
    syscall
    ret
SysYieldExecution ENDP

end 
