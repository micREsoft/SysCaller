.code

SCAcceptConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAcceptConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SCAcceptConnectPort ENDP

SCAccessCheck PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheck syscall offset (<syscall_id>)
    syscall
    ret
SCAccessCheck ENDP

SCAccessCheckAndAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckAndAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SCAccessCheckAndAuditAlarm ENDP

SCAccessCheckByType PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByType syscall offset (<syscall_id>)
    syscall
    ret
SCAccessCheckByType ENDP

SCAccessCheckByTypeAndAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByTypeAndAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SCAccessCheckByTypeAndAuditAlarm ENDP

SCAccessCheckByTypeResultList PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByTypeResultList syscall offset (<syscall_id>)
    syscall
    ret
SCAccessCheckByTypeResultList ENDP

SCAccessCheckByTypeResultListAndAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByTypeResultListAndAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SCAccessCheckByTypeResultListAndAuditAlarm ENDP

SCAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAccessCheckByTypeResultListAndAuditAlarmByHandle syscall offset (<syscall_id>)
    syscall
    ret
SCAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

SCAcquireCrossVmMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAcquireCrossVmMutant syscall offset (<syscall_id>)
    syscall
    ret
SCAcquireCrossVmMutant ENDP

SCAcquireProcessActivityReference PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAcquireProcessActivityReference syscall offset (<syscall_id>)
    syscall
    ret
SCAcquireProcessActivityReference ENDP

SCAddAtom PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAddAtom syscall offset (<syscall_id>)
    syscall
    ret
SCAddAtom ENDP

SCAddAtomEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAddAtomEx syscall offset (<syscall_id>)
    syscall
    ret
SCAddAtomEx ENDP

SCAddBootEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAddBootEntry syscall offset (<syscall_id>)
    syscall
    ret
SCAddBootEntry ENDP

SCAddDriverEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAddDriverEntry syscall offset (<syscall_id>)
    syscall
    ret
SCAddDriverEntry ENDP

SCAdjustGroupsToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAdjustGroupsToken syscall offset (<syscall_id>)
    syscall
    ret
SCAdjustGroupsToken ENDP

SCAdjustPrivilegesToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAdjustPrivilegesToken syscall offset (<syscall_id>)
    syscall
    ret
SCAdjustPrivilegesToken ENDP

SCAdjustTokenClaimsAndDeviceGroups PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAdjustTokenClaimsAndDeviceGroups syscall offset (<syscall_id>)
    syscall
    ret
SCAdjustTokenClaimsAndDeviceGroups ENDP

SCAlertResumeThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlertResumeThread syscall offset (<syscall_id>)
    syscall
    ret
SCAlertResumeThread ENDP

SCAlertThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlertThread syscall offset (<syscall_id>)
    syscall
    ret
SCAlertThread ENDP

SCAlertThreadByThreadId PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlertThreadByThreadId syscall offset (<syscall_id>)
    syscall
    ret
SCAlertThreadByThreadId ENDP

SCAllocateLocallyUniqueId PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateLocallyUniqueId syscall offset (<syscall_id>)
    syscall
    ret
SCAllocateLocallyUniqueId ENDP

SCAllocateReserveObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateReserveObject syscall offset (<syscall_id>)
    syscall
    ret
SCAllocateReserveObject ENDP

SCAllocateUserPhysicalPages PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateUserPhysicalPages syscall offset (<syscall_id>)
    syscall
    ret
SCAllocateUserPhysicalPages ENDP

SCAllocateUserPhysicalPagesEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateUserPhysicalPagesEx syscall offset (<syscall_id>)
    syscall
    ret
SCAllocateUserPhysicalPagesEx ENDP

SCAllocateUuids PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateUuids syscall offset (<syscall_id>)
    syscall
    ret
SCAllocateUuids ENDP

SCAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCAllocateVirtualMemory ENDP

SCAllocateVirtualMemoryEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAllocateVirtualMemoryEx syscall offset (<syscall_id>)
    syscall
    ret
SCAllocateVirtualMemoryEx ENDP

SCAlpcAcceptConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcAcceptConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcAcceptConnectPort ENDP

SCAlpcCancelMessage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCancelMessage syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcCancelMessage ENDP

SCAlpcConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcConnectPort ENDP

SCAlpcConnectPortEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcConnectPortEx syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcConnectPortEx ENDP

SCAlpcCreatePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreatePort syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcCreatePort ENDP

SCAlpcCreatePortSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreatePortSection syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcCreatePortSection ENDP

SCAlpcCreateResourceReserve PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreateResourceReserve syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcCreateResourceReserve ENDP

SCAlpcCreateSectionView PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreateSectionView syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcCreateSectionView ENDP

SCAlpcCreateSecurityContext PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcCreateSecurityContext syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcCreateSecurityContext ENDP

SCAlpcDeletePortSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDeletePortSection syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcDeletePortSection ENDP

SCAlpcDeleteResourceReserve PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDeleteResourceReserve syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcDeleteResourceReserve ENDP

SCAlpcDeleteSectionView PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDeleteSectionView syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcDeleteSectionView ENDP

SCAlpcDeleteSecurityContext PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDeleteSecurityContext syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcDeleteSecurityContext ENDP

SCAlpcDisconnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcDisconnectPort syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcDisconnectPort ENDP

SCAlpcImpersonateClientContainerOfPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcImpersonateClientContainerOfPort syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcImpersonateClientContainerOfPort ENDP

SCAlpcImpersonateClientOfPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcImpersonateClientOfPort syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcImpersonateClientOfPort ENDP

SCAlpcOpenSenderProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcOpenSenderProcess syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcOpenSenderProcess ENDP

SCAlpcOpenSenderThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcOpenSenderThread syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcOpenSenderThread ENDP

SCAlpcQueryInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcQueryInformation syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcQueryInformation ENDP

SCAlpcQueryInformationMessage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcQueryInformationMessage syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcQueryInformationMessage ENDP

SCAlpcRevokeSecurityContext PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcRevokeSecurityContext syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcRevokeSecurityContext ENDP

SCAlpcSendWaitReceivePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcSendWaitReceivePort syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcSendWaitReceivePort ENDP

SCAlpcSetInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAlpcSetInformation syscall offset (<syscall_id>)
    syscall
    ret
SCAlpcSetInformation ENDP

SCApphelpCacheControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwApphelpCacheControl syscall offset (<syscall_id>)
    syscall
    ret
SCApphelpCacheControl ENDP

SCAreMappedFilesTheSame PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAreMappedFilesTheSame syscall offset (<syscall_id>)
    syscall
    ret
SCAreMappedFilesTheSame ENDP

SCAssignProcessToJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAssignProcessToJobObject syscall offset (<syscall_id>)
    syscall
    ret
SCAssignProcessToJobObject ENDP

SCAssociateWaitCompletionPacket PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwAssociateWaitCompletionPacket syscall offset (<syscall_id>)
    syscall
    ret
SCAssociateWaitCompletionPacket ENDP

SCCallEnclave PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCallEnclave syscall offset (<syscall_id>)
    syscall
    ret
SCCallEnclave ENDP

SCCallbackReturn PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCallbackReturn syscall offset (<syscall_id>)
    syscall
    ret
SCCallbackReturn ENDP

SCCancelIoFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelIoFile syscall offset (<syscall_id>)
    syscall
    ret
SCCancelIoFile ENDP

SCCancelIoFileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelIoFileEx syscall offset (<syscall_id>)
    syscall
    ret
SCCancelIoFileEx ENDP

SCCancelSynchronousIoFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelSynchronousIoFile syscall offset (<syscall_id>)
    syscall
    ret
SCCancelSynchronousIoFile ENDP

SCCancelTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelTimer syscall offset (<syscall_id>)
    syscall
    ret
SCCancelTimer ENDP

SCCancelTimer2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelTimer2 syscall offset (<syscall_id>)
    syscall
    ret
SCCancelTimer2 ENDP

SCCancelWaitCompletionPacket PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCancelWaitCompletionPacket syscall offset (<syscall_id>)
    syscall
    ret
SCCancelWaitCompletionPacket ENDP

SCChangeProcessState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwChangeProcessState syscall offset (<syscall_id>)
    syscall
    ret
SCChangeProcessState ENDP

SCChangeThreadState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwChangeThreadState syscall offset (<syscall_id>)
    syscall
    ret
SCChangeThreadState ENDP

SCClearEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwClearEvent syscall offset (<syscall_id>)
    syscall
    ret
SCClearEvent ENDP

SCClose PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwClose syscall offset (<syscall_id>)
    syscall
    ret
SCClose ENDP

SCCloseObjectAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCloseObjectAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SCCloseObjectAuditAlarm ENDP

SCCommitComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCommitComplete syscall offset (<syscall_id>)
    syscall
    ret
SCCommitComplete ENDP

SCCommitEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCommitEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCCommitEnlistment ENDP

SCCommitRegistryTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCommitRegistryTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCCommitRegistryTransaction ENDP

SCCommitTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCommitTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCCommitTransaction ENDP

SCCompactKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompactKeys syscall offset (<syscall_id>)
    syscall
    ret
SCCompactKeys ENDP

SCCompareObjects PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompareObjects syscall offset (<syscall_id>)
    syscall
    ret
SCCompareObjects ENDP

SCCompareSigningLevels PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompareSigningLevels syscall offset (<syscall_id>)
    syscall
    ret
SCCompareSigningLevels ENDP

SCCompareTokens PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompareTokens syscall offset (<syscall_id>)
    syscall
    ret
SCCompareTokens ENDP

SCCompleteConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompleteConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SCCompleteConnectPort ENDP

SCCompressKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCompressKey syscall offset (<syscall_id>)
    syscall
    ret
SCCompressKey ENDP

SCConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SCConnectPort ENDP

SCContinue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwContinue syscall offset (<syscall_id>)
    syscall
    ret
SCContinue ENDP

SCContinueEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwContinueEx syscall offset (<syscall_id>)
    syscall
    ret
SCContinueEx ENDP

SCConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter syscall offset (<syscall_id>)
    syscall
    ret
SCConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

SCCopyFileChunk PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCopyFileChunk syscall offset (<syscall_id>)
    syscall
    ret
SCCopyFileChunk ENDP

SCCreateCpuPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateCpuPartition syscall offset (<syscall_id>)
    syscall
    ret
SCCreateCpuPartition ENDP

SCCreateCrossVmEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateCrossVmEvent syscall offset (<syscall_id>)
    syscall
    ret
SCCreateCrossVmEvent ENDP

SCCreateCrossVmMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateCrossVmMutant syscall offset (<syscall_id>)
    syscall
    ret
SCCreateCrossVmMutant ENDP

SCCreateDebugObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateDebugObject syscall offset (<syscall_id>)
    syscall
    ret
SCCreateDebugObject ENDP

SCCreateDirectoryObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateDirectoryObject syscall offset (<syscall_id>)
    syscall
    ret
SCCreateDirectoryObject ENDP

SCCreateDirectoryObjectEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateDirectoryObjectEx syscall offset (<syscall_id>)
    syscall
    ret
SCCreateDirectoryObjectEx ENDP

SCCreateEnclave PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateEnclave syscall offset (<syscall_id>)
    syscall
    ret
SCCreateEnclave ENDP

SCCreateEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCCreateEnlistment ENDP

SCCreateEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateEvent syscall offset (<syscall_id>)
    syscall
    ret
SCCreateEvent ENDP

SCCreateEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateEventPair syscall offset (<syscall_id>)
    syscall
    ret
SCCreateEventPair ENDP

SCCreateFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateFile syscall offset (<syscall_id>)
    syscall
    ret
SCCreateFile ENDP

SCCreateIRTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateIRTimer syscall offset (<syscall_id>)
    syscall
    ret
SCCreateIRTimer ENDP

SCCreateIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SCCreateIoCompletion ENDP

SCCreateIoRing PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateIoRing syscall offset (<syscall_id>)
    syscall
    ret
SCCreateIoRing ENDP

SCCreateJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateJobObject syscall offset (<syscall_id>)
    syscall
    ret
SCCreateJobObject ENDP

SCCreateJobSet PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateJobSet syscall offset (<syscall_id>)
    syscall
    ret
SCCreateJobSet ENDP

SCCreateKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateKey syscall offset (<syscall_id>)
    syscall
    ret
SCCreateKey ENDP

SCCreateKeyTransacted PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateKeyTransacted syscall offset (<syscall_id>)
    syscall
    ret
SCCreateKeyTransacted ENDP

SCCreateKeyedEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateKeyedEvent syscall offset (<syscall_id>)
    syscall
    ret
SCCreateKeyedEvent ENDP

SCCreateLowBoxToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateLowBoxToken syscall offset (<syscall_id>)
    syscall
    ret
SCCreateLowBoxToken ENDP

SCCreateMailslotFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateMailslotFile syscall offset (<syscall_id>)
    syscall
    ret
SCCreateMailslotFile ENDP

SCCreateMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateMutant syscall offset (<syscall_id>)
    syscall
    ret
SCCreateMutant ENDP

SCCreateNamedPipeFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateNamedPipeFile syscall offset (<syscall_id>)
    syscall
    ret
SCCreateNamedPipeFile ENDP

SCCreatePagingFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreatePagingFile syscall offset (<syscall_id>)
    syscall
    ret
SCCreatePagingFile ENDP

SCCreatePartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreatePartition syscall offset (<syscall_id>)
    syscall
    ret
SCCreatePartition ENDP

SCCreatePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreatePort syscall offset (<syscall_id>)
    syscall
    ret
SCCreatePort ENDP

SCCreatePrivateNamespace PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreatePrivateNamespace syscall offset (<syscall_id>)
    syscall
    ret
SCCreatePrivateNamespace ENDP

SCCreateProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProcess syscall offset (<syscall_id>)
    syscall
    ret
SCCreateProcess ENDP

SCCreateProcessEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProcessEx syscall offset (<syscall_id>)
    syscall
    ret
SCCreateProcessEx ENDP

SCCreateProcessStateChange PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProcessStateChange syscall offset (<syscall_id>)
    syscall
    ret
SCCreateProcessStateChange ENDP

SCCreateProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProfile syscall offset (<syscall_id>)
    syscall
    ret
SCCreateProfile ENDP

SCCreateProfileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateProfileEx syscall offset (<syscall_id>)
    syscall
    ret
SCCreateProfileEx ENDP

SCCreateRegistryTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateRegistryTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCCreateRegistryTransaction ENDP

SCCreateResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SCCreateResourceManager ENDP

SCCreateSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateSection syscall offset (<syscall_id>)
    syscall
    ret
SCCreateSection ENDP

SCCreateSectionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateSectionEx syscall offset (<syscall_id>)
    syscall
    ret
SCCreateSectionEx ENDP

SCCreateSemaphore PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateSemaphore syscall offset (<syscall_id>)
    syscall
    ret
SCCreateSemaphore ENDP

SCCreateSymbolicLinkObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateSymbolicLinkObject syscall offset (<syscall_id>)
    syscall
    ret
SCCreateSymbolicLinkObject ENDP

SCCreateThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateThread syscall offset (<syscall_id>)
    syscall
    ret
SCCreateThread ENDP

SCCreateThreadEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateThreadEx syscall offset (<syscall_id>)
    syscall
    ret
SCCreateThreadEx ENDP

SCCreateThreadStateChange PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateThreadStateChange syscall offset (<syscall_id>)
    syscall
    ret
SCCreateThreadStateChange ENDP

SCCreateTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTimer syscall offset (<syscall_id>)
    syscall
    ret
SCCreateTimer ENDP

SCCreateTimer2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTimer2 syscall offset (<syscall_id>)
    syscall
    ret
SCCreateTimer2 ENDP

SCCreateToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateToken syscall offset (<syscall_id>)
    syscall
    ret
SCCreateToken ENDP

SCCreateTokenEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTokenEx syscall offset (<syscall_id>)
    syscall
    ret
SCCreateTokenEx ENDP

SCCreateTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCCreateTransaction ENDP

SCCreateTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SCCreateTransactionManager ENDP

SCCreateUserProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateUserProcess syscall offset (<syscall_id>)
    syscall
    ret
SCCreateUserProcess ENDP

SCCreateWaitCompletionPacket PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateWaitCompletionPacket syscall offset (<syscall_id>)
    syscall
    ret
SCCreateWaitCompletionPacket ENDP

SCCreateWaitablePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateWaitablePort syscall offset (<syscall_id>)
    syscall
    ret
SCCreateWaitablePort ENDP

SCCreateWnfStateName PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateWnfStateName syscall offset (<syscall_id>)
    syscall
    ret
SCCreateWnfStateName ENDP

SCCreateWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwCreateWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SCCreateWorkerFactory ENDP

SCDebugActiveProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDebugActiveProcess syscall offset (<syscall_id>)
    syscall
    ret
SCDebugActiveProcess ENDP

SCDebugContinue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDebugContinue syscall offset (<syscall_id>)
    syscall
    ret
SCDebugContinue ENDP

SCDelayExecution PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDelayExecution syscall offset (<syscall_id>)
    syscall
    ret
SCDelayExecution ENDP

SCDeleteAtom PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteAtom syscall offset (<syscall_id>)
    syscall
    ret
SCDeleteAtom ENDP

SCDeleteBootEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteBootEntry syscall offset (<syscall_id>)
    syscall
    ret
SCDeleteBootEntry ENDP

SCDeleteDriverEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteDriverEntry syscall offset (<syscall_id>)
    syscall
    ret
SCDeleteDriverEntry ENDP

SCDeleteFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteFile syscall offset (<syscall_id>)
    syscall
    ret
SCDeleteFile ENDP

SCDeleteKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteKey syscall offset (<syscall_id>)
    syscall
    ret
SCDeleteKey ENDP

SCDeleteObjectAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteObjectAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SCDeleteObjectAuditAlarm ENDP

SCDeletePrivateNamespace PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeletePrivateNamespace syscall offset (<syscall_id>)
    syscall
    ret
SCDeletePrivateNamespace ENDP

SCDeleteValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteValueKey syscall offset (<syscall_id>)
    syscall
    ret
SCDeleteValueKey ENDP

SCDeleteWnfStateData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteWnfStateData syscall offset (<syscall_id>)
    syscall
    ret
SCDeleteWnfStateData ENDP

SCDeleteWnfStateName PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeleteWnfStateName syscall offset (<syscall_id>)
    syscall
    ret
SCDeleteWnfStateName ENDP

SCDeviceIoControlFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDeviceIoControlFile syscall offset (<syscall_id>)
    syscall
    ret
SCDeviceIoControlFile ENDP

SCDirectGraphicsCall PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDirectGraphicsCall syscall offset (<syscall_id>)
    syscall
    ret
SCDirectGraphicsCall ENDP

SCDisableLastKnownGood PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDisableLastKnownGood syscall offset (<syscall_id>)
    syscall
    ret
SCDisableLastKnownGood ENDP

SCDisplayString PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDisplayString syscall offset (<syscall_id>)
    syscall
    ret
SCDisplayString ENDP

SCDrawText PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDrawText syscall offset (<syscall_id>)
    syscall
    ret
SCDrawText ENDP

SCDuplicateObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDuplicateObject syscall offset (<syscall_id>)
    syscall
    ret
SCDuplicateObject ENDP

SCDuplicateToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwDuplicateToken syscall offset (<syscall_id>)
    syscall
    ret
SCDuplicateToken ENDP

SCEnableLastKnownGood PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnableLastKnownGood syscall offset (<syscall_id>)
    syscall
    ret
SCEnableLastKnownGood ENDP

SCEnumerateBootEntries PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateBootEntries syscall offset (<syscall_id>)
    syscall
    ret
SCEnumerateBootEntries ENDP

SCEnumerateDriverEntries PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateDriverEntries syscall offset (<syscall_id>)
    syscall
    ret
SCEnumerateDriverEntries ENDP

SCEnumerateKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateKey syscall offset (<syscall_id>)
    syscall
    ret
SCEnumerateKey ENDP

SCEnumerateSystemEnvironmentValuesEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateSystemEnvironmentValuesEx syscall offset (<syscall_id>)
    syscall
    ret
SCEnumerateSystemEnvironmentValuesEx ENDP

SCEnumerateTransactionObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateTransactionObject syscall offset (<syscall_id>)
    syscall
    ret
SCEnumerateTransactionObject ENDP

SCEnumerateValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwEnumerateValueKey syscall offset (<syscall_id>)
    syscall
    ret
SCEnumerateValueKey ENDP

SCExtendSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwExtendSection syscall offset (<syscall_id>)
    syscall
    ret
SCExtendSection ENDP

SCFilterBootOption PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFilterBootOption syscall offset (<syscall_id>)
    syscall
    ret
SCFilterBootOption ENDP

SCFilterToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFilterToken syscall offset (<syscall_id>)
    syscall
    ret
SCFilterToken ENDP

SCFilterTokenEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFilterTokenEx syscall offset (<syscall_id>)
    syscall
    ret
SCFilterTokenEx ENDP

SCFindAtom PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFindAtom syscall offset (<syscall_id>)
    syscall
    ret
SCFindAtom ENDP

SCFlushBuffersFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushBuffersFile syscall offset (<syscall_id>)
    syscall
    ret
SCFlushBuffersFile ENDP

SCFlushBuffersFileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushBuffersFileEx syscall offset (<syscall_id>)
    syscall
    ret
SCFlushBuffersFileEx ENDP

SCFlushInstallUILanguage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushInstallUILanguage syscall offset (<syscall_id>)
    syscall
    ret
SCFlushInstallUILanguage ENDP

SCFlushInstructionCache PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushInstructionCache syscall offset (<syscall_id>)
    syscall
    ret
SCFlushInstructionCache ENDP

SCFlushKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushKey syscall offset (<syscall_id>)
    syscall
    ret
SCFlushKey ENDP

SCFlushProcessWriteBuffers PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushProcessWriteBuffers syscall offset (<syscall_id>)
    syscall
    ret
SCFlushProcessWriteBuffers ENDP

SCFlushVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCFlushVirtualMemory ENDP

SCFlushWriteBuffer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFlushWriteBuffer syscall offset (<syscall_id>)
    syscall
    ret
SCFlushWriteBuffer ENDP

SCFreeUserPhysicalPages PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFreeUserPhysicalPages syscall offset (<syscall_id>)
    syscall
    ret
SCFreeUserPhysicalPages ENDP

SCFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFreeVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCFreeVirtualMemory ENDP

SCFreezeRegistry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFreezeRegistry syscall offset (<syscall_id>)
    syscall
    ret
SCFreezeRegistry ENDP

SCFreezeTransactions PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFreezeTransactions syscall offset (<syscall_id>)
    syscall
    ret
SCFreezeTransactions ENDP

SCFsControlFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwFsControlFile syscall offset (<syscall_id>)
    syscall
    ret
SCFsControlFile ENDP

SCGetCachedSigningLevel PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetCachedSigningLevel syscall offset (<syscall_id>)
    syscall
    ret
SCGetCachedSigningLevel ENDP

SCGetCompleteWnfStateSubscription PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetCompleteWnfStateSubscription syscall offset (<syscall_id>)
    syscall
    ret
SCGetCompleteWnfStateSubscription ENDP

SCGetContextThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetContextThread syscall offset (<syscall_id>)
    syscall
    ret
SCGetContextThread ENDP

SCGetCurrentProcessorNumber PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetCurrentProcessorNumber syscall offset (<syscall_id>)
    syscall
    ret
SCGetCurrentProcessorNumber ENDP

SCGetCurrentProcessorNumberEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetCurrentProcessorNumberEx syscall offset (<syscall_id>)
    syscall
    ret
SCGetCurrentProcessorNumberEx ENDP

SCGetDevicePowerState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetDevicePowerState syscall offset (<syscall_id>)
    syscall
    ret
SCGetDevicePowerState ENDP

SCGetMUIRegistryInfo PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetMUIRegistryInfo syscall offset (<syscall_id>)
    syscall
    ret
SCGetMUIRegistryInfo ENDP

SCGetNextProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetNextProcess syscall offset (<syscall_id>)
    syscall
    ret
SCGetNextProcess ENDP

SCGetNextThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetNextThread syscall offset (<syscall_id>)
    syscall
    ret
SCGetNextThread ENDP

SCGetNlsSectionPtr PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetNlsSectionPtr syscall offset (<syscall_id>)
    syscall
    ret
SCGetNlsSectionPtr ENDP

SCGetNotificationResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetNotificationResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SCGetNotificationResourceManager ENDP

SCGetWriteWatch PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwGetWriteWatch syscall offset (<syscall_id>)
    syscall
    ret
SCGetWriteWatch ENDP

SCImpersonateAnonymousToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwImpersonateAnonymousToken syscall offset (<syscall_id>)
    syscall
    ret
SCImpersonateAnonymousToken ENDP

SCImpersonateClientOfPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwImpersonateClientOfPort syscall offset (<syscall_id>)
    syscall
    ret
SCImpersonateClientOfPort ENDP

SCImpersonateThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwImpersonateThread syscall offset (<syscall_id>)
    syscall
    ret
SCImpersonateThread ENDP

SCInitializeEnclave PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwInitializeEnclave syscall offset (<syscall_id>)
    syscall
    ret
SCInitializeEnclave ENDP

SCInitializeNlsFiles PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwInitializeNlsFiles syscall offset (<syscall_id>)
    syscall
    ret
SCInitializeNlsFiles ENDP

SCInitializeRegistry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwInitializeRegistry syscall offset (<syscall_id>)
    syscall
    ret
SCInitializeRegistry ENDP

SCInitiatePowerAction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwInitiatePowerAction syscall offset (<syscall_id>)
    syscall
    ret
SCInitiatePowerAction ENDP

SCIsProcessInJob PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwIsProcessInJob syscall offset (<syscall_id>)
    syscall
    ret
SCIsProcessInJob ENDP

SCIsSystemResumeAutomatic PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwIsSystemResumeAutomatic syscall offset (<syscall_id>)
    syscall
    ret
SCIsSystemResumeAutomatic ENDP

SCIsUILanguageComitted PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwIsUILanguageComitted syscall offset (<syscall_id>)
    syscall
    ret
SCIsUILanguageComitted ENDP

SCListenPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwListenPort syscall offset (<syscall_id>)
    syscall
    ret
SCListenPort ENDP

SCLoadDriver PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadDriver syscall offset (<syscall_id>)
    syscall
    ret
SCLoadDriver ENDP

SCLoadEnclaveData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadEnclaveData syscall offset (<syscall_id>)
    syscall
    ret
SCLoadEnclaveData ENDP

SCLoadKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadKey syscall offset (<syscall_id>)
    syscall
    ret
SCLoadKey ENDP

SCLoadKey2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadKey2 syscall offset (<syscall_id>)
    syscall
    ret
SCLoadKey2 ENDP

SCLoadKey3 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadKey3 syscall offset (<syscall_id>)
    syscall
    ret
SCLoadKey3 ENDP

SCLoadKeyEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLoadKeyEx syscall offset (<syscall_id>)
    syscall
    ret
SCLoadKeyEx ENDP

SCLockFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockFile syscall offset (<syscall_id>)
    syscall
    ret
SCLockFile ENDP

SCLockProductActivationKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockProductActivationKeys syscall offset (<syscall_id>)
    syscall
    ret
SCLockProductActivationKeys ENDP

SCLockRegistryKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockRegistryKey syscall offset (<syscall_id>)
    syscall
    ret
SCLockRegistryKey ENDP

SCLockVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCLockVirtualMemory ENDP

SCMakePermanentObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMakePermanentObject syscall offset (<syscall_id>)
    syscall
    ret
SCMakePermanentObject ENDP

SCMakeTemporaryObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMakeTemporaryObject syscall offset (<syscall_id>)
    syscall
    ret
SCMakeTemporaryObject ENDP

SCManageHotPatch PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwManageHotPatch syscall offset (<syscall_id>)
    syscall
    ret
SCManageHotPatch ENDP

SCManagePartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwManagePartition syscall offset (<syscall_id>)
    syscall
    ret
SCManagePartition ENDP

SCMapCMFModule PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMapCMFModule syscall offset (<syscall_id>)
    syscall
    ret
SCMapCMFModule ENDP

SCMapUserPhysicalPages PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMapUserPhysicalPages syscall offset (<syscall_id>)
    syscall
    ret
SCMapUserPhysicalPages ENDP

SCMapUserPhysicalPagesScatter PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwLockProductActivationKeys syscall offset (<syscall_id>)
    syscall
    ret
SCMapUserPhysicalPagesScatter ENDP

SCMapViewOfSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMapViewOfSection syscall offset (<syscall_id>)
    syscall
    ret
SCMapViewOfSection ENDP

SCMapViewOfSectionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwMapViewOfSectionEx syscall offset (<syscall_id>)
    syscall
    ret
SCMapViewOfSectionEx ENDP

SCModifyBootEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwModifyBootEntry syscall offset (<syscall_id>)
    syscall
    ret
SCModifyBootEntry ENDP

SCModifyDriverEntry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwModifyDriverEntry syscall offset (<syscall_id>)
    syscall
    ret
SCModifyDriverEntry ENDP

SCNotifyChangeDirectoryFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeDirectoryFile syscall offset (<syscall_id>)
    syscall
    ret
SCNotifyChangeDirectoryFile ENDP

SCNotifyChangeDirectoryFileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeDirectoryFileEx syscall offset (<syscall_id>)
    syscall
    ret
SCNotifyChangeDirectoryFileEx ENDP

SCNotifyChangeKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeKey syscall offset (<syscall_id>)
    syscall
    ret
SCNotifyChangeKey ENDP

SCNotifyChangeMultipleKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeMultipleKeys syscall offset (<syscall_id>)
    syscall
    ret
SCNotifyChangeMultipleKeys ENDP

SCNotifyChangeSession PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwNotifyChangeSession syscall offset (<syscall_id>)
    syscall
    ret
SCNotifyChangeSession ENDP

SCOpenCpuPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenCpuPartition syscall offset (<syscall_id>)
    syscall
    ret
SCOpenCpuPartition ENDP

SCOpenEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCOpenEnlistment ENDP

SCOpenEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenEvent syscall offset (<syscall_id>)
    syscall
    ret
SCOpenEvent ENDP

SCOpenEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenEventPair syscall offset (<syscall_id>)
    syscall
    ret
SCOpenEventPair ENDP

SCOpenFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenFile syscall offset (<syscall_id>)
    syscall
    ret
SCOpenFile ENDP

SCOpenIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SCOpenIoCompletion ENDP

SCOpenJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenJobObject syscall offset (<syscall_id>)
    syscall
    ret
SCOpenJobObject ENDP

SCOpenKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKey syscall offset (<syscall_id>)
    syscall
    ret
SCOpenKey ENDP

SCOpenKeyEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKeyEx syscall offset (<syscall_id>)
    syscall
    ret
SCOpenKeyEx ENDP

SCOpenKeyTransacted PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKeyTransacted syscall offset (<syscall_id>)
    syscall
    ret
SCOpenKeyTransacted ENDP

SCOpenKeyTransactedEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKeyTransactedEx syscall offset (<syscall_id>)
    syscall
    ret
SCOpenKeyTransactedEx ENDP

SCOpenKeyedEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenKeyedEvent syscall offset (<syscall_id>)
    syscall
    ret
SCOpenKeyedEvent ENDP

SCOpenMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenMutant syscall offset (<syscall_id>)
    syscall
    ret
SCOpenMutant ENDP

SCOpenObjectAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenObjectAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SCOpenObjectAuditAlarm ENDP

SCOpenPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenPartition syscall offset (<syscall_id>)
    syscall
    ret
SCOpenPartition ENDP

SCOpenPrivateNamespace PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenPrivateNamespace syscall offset (<syscall_id>)
    syscall
    ret
SCOpenPrivateNamespace ENDP

SCOpenProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenProcess syscall offset (<syscall_id>)
    syscall
    ret
SCOpenProcess ENDP

SCOpenProcessToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenProcessToken syscall offset (<syscall_id>)
    syscall
    ret
SCOpenProcessToken ENDP

SCOpenProcessTokenEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenProcessTokenEx syscall offset (<syscall_id>)
    syscall
    ret
SCOpenProcessTokenEx ENDP

SCOpenRegistryTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenRegistryTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCOpenRegistryTransaction ENDP

SCOpenResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SCOpenResourceManager ENDP

SCOpenSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenSection syscall offset (<syscall_id>)
    syscall
    ret
SCOpenSection ENDP

SCOpenSemaphore PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenSemaphore syscall offset (<syscall_id>)
    syscall
    ret
SCOpenSemaphore ENDP

SCOpenSession PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenSession syscall offset (<syscall_id>)
    syscall
    ret
SCOpenSession ENDP

SCOpenSymbolicLinkObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenSymbolicLinkObject syscall offset (<syscall_id>)
    syscall
    ret
SCOpenSymbolicLinkObject ENDP

SCOpenThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenThread syscall offset (<syscall_id>)
    syscall
    ret
SCOpenThread ENDP

SCOpenThreadToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenThreadToken syscall offset (<syscall_id>)
    syscall
    ret
SCOpenThreadToken ENDP

SCOpenThreadTokenEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenThreadTokenEx syscall offset (<syscall_id>)
    syscall
    ret
SCOpenThreadTokenEx ENDP

SCOpenTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenTimer syscall offset (<syscall_id>)
    syscall
    ret
SCOpenTimer ENDP

SCOpenTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCOpenTransaction ENDP

SCOpenTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwOpenTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SCOpenTransactionManager ENDP

SCPlugPlayControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPlugPlayControl syscall offset (<syscall_id>)
    syscall
    ret
SCPlugPlayControl ENDP

SCPowerInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPowerInformation syscall offset (<syscall_id>)
    syscall
    ret
SCPowerInformation ENDP

SCPrePrepareComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrePrepareComplete syscall offset (<syscall_id>)
    syscall
    ret
SCPrePrepareComplete ENDP

SCPrePrepareEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrePrepareEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCPrePrepareEnlistment ENDP

SCPrepareComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrepareComplete syscall offset (<syscall_id>)
    syscall
    ret
SCPrepareComplete ENDP

SCPrepareEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrepareEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCPrepareEnlistment ENDP

SCPrivilegeCheck PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrivilegeCheck syscall offset (<syscall_id>)
    syscall
    ret
SCPrivilegeCheck ENDP

SCPrivilegeObjectAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrivilegeObjectAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SCPrivilegeObjectAuditAlarm ENDP

SCPrivilegedServiceAuditAlarm PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPrivilegedServiceAuditAlarm syscall offset (<syscall_id>)
    syscall
    ret
SCPrivilegedServiceAuditAlarm ENDP

SCPropagationComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPropagationComplete syscall offset (<syscall_id>)
    syscall
    ret
SCPropagationComplete ENDP

SCPropagationFailed PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPropagationFailed syscall offset (<syscall_id>)
    syscall
    ret
SCPropagationFailed ENDP

SCProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwProtectVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCProtectVirtualMemory ENDP

SCPssCaptureVaSpaceBulk PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPssCaptureVaSpaceBulk syscall offset (<syscall_id>)
    syscall
    ret
SCPssCaptureVaSpaceBulk ENDP

SCPulseEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwPulseEvent syscall offset (<syscall_id>)
    syscall
    ret
SCPulseEvent ENDP

SCQueryAttributesFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryAttributesFile syscall offset (<syscall_id>)
    syscall
    ret
SCQueryAttributesFile ENDP

SCQueryAuxiliaryCounterFrequency PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryAuxiliaryCounterFrequency syscall offset (<syscall_id>)
    syscall
    ret
SCQueryAuxiliaryCounterFrequency ENDP

SCQueryBootEntryOrder PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryBootEntryOrder syscall offset (<syscall_id>)
    syscall
    ret
SCQueryBootEntryOrder ENDP

SCQueryBootOptions PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryBootOptions syscall offset (<syscall_id>)
    syscall
    ret
SCQueryBootOptions ENDP

SCQueryDebugFilterState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDebugFilterState syscall offset (<syscall_id>)
    syscall
    ret
SCQueryDebugFilterState ENDP

SCQueryDefaultLocale PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDefaultLocale syscall offset (<syscall_id>)
    syscall
    ret
SCQueryDefaultLocale ENDP

SCQueryDefaultUILanguage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDefaultUILanguage syscall offset (<syscall_id>)
    syscall
    ret
SCQueryDefaultUILanguage ENDP

SCQueryDirectoryFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDirectoryFile syscall offset (<syscall_id>)
    syscall
    ret
SCQueryDirectoryFile ENDP

SCQueryDirectoryFileEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDirectoryFileEx syscall offset (<syscall_id>)
    syscall
    ret
SCQueryDirectoryFileEx ENDP

SCQueryDirectoryObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDirectoryObject syscall offset (<syscall_id>)
    syscall
    ret
SCQueryDirectoryObject ENDP

SCQueryDriverEntryOrder PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryDriverEntryOrder syscall offset (<syscall_id>)
    syscall
    ret
SCQueryDriverEntryOrder ENDP

SCQueryEaFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryEaFile syscall offset (<syscall_id>)
    syscall
    ret
SCQueryEaFile ENDP

SCQueryEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryEvent syscall offset (<syscall_id>)
    syscall
    ret
SCQueryEvent ENDP

SCQueryFullAttributesFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryFullAttributesFile syscall offset (<syscall_id>)
    syscall
    ret
SCQueryFullAttributesFile ENDP

SCQueryInformationAtom PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationAtom syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationAtom ENDP

SCQueryInformationByName PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationByName syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationByName ENDP

SCQueryInformationCpuPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationCpuPartition syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationCpuPartition ENDP

SCQueryInformationEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationEnlistment ENDP

SCQueryInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationFile ENDP

SCQueryInformationJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationJobObject syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationJobObject ENDP

SCQueryInformationPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationPort syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationPort ENDP

SCQueryInformationProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationProcess syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationProcess ENDP

SCQueryInformationResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationResourceManager ENDP

SCQueryInformationThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationThread syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationThread ENDP

SCQueryInformationToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationToken syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationToken ENDP

SCQueryInformationTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationTransaction ENDP

SCQueryInformationTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationTransactionManager ENDP

SCQueryInformationWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInformationWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInformationWorkerFactory ENDP

SCQueryInstallUILanguage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryInstallUILanguage syscall offset (<syscall_id>)
    syscall
    ret
SCQueryInstallUILanguage ENDP

SCQueryIntervalProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryIntervalProfile syscall offset (<syscall_id>)
    syscall
    ret
SCQueryIntervalProfile ENDP

SCQueryIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SCQueryIoCompletion ENDP

SCQueryIoRingCapabilities PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryIoRingCapabilities syscall offset (<syscall_id>)
    syscall
    ret
SCQueryIoRingCapabilities ENDP

SCQueryKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryKey syscall offset (<syscall_id>)
    syscall
    ret
SCQueryKey ENDP

SCQueryLicenseValue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryLicenseValue syscall offset (<syscall_id>)
    syscall
    ret
SCQueryLicenseValue ENDP

SCQueryMultipleValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryMultipleValueKey syscall offset (<syscall_id>)
    syscall
    ret
SCQueryMultipleValueKey ENDP

SCQueryMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryMutant syscall offset (<syscall_id>)
    syscall
    ret
SCQueryMutant ENDP

SCQueryObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryObject syscall offset (<syscall_id>)
    syscall
    ret
SCQueryObject ENDP

SCQueryOpenSubKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryOpenSubKeys syscall offset (<syscall_id>)
    syscall
    ret
SCQueryOpenSubKeys ENDP

SCQueryOpenSubKeysEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryOpenSubKeysEx syscall offset (<syscall_id>)
    syscall
    ret
SCQueryOpenSubKeysEx ENDP

SCQueryPerformanceCounter PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryPerformanceCounter syscall offset (<syscall_id>)
    syscall
    ret
SCQueryPerformanceCounter ENDP

SCQueryPortInformationProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryPortInformationProcess syscall offset (<syscall_id>)
    syscall
    ret
SCQueryPortInformationProcess ENDP

SCQueryQuotaInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryQuotaInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SCQueryQuotaInformationFile ENDP

SCQuerySection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySection syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySection ENDP

SCQuerySecurityAttributesToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySecurityAttributesToken syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySecurityAttributesToken ENDP

SCQuerySecurityObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySecurityObject syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySecurityObject ENDP

SCQuerySecurityPolicy PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySecurityPolicy syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySecurityPolicy ENDP

SCQuerySemaphore PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySemaphore syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySemaphore ENDP

SCQuerySymbolicLinkObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySymbolicLinkObject syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySymbolicLinkObject ENDP

SCQuerySystemEnvironmentValue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySystemEnvironmentValue syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySystemEnvironmentValue ENDP

SCQuerySystemEnvironmentValueEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySystemEnvironmentValueEx syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySystemEnvironmentValueEx ENDP

SCQuerySystemInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySystemInformation syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySystemInformation ENDP

SCQuerySystemInformationEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQuerySystemInformationEx syscall offset (<syscall_id>)
    syscall
    ret
SCQuerySystemInformationEx ENDP

SCQueryTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryTimer syscall offset (<syscall_id>)
    syscall
    ret
SCQueryTimer ENDP

SCQueryTimerResolution PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryTimerResolution syscall offset (<syscall_id>)
    syscall
    ret
SCQueryTimerResolution ENDP

SCQueryValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryValueKey syscall offset (<syscall_id>)
    syscall
    ret
SCQueryValueKey ENDP

SCQueryVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCQueryVirtualMemory ENDP

SCQueryVolumeInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryVolumeInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SCQueryVolumeInformationFile ENDP

SCQueryWnfStateData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryWnfStateData syscall offset (<syscall_id>)
    syscall
    ret
SCQueryWnfStateData ENDP

SCQueryWnfStateNameInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueryWnfStateNameInformation syscall offset (<syscall_id>)
    syscall
    ret
SCQueryWnfStateNameInformation ENDP

SCQueueApcThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueueApcThread syscall offset (<syscall_id>)
    syscall
    ret
SCQueueApcThread ENDP

SCQueueApcThreadEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueueApcThreadEx syscall offset (<syscall_id>)
    syscall
    ret
SCQueueApcThreadEx ENDP

SCQueueApcThreadEx2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwQueueApcThreadEx2 syscall offset (<syscall_id>)
    syscall
    ret
SCQueueApcThreadEx2 ENDP

SCRaiseException PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRaiseException syscall offset (<syscall_id>)
    syscall
    ret
SCRaiseException ENDP

SCRaiseHardError PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRaiseHardError syscall offset (<syscall_id>)
    syscall
    ret
SCRaiseHardError ENDP

SCReadFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadFile syscall offset (<syscall_id>)
    syscall
    ret
SCReadFile ENDP

SCReadFileScatter PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadFileScatter syscall offset (<syscall_id>)
    syscall
    ret
SCReadFileScatter ENDP

SCReadOnlyEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadOnlyEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCReadOnlyEnlistment ENDP

SCReadRequestData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadRequestData syscall offset (<syscall_id>)
    syscall
    ret
SCReadRequestData ENDP

SCReadVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCReadVirtualMemory ENDP

SCReadVirtualMemoryEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReadVirtualMemoryEx syscall offset (<syscall_id>)
    syscall
    ret
SCReadVirtualMemoryEx ENDP

SCRecoverEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRecoverEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCRecoverEnlistment ENDP

SCRecoverResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRecoverResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SCRecoverResourceManager ENDP

SCRecoverTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRecoverTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SCRecoverTransactionManager ENDP

SCRegisterProtocolAddressInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRegisterProtocolAddressInformation syscall offset (<syscall_id>)
    syscall
    ret
SCRegisterProtocolAddressInformation ENDP

SCRegisterThreadTerminatePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRegisterThreadTerminatePort syscall offset (<syscall_id>)
    syscall
    ret
SCRegisterThreadTerminatePort ENDP

SCReleaseKeyedEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReleaseKeyedEvent syscall offset (<syscall_id>)
    syscall
    ret
SCReleaseKeyedEvent ENDP

SCReleaseMutant PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReleaseMutant syscall offset (<syscall_id>)
    syscall
    ret
SCReleaseMutant ENDP

SCReleaseSemaphore PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReleaseSemaphore syscall offset (<syscall_id>)
    syscall
    ret
SCReleaseSemaphore ENDP

SCReleaseWorkerFactoryWorker PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReleaseWorkerFactoryWorker syscall offset (<syscall_id>)
    syscall
    ret
SCReleaseWorkerFactoryWorker ENDP

SCRemoveIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRemoveIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SCRemoveIoCompletion ENDP

SCRemoveIoCompletionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRemoveIoCompletionEx syscall offset (<syscall_id>)
    syscall
    ret
SCRemoveIoCompletionEx ENDP

SCRemoveProcessDebug PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRemoveProcessDebug syscall offset (<syscall_id>)
    syscall
    ret
SCRemoveProcessDebug ENDP

SCRenameKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRenameKey syscall offset (<syscall_id>)
    syscall
    ret
SCRenameKey ENDP

SCRenameTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRenameTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SCRenameTransactionManager ENDP

SCReplaceKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplaceKey syscall offset (<syscall_id>)
    syscall
    ret
SCReplaceKey ENDP

SCReplacePartitionUnit PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplacePartitionUnit syscall offset (<syscall_id>)
    syscall
    ret
SCReplacePartitionUnit ENDP

SCReplyPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplyPort syscall offset (<syscall_id>)
    syscall
    ret
SCReplyPort ENDP

SCReplyWaitReceivePort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplyWaitReceivePort syscall offset (<syscall_id>)
    syscall
    ret
SCReplyWaitReceivePort ENDP

SCReplyWaitReceivePortEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplyWaitReceivePortEx syscall offset (<syscall_id>)
    syscall
    ret
SCReplyWaitReceivePortEx ENDP

SCReplyWaitReplyPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwReplyWaitReplyPort syscall offset (<syscall_id>)
    syscall
    ret
SCReplyWaitReplyPort ENDP

SCRequestPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRequestPort syscall offset (<syscall_id>)
    syscall
    ret
SCRequestPort ENDP

SCRequestWaitReplyPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRequestWaitReplyPort syscall offset (<syscall_id>)
    syscall
    ret
SCRequestWaitReplyPort ENDP

SCResetEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwResetEvent syscall offset (<syscall_id>)
    syscall
    ret
SCResetEvent ENDP

SCResetWriteWatch PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwResetWriteWatch syscall offset (<syscall_id>)
    syscall
    ret
SCResetWriteWatch ENDP

SCRestoreKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRestoreKey syscall offset (<syscall_id>)
    syscall
    ret
SCRestoreKey ENDP

SCResumeProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwResumeProcess syscall offset (<syscall_id>)
    syscall
    ret
SCResumeProcess ENDP

SCResumeThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwResumeThread syscall offset (<syscall_id>)
    syscall
    ret
SCResumeThread ENDP

SCRevertContainerImpersonation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRevertContainerImpersonation syscall offset (<syscall_id>)
    syscall
    ret
SCRevertContainerImpersonation ENDP

SCRollbackComplete PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollbackComplete syscall offset (<syscall_id>)
    syscall
    ret
SCRollbackComplete ENDP

SCRollbackEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollbackEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCRollbackEnlistment ENDP

SCRollbackRegistryTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollbackRegistryTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCRollbackRegistryTransaction ENDP

SCRollbackTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollbackTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCRollbackTransaction ENDP

SCRollforwardTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwRollforwardTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SCRollforwardTransactionManager ENDP

SCSaveKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSaveKey syscall offset (<syscall_id>)
    syscall
    ret
SCSaveKey ENDP

SCSaveKeyEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSaveKeyEx syscall offset (<syscall_id>)
    syscall
    ret
SCSaveKeyEx ENDP

SCSaveMergedKeys PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSaveMergedKeys syscall offset (<syscall_id>)
    syscall
    ret
SCSaveMergedKeys ENDP

SCSecureConnectPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSecureConnectPort syscall offset (<syscall_id>)
    syscall
    ret
SCSecureConnectPort ENDP

SCSerializeBoot PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSerializeBoot syscall offset (<syscall_id>)
    syscall
    ret
SCSerializeBoot ENDP

SCSetBootEntryOrder PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetBootEntryOrder syscall offset (<syscall_id>)
    syscall
    ret
SCSetBootEntryOrder ENDP

SCSetBootOptions PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetBootOptions syscall offset (<syscall_id>)
    syscall
    ret
SCSetBootOptions ENDP

SCSetCachedSigningLevel PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetCachedSigningLevel syscall offset (<syscall_id>)
    syscall
    ret
SCSetCachedSigningLevel ENDP

SCSetCachedSigningLevel2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetCachedSigningLevel2 syscall offset (<syscall_id>)
    syscall
    ret
SCSetCachedSigningLevel2 ENDP

SCSetContextThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetContextThread syscall offset (<syscall_id>)
    syscall
    ret
SCSetContextThread ENDP

SCSetDebugFilterState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDebugFilterState syscall offset (<syscall_id>)
    syscall
    ret
SCSetDebugFilterState ENDP

SCSetDefaultHardErrorPort PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDefaultHardErrorPort syscall offset (<syscall_id>)
    syscall
    ret
SCSetDefaultHardErrorPort ENDP

SCSetDefaultLocale PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDefaultLocale syscall offset (<syscall_id>)
    syscall
    ret
SCSetDefaultLocale ENDP

SCSetDefaultUILanguage PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDefaultUILanguage syscall offset (<syscall_id>)
    syscall
    ret
SCSetDefaultUILanguage ENDP

SCSetDriverEntryOrder PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetDriverEntryOrder syscall offset (<syscall_id>)
    syscall
    ret
SCSetDriverEntryOrder ENDP

SCSetEaFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetEaFile syscall offset (<syscall_id>)
    syscall
    ret
SCSetEaFile ENDP

SCSetEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetEvent syscall offset (<syscall_id>)
    syscall
    ret
SCSetEvent ENDP

SCSetEventBoostPriority PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetEventBoostPriority syscall offset (<syscall_id>)
    syscall
    ret
SCSetEventBoostPriority ENDP

SCSetHighEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetHighEventPair syscall offset (<syscall_id>)
    syscall
    ret
SCSetHighEventPair ENDP

SCSetHighWaitLowEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetHighWaitLowEventPair syscall offset (<syscall_id>)
    syscall
    ret
SCSetHighWaitLowEventPair ENDP

SCSetIRTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetIRTimer syscall offset (<syscall_id>)
    syscall
    ret
SCSetIRTimer ENDP

SCSetInformationCpuPartition PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationCpuPartition syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationCpuPartition ENDP

SCSetInformationDebugObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationDebugObject syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationDebugObject ENDP

SCSetInformationEnlistment PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationEnlistment syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationEnlistment ENDP

SCSetInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationFile ENDP

SCSetInformationIoRing PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationIoRing syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationIoRing ENDP

SCSetInformationJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationJobObject syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationJobObject ENDP

SCSetInformationKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationKey syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationKey ENDP

SCSetInformationObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationObject syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationObject ENDP

SCSetInformationProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationProcess syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationProcess ENDP

SCSetInformationResourceManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationResourceManager syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationResourceManager ENDP

SCSetInformationSymbolicLink PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationSymbolicLink syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationSymbolicLink ENDP

SCSetInformationThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationThread syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationThread ENDP

SCSetInformationToken PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationToken syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationToken ENDP

SCSetInformationTransaction PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationTransaction syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationTransaction ENDP

SCSetInformationTransactionManager PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationTransactionManager syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationTransactionManager ENDP

SCSetInformationVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationVirtualMemory ENDP

SCSetInformationWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetInformationWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SCSetInformationWorkerFactory ENDP

SCSetIntervalProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetIntervalProfile syscall offset (<syscall_id>)
    syscall
    ret
SCSetIntervalProfile ENDP

SCSetIoCompletion PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetIoCompletion syscall offset (<syscall_id>)
    syscall
    ret
SCSetIoCompletion ENDP

SCSetIoCompletionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetIoCompletionEx syscall offset (<syscall_id>)
    syscall
    ret
SCSetIoCompletionEx ENDP

SCSetLdtEntries PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetLdtEntries syscall offset (<syscall_id>)
    syscall
    ret
SCSetLdtEntries ENDP

SCSetLowEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetLowEventPair syscall offset (<syscall_id>)
    syscall
    ret
SCSetLowEventPair ENDP

SCSetLowWaitHighEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetLowWaitHighEventPair syscall offset (<syscall_id>)
    syscall
    ret
SCSetLowWaitHighEventPair ENDP

SCSetQuotaInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetQuotaInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SCSetQuotaInformationFile ENDP

SCSetSecurityObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSecurityObject syscall offset (<syscall_id>)
    syscall
    ret
SCSetSecurityObject ENDP

SCSetSystemEnvironmentValue PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemEnvironmentValue syscall offset (<syscall_id>)
    syscall
    ret
SCSetSystemEnvironmentValue ENDP

SCSetSystemEnvironmentValueEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemEnvironmentValueEx syscall offset (<syscall_id>)
    syscall
    ret
SCSetSystemEnvironmentValueEx ENDP

SCSetSystemInformation PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemInformation syscall offset (<syscall_id>)
    syscall
    ret
SCSetSystemInformation ENDP

SCSetSystemPowerState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemPowerState syscall offset (<syscall_id>)
    syscall
    ret
SCSetSystemPowerState ENDP

SCSetSystemTime PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetSystemTime syscall offset (<syscall_id>)
    syscall
    ret
SCSetSystemTime ENDP

SCSetThreadExecutionState PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetThreadExecutionState syscall offset (<syscall_id>)
    syscall
    ret
SCSetThreadExecutionState ENDP

SCSetTimer PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetTimer syscall offset (<syscall_id>)
    syscall
    ret
SCSetTimer ENDP

SCSetTimer2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetTimer2 syscall offset (<syscall_id>)
    syscall
    ret
SCSetTimer2 ENDP

SCSetTimerEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetTimerEx syscall offset (<syscall_id>)
    syscall
    ret
SCSetTimerEx ENDP

SCSetTimerResolution PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetTimerResolution syscall offset (<syscall_id>)
    syscall
    ret
SCSetTimerResolution ENDP

SCSetUuidSeed PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetUuidSeed syscall offset (<syscall_id>)
    syscall
    ret
SCSetUuidSeed ENDP

SCSetValueKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetValueKey syscall offset (<syscall_id>)
    syscall
    ret
SCSetValueKey ENDP

SCSetVolumeInformationFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetVolumeInformationFile syscall offset (<syscall_id>)
    syscall
    ret
SCSetVolumeInformationFile ENDP

SCSetWnfProcessNotificationEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSetWnfProcessNotificationEvent syscall offset (<syscall_id>)
    syscall
    ret
SCSetWnfProcessNotificationEvent ENDP

SCShutdownSystem PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwShutdownSystem syscall offset (<syscall_id>)
    syscall
    ret
SCShutdownSystem ENDP

SCShutdownWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwShutdownWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SCShutdownWorkerFactory ENDP

SCSignalAndWaitForSingleObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSignalAndWaitForSingleObject syscall offset (<syscall_id>)
    syscall
    ret
SCSignalAndWaitForSingleObject ENDP

SCSinglePhaseReject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSinglePhaseReject syscall offset (<syscall_id>)
    syscall
    ret
SCSinglePhaseReject ENDP

SCStartProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwStartProfile syscall offset (<syscall_id>)
    syscall
    ret
SCStartProfile ENDP

SCStopProfile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwStopProfile syscall offset (<syscall_id>)
    syscall
    ret
SCStopProfile ENDP

SCSubmitIoRing PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSubmitIoRing syscall offset (<syscall_id>)
    syscall
    ret
SCSubmitIoRing ENDP

SCSubscribeWnfStateChange PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSubscribeWnfStateChange syscall offset (<syscall_id>)
    syscall
    ret
SCSubscribeWnfStateChange ENDP

SCSuspendProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSuspendProcess syscall offset (<syscall_id>)
    syscall
    ret
SCSuspendProcess ENDP

SCSuspendThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSuspendThread syscall offset (<syscall_id>)
    syscall
    ret
SCSuspendThread ENDP

SCSystemDebugControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwSystemDebugControl syscall offset (<syscall_id>)
    syscall
    ret
SCSystemDebugControl ENDP

SCTerminateEnclave PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTerminateEnclave syscall offset (<syscall_id>)
    syscall
    ret
SCTerminateEnclave ENDP

SCTerminateJobObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTerminateJobObject syscall offset (<syscall_id>)
    syscall
    ret
SCTerminateJobObject ENDP

SCTerminateProcess PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTerminateProcess syscall offset (<syscall_id>)
    syscall
    ret
SCTerminateProcess ENDP

SCTerminateThread PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTerminateThread syscall offset (<syscall_id>)
    syscall
    ret
SCTerminateThread ENDP

SCTestAlert PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTestAlert syscall offset (<syscall_id>)
    syscall
    ret
SCTestAlert ENDP

SCThawRegistry PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwThawRegistry syscall offset (<syscall_id>)
    syscall
    ret
SCThawRegistry ENDP

SCThawTransactions PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwThawTransactions syscall offset (<syscall_id>)
    syscall
    ret
SCThawTransactions ENDP

SCTraceControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTraceControl syscall offset (<syscall_id>)
    syscall
    ret
SCTraceControl ENDP

SCTraceEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTraceEvent syscall offset (<syscall_id>)
    syscall
    ret
SCTraceEvent ENDP

SCTranslateFilePath PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwTranslateFilePath syscall offset (<syscall_id>)
    syscall
    ret
SCTranslateFilePath ENDP

SCUmsThreadYield PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUmsThreadYield syscall offset (<syscall_id>)
    syscall
    ret
SCUmsThreadYield ENDP

SCUnloadDriver PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnloadDriver syscall offset (<syscall_id>)
    syscall
    ret
SCUnloadDriver ENDP

SCUnloadKey PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnloadKey syscall offset (<syscall_id>)
    syscall
    ret
SCUnloadKey ENDP

SCUnloadKey2 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnloadKey2 syscall offset (<syscall_id>)
    syscall
    ret
SCUnloadKey2 ENDP

SCUnloadKeyEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnloadKeyEx syscall offset (<syscall_id>)
    syscall
    ret
SCUnloadKeyEx ENDP

SCUnlockFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnlockFile syscall offset (<syscall_id>)
    syscall
    ret
SCUnlockFile ENDP

SCUnlockVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnlockVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCUnlockVirtualMemory ENDP

SCUnmapViewOfSection PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnmapViewOfSection syscall offset (<syscall_id>)
    syscall
    ret
SCUnmapViewOfSection ENDP

SCUnmapViewOfSectionEx PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnmapViewOfSectionEx syscall offset (<syscall_id>)
    syscall
    ret
SCUnmapViewOfSectionEx ENDP

SCUnsubscribeWnfStateChange PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUnsubscribeWnfStateChange syscall offset (<syscall_id>)
    syscall
    ret
SCUnsubscribeWnfStateChange ENDP

SCUpdateWnfStateData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwUpdateWnfStateData syscall offset (<syscall_id>)
    syscall
    ret
SCUpdateWnfStateData ENDP

SCVdmControl PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwVdmControl syscall offset (<syscall_id>)
    syscall
    ret
SCVdmControl ENDP

SCWaitForAlertByThreadId PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForAlertByThreadId syscall offset (<syscall_id>)
    syscall
    ret
SCWaitForAlertByThreadId ENDP

SCWaitForDebugEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForDebugEvent syscall offset (<syscall_id>)
    syscall
    ret
SCWaitForDebugEvent ENDP

SCWaitForKeyedEvent PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForKeyedEvent syscall offset (<syscall_id>)
    syscall
    ret
SCWaitForKeyedEvent ENDP

SCWaitForMultipleObjects PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForMultipleObjects syscall offset (<syscall_id>)
    syscall
    ret
SCWaitForMultipleObjects ENDP

SCWaitForMultipleObjects32 PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForMultipleObjects32 syscall offset (<syscall_id>)
    syscall
    ret
SCWaitForMultipleObjects32 ENDP

SCWaitForSingleObject PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForSingleObject syscall offset (<syscall_id>)
    syscall
    ret
SCWaitForSingleObject ENDP

SCWaitForWorkViaWorkerFactory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitForWorkViaWorkerFactory syscall offset (<syscall_id>)
    syscall
    ret
SCWaitForWorkViaWorkerFactory ENDP

SCWaitHighEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitHighEventPair syscall offset (<syscall_id>)
    syscall
    ret
SCWaitHighEventPair ENDP

SCWaitLowEventPair PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWaitLowEventPair syscall offset (<syscall_id>)
    syscall
    ret
SCWaitLowEventPair ENDP

SCWorkerFactoryWorkerReady PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWorkerFactoryWorkerReady syscall offset (<syscall_id>)
    syscall
    ret
SCWorkerFactoryWorkerReady ENDP

SCWriteFile PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWriteFile syscall offset (<syscall_id>)
    syscall
    ret
SCWriteFile ENDP

SCWriteFileGather PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWriteFileGather syscall offset (<syscall_id>)
    syscall
    ret
SCWriteFileGather ENDP

SCWriteRequestData PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWriteRequestData syscall offset (<syscall_id>)
    syscall
    ret
SCWriteRequestData ENDP

SCWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwWriteVirtualMemory syscall offset (<syscall_id>)
    syscall
    ret
SCWriteVirtualMemory ENDP

SCYieldExecution PROC
    mov r10, rcx
    mov eax, <syscall_id>h    ; Nt/ZwYieldExecution syscall offset (<syscall_id>)
    syscall
    ret
SCYieldExecution ENDP

end 
