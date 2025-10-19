using Printf

const KERNEL32 = "kernel32"
const SYSCALLER = "SysCaller"

const MEM_COMMIT = 0x1000
const MEM_RESERVE = 0x2000
const PAGE_EXECUTE_READWRITE = 0x40
const THREAD_ALL_ACCESS = 0x1FFFFF
const PROCESS_ALL_ACCESS = 0x1F0FFF

nt_success(status::Int32) = status >= 0

function get_full_path(path::AbstractString)
    buf = Vector{UInt8}(undef, 260)
    n = ccall((:GetFullPathNameA, KERNEL32), UInt32,
              (Cstring, UInt32, Ptr{UInt8}, Ptr{Ptr{UInt8}}),
              path, UInt32(length(buf)), buf, C_NULL)
    if n > 0 && n < length(buf)
        return unsafe_string(pointer(buf), n)
    else
        return path
    end
end

function open_process(pid::UInt32)
    h = ccall((:OpenProcess, KERNEL32), Ptr{Cvoid},
              (UInt32, Cint, UInt32), PROCESS_ALL_ACCESS, 0, pid)
    return h
end

function close_handle(h::Ptr{Cvoid})
    ccall((:CloseHandle, KERNEL32), Cint, (Ptr{Cvoid},), h)
end

function get_loadlibraryA()
    k32 = ccall((:GetModuleHandleA, KERNEL32), Ptr{Cvoid}, (Cstring,), "kernel32.dll")
    k32 == C_NULL && error("Failed to get kernel32.dll handle")
    p = ccall((:GetProcAddress, KERNEL32), Ptr{Cvoid}, (Ptr{Cvoid}, Cstring), k32, "LoadLibraryA")
    p == C_NULL && error("Failed to get LoadLibraryA address")
    return p
end

function injectdll(hproc::Ptr{Cvoid}, dllpath::AbstractString)
    abs = get_full_path(dllpath)
    path_bytes = Vector{UInt8}(codeunits(abs))
    push!(path_bytes, 0x00)

    base_ref = Ref{Ptr{Cvoid}}(C_NULL)
    region = Ref{Csize_t}(Csize_t(length(path_bytes)))
    status = ccall((:SysAllocateVirtualMemoryEx, SYSCALLER), Int32,
                   (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Csize_t}, UInt32, UInt32, Ptr{Cvoid}, UInt32),
                   hproc, base_ref, region, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE, C_NULL, 0)
    if !nt_success(status)
        @printf("[!] Failed to allocate memory for DLL path. Status: 0x%08X\n", UInt32(status))
        return false
    end
    base = base_ref[]
    @printf("[+] Allocated DLL path memory at: %p\n", base)

    written = Ref{Csize_t}(0)
    GC.@preserve path_bytes begin
        status = ccall((:SysWriteVirtualMemory, SYSCALLER), Int32,
                       (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Csize_t, Ptr{Csize_t}),
                       hproc, base, pointer(path_bytes), Csize_t(length(path_bytes)), written)
    end
    if !nt_success(status) || written[] != Csize_t(length(path_bytes))
        @printf("[!] Failed to write DLL path. Status: 0x%08X, Bytes written: %d\n", UInt32(status), UInt64(written[]))
        return false
    end
    println("[+] Successfully wrote DLL path to memory")

    loadlib = get_loadlibraryA()
    @printf("[+] LoadLibraryA address: %p\n", loadlib)

    sc = UInt8[]
    append!(sc, [0x48, 0x83, 0xEC, 0x28])                
    append!(sc, [0x48, 0xB9])                             
    addr_path = UInt64(UInt(base))
    for b in 0:7 push!(sc, UInt8((addr_path >> (8*b)) & 0xFF)) end
    append!(sc, [0x48, 0xB8])                             
    addr_ll = UInt64(UInt(loadlib))
    for b in 0:7 push!(sc, UInt8((addr_ll >> (8*b)) & 0xFF)) end
    append!(sc, [0xFF, 0xD0])                             
    append!(sc, [0x48, 0x83, 0xC4, 0x28])                 
    push!(sc, 0xC3)                                        

    sc_base_ref = Ref{Ptr{Cvoid}}(C_NULL)
    region = Ref{Csize_t}(Csize_t(length(sc)))
    status = ccall((:SysAllocateVirtualMemoryEx, SYSCALLER), Int32,
                   (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Csize_t}, UInt32, UInt32, Ptr{Cvoid}, UInt32),
                   hproc, sc_base_ref, region, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE, C_NULL, 0)
    if !nt_success(status)
        @printf("[!] Failed to allocate shellcode. Status: 0x%08X\n", UInt32(status))
        return false
    end
    sc_base = sc_base_ref[]
    @printf("[+] Allocated shellcode memory at: %p\n", sc_base)

    written[] = 0
    GC.@preserve sc begin
        status = ccall((:SysWriteVirtualMemory, SYSCALLER), Int32,
                       (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Csize_t, Ptr{Csize_t}),
                       hproc, sc_base, pointer(sc), Csize_t(length(sc)), written)
    end
    if !nt_success(status) || written[] != Csize_t(length(sc))
        @printf("[!] Failed to write shellcode. Status: 0x%08X, Bytes written: %d\n", UInt32(status), UInt64(written[]))
        return false
    end
    println("[+] Successfully wrote shellcode")

    thread_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = ccall((:SysCreateThreadEx, SYSCALLER), Int32,
                   (Ptr{Ptr{Cvoid}}, UInt32, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, UInt32,
                    Csize_t, Csize_t, Csize_t, Ptr{Cvoid}),
                   thread_ref, THREAD_ALL_ACCESS, C_NULL, hproc, sc_base, C_NULL, 0,
                   Csize_t(0), Csize_t(0), Csize_t(0), C_NULL)
    thr = thread_ref[]
    if !nt_success(status) || thr == C_NULL
        @printf("[!] Failed to create remote thread. Status: 0x%08X, Handle: %p\n", UInt32(status), thr)
        return false
    end
    @printf("[+] Created remote thread: %p\n", thr)

    ccall((:WaitForSingleObject, KERNEL32), UInt32, (Ptr{Cvoid}, UInt32), thr, 5000)
    ccall((:SysClose, SYSCALLER), Int32, (Ptr{Cvoid},), thr)

    println("[+] Successfully injected $(dllpath)!")
    return true
end

function main()
    if length(ARGS) != 2
        println("Usage: julia InjectDLL.jl <pid> <dll_path>")
        return
    end
    pid = parse(UInt32, ARGS[1])
    dll = ARGS[2]
    hproc = open_process(pid)
    if hproc == C_NULL
        println("[!] Failed to open process ", pid)
        return
    end
    try
        injectdll(hproc, dll)
    finally
        close_handle(hproc)
    end
end

main()