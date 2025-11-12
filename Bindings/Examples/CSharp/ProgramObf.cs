using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SysCallerCSharp
{
    internal static class NativeMethods
    {
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        public const uint THREAD_ALL_ACCESS = 0x1FFFFF;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibraryA(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }

    internal static class SysCaller
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int oznbvo_655212Delegate(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref UIntPtr regionSize,
            uint allocationType,
            uint protect,
            IntPtr extendedParams,
            uint paramCount
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int yexedj_555900Delegate(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            UIntPtr bufferSize,
            ref UIntPtr bytesWritten
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int jljtug_682236Delegate(
            ref IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startRoutine,
            IntPtr argument,
            uint createFlags,
            UIntPtr zeroBits,
            UIntPtr stackSize,
            UIntPtr maxStackSize,
            IntPtr attributeList
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ezhgwv_592746Delegate(IntPtr handle);
    }

    internal class Program
    {
        static bool NT_SUCCESS(int status) => status >= 0;

        static bool InjectDLL(
            IntPtr hProcess,
            string dllPath,
            SysCaller.oznbvo_655212Delegate oznbvo_655212,
            SysCaller.yexedj_555900Delegate yexedj_555900,
            SysCaller.jljtug_682236Delegate jljtug_682236,
            SysCaller.ezhgwv_592746Delegate ezhgwv_592746)
        {
            // Get absolute path
            string absPath = Path.GetFullPath(dllPath);
            byte[] absPathBytes = Encoding.ASCII.GetBytes(absPath + "\0");
            UIntPtr pathLen = (UIntPtr)absPathBytes.Length;
            // Allocate memory for DLL path
            IntPtr baseAddress = IntPtr.Zero;
            UIntPtr regionSize = pathLen;
            int status = oznbvo_655212(
                hProcess,
                ref baseAddress,
                ref regionSize,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                NativeMethods.PAGE_EXECUTE_READWRITE,
                IntPtr.Zero,
                0
            );
            if (!NT_SUCCESS(status))
            {
                Console.WriteLine($"[!] Failed to allocate memory for DLL path. Status: 0x{status:X8}");
                return false;
            }
            Console.WriteLine($"[+] Allocated DLL path memory at: 0x{baseAddress.ToInt64():X16}");
            // Write DLL path
            UIntPtr bytesWritten = UIntPtr.Zero;
            GCHandle handle = GCHandle.Alloc(absPathBytes, GCHandleType.Pinned);
            try
            {
                status = yexedj_555900(
                    hProcess,
                    baseAddress,
                    handle.AddrOfPinnedObject(),
                    pathLen,
                    ref bytesWritten
                );
            }
            finally
            {
                handle.Free();
            }
            if (!NT_SUCCESS(status) || bytesWritten != pathLen)
            {
                Console.WriteLine($"[!] Failed to write DLL path. Status: 0x{status:X8}, Bytes written: {bytesWritten}");
                return false;
            }
            Console.WriteLine("[+] Successfully wrote DLL path to memory");
            // Get LoadLibraryA address
            IntPtr hKernel32 = NativeMethods.LoadLibraryA("kernel32.dll");
            if (hKernel32 == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to get kernel32.dll handle");
                return false;
            }
            IntPtr loadLibraryA = NativeMethods.GetProcAddress(hKernel32, "LoadLibraryA");
            if (loadLibraryA == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to get LoadLibraryA address");
                return false;
            }
            Console.WriteLine($"[+] LoadLibraryA address: 0x{loadLibraryA.ToInt64():X16}");
            // Build x64 shellcode
            byte[] shellcode = new byte[32];
            int idx = 0;
            // sub rsp, 0x28
            shellcode[idx++] = 0x48; shellcode[idx++] = 0x83; shellcode[idx++] = 0xEC; shellcode[idx++] = 0x28;
            // mov rcx, <base_address>
            shellcode[idx++] = 0x48; shellcode[idx++] = 0xB9;
            Array.Copy(BitConverter.GetBytes((ulong)baseAddress.ToInt64()), 0, shellcode, idx, 8); idx += 8;
            // mov rax, <LoadLibraryA>
            shellcode[idx++] = 0x48; shellcode[idx++] = 0xB8;
            Array.Copy(BitConverter.GetBytes((ulong)loadLibraryA.ToInt64()), 0, shellcode, idx, 8); idx += 8;
            // call rax
            shellcode[idx++] = 0xFF; shellcode[idx++] = 0xD0;
            // add rsp, 0x28
            shellcode[idx++] = 0x48; shellcode[idx++] = 0x83; shellcode[idx++] = 0xC4; shellcode[idx++] = 0x28;
            // ret
            shellcode[idx++] = 0xC3;
            UIntPtr shellcodeSize = (UIntPtr)idx;
            // Allocate memory for shellcode
            IntPtr shellcodeAddr = IntPtr.Zero;
            regionSize = shellcodeSize;
            status = oznbvo_655212(
                hProcess,
                ref shellcodeAddr,
                ref regionSize,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                NativeMethods.PAGE_EXECUTE_READWRITE,
                IntPtr.Zero,
                0
            );
            if (!NT_SUCCESS(status))
            {
                Console.WriteLine($"[!] Failed to allocate memory for shellcode. Status: 0x{status:X8}");
                return false;
            }
            Console.WriteLine($"[+] Allocated shellcode memory at: 0x{shellcodeAddr.ToInt64():X16}");
            // Write shellcode
            bytesWritten = UIntPtr.Zero;
            handle = GCHandle.Alloc(shellcode, GCHandleType.Pinned);
            try
            {
                status = yexedj_555900(
                    hProcess,
                    shellcodeAddr,
                    handle.AddrOfPinnedObject(),
                    shellcodeSize,
                    ref bytesWritten
                );
            }
            finally
            {
                handle.Free();
            }
            if (!NT_SUCCESS(status) || bytesWritten != shellcodeSize)
            {
                Console.WriteLine($"[!] Failed to write shellcode. Status: 0x{status:X8}, Bytes written: {bytesWritten}");
                return false;
            }
            Console.WriteLine("[+] Successfully wrote shellcode");
            // Create remote thread
            IntPtr hThread = IntPtr.Zero;
            status = jljtug_682236(
                ref hThread,
                NativeMethods.THREAD_ALL_ACCESS,
                IntPtr.Zero,
                hProcess,
                shellcodeAddr,
                IntPtr.Zero,
                0, UIntPtr.Zero, UIntPtr.Zero, UIntPtr.Zero,
                IntPtr.Zero
            );
            if (!NT_SUCCESS(status) || hThread == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Failed to create remote thread. Status: 0x{status:X8}, Handle: 0x{hThread.ToInt64():X16}");
                return false;
            }
            Console.WriteLine($"[+] Created remote thread: 0x{hThread.ToInt64():X16}");
            // Wait for thread and close handle
            NativeMethods.WaitForSingleObject(hThread, 5000);
            ezhgwv_592746(hThread);
            Console.WriteLine($"[+] Successfully injected {dllPath}!");
            return true;
        }

        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine($"Usage: {AppDomain.CurrentDomain.FriendlyName} <pid> <dll_path>");
                return;
            }
            if (!File.Exists("SysCaller.dll"))
            {
                Console.WriteLine("[!] SysCaller.dll not found in current directory.");
                return;
            }
            uint pid = uint.Parse(args[0]);
            string dllPath = args[1];
            IntPtr hSysCaller = NativeMethods.LoadLibraryA("SysCaller.dll");
            if (hSysCaller == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to load SysCaller.dll");
                return;
            }
            var oznbvo_655212 = Marshal.GetDelegateForFunctionPointer<SysCaller.oznbvo_655212Delegate>(NativeMethods.GetProcAddress(hSysCaller, "oznbvo_655212"));
            var yexedj_555900 = Marshal.GetDelegateForFunctionPointer<SysCaller.yexedj_555900Delegate>(NativeMethods.GetProcAddress(hSysCaller, "yexedj_555900"));
            var jljtug_682236 = Marshal.GetDelegateForFunctionPointer<SysCaller.jljtug_682236Delegate>(NativeMethods.GetProcAddress(hSysCaller, "jljtug_682236"));
            var ezhgwv_592746 = Marshal.GetDelegateForFunctionPointer<SysCaller.ezhgwv_592746Delegate>(NativeMethods.GetProcAddress(hSysCaller, "ezhgwv_592746"));
            if (oznbvo_655212 == null || yexedj_555900 == null || jljtug_682236 == null || ezhgwv_592746 == null)
            {
                Console.WriteLine("[!] Failed to resolve SysCaller functions");
                return;
            }
            IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_ALL_ACCESS, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Failed to open process {pid}");
                return;
            }
            InjectDLL(hProcess, dllPath, oznbvo_655212, yexedj_555900, jljtug_682236, ezhgwv_592746);
            NativeMethods.CloseHandle(hProcess);
        }
    }
}