public class InjectDLL {
    static {
        System.loadLibrary("InjectDLLNative");
    }

    private static native boolean inject(int pid, String dllPath);

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java InjectDLL <pid> <dll_path>");
            return;
        }
        int pid = Integer.parseInt(args[0]);
        String dll = args[1];
        boolean ok = inject(pid, dll);
        System.out.println(ok ? "[+] Injection succeeded" : "[!] Injection failed");
    }
}
