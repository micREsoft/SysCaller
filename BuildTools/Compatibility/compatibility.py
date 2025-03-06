import pefile
import re
import capstone

def read_syscalls(asm_file):
    syscalls = []
    unique_offsets = {}
    with open(asm_file, 'r') as file:
        lines = file.readlines()
    syscall = None
    for line in lines:
        proc_match = re.search(r"(Sys\w+)\s+PROC", line)
        if proc_match:
            if syscall and syscall['offset'] not in unique_offsets:
                syscalls.append(syscall)
                unique_offsets[syscall['offset']] = syscall['name']
            syscall = {'name': proc_match.group(1)}
        offset_match = re.search(r"mov\s+(eax|rax),\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)h?", line)
        if syscall and offset_match:
            syscall['offset'] = int(offset_match.group(2), 16)
        if syscall and "ENDP" in line:
            if syscall['offset'] not in unique_offsets:
                syscalls.append(syscall)
                unique_offsets[syscall['offset']] = syscall['name']
    return syscalls

def get_syscalls(dll_path):
    pe = pefile.PE(dll_path)
    syscall_numbers = {}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not export.name:
            continue
        func_name = export.name.decode()
        func_rva = export.address
        # only read first 16 bytes
        func_bytes = pe.get_data(func_rva, 16)
        for instruction in md.disasm(func_bytes, func_rva):
            if instruction.mnemonic == 'mov' and ('eax' in instruction.op_str or 'rax' in instruction.op_str):
                parts = instruction.op_str.split(',')
                if len(parts) == 2:
                    try:
                        syscall_id = int(parts[1].strip(), 16)
                        syscall_numbers[func_name] = syscall_id
                        break
                    except ValueError:
                        continue
    return syscall_numbers

def validate_syscalls(asm_file, dll_path):
    syscalls = read_syscalls(asm_file)
    syscall_numbers = get_syscalls(dll_path)
    print(f"Found {len(syscalls)} syscalls in {asm_file}")
    valid, invalid = 0, 0
    for syscall in syscalls:
        expected_nt_name = "Nt" + syscall['name'][3:]
        expected_zw_name = "Zw" + syscall['name'][3:]
        # check for valid syscall and correct offset
        if expected_nt_name in syscall_numbers:
            if syscall['offset'] == syscall_numbers[expected_nt_name]:  # check if the offset matches
                valid += 1
                print(f"{syscall['name']}: Found (Nt) v0x{syscall['offset']:X} f0x{syscall_numbers[expected_nt_name]:X} (MATCH)")
            else:
                invalid += 1
                print(f"{syscall['name']}: Found (Nt) i0x{syscall['offset']:X} f0x{syscall_numbers[expected_nt_name]:X} (MISMATCH)")
        elif expected_zw_name in syscall_numbers:
            if syscall['offset'] == syscall_numbers[expected_zw_name]:  # check if the offset matches
                valid += 1
                print(f"{syscall['name']}: Found (Zw) v0x{syscall['offset']:X} f0x{syscall_numbers[expected_zw_name]:X} (MATCH)")
            else:
                invalid += 1
                print(f"{syscall['name']}: Found (Zw) i0x{syscall['offset']:X} f0x{syscall_numbers[expected_zw_name]:X} (MISMATCH)")
        else:
            invalid += 1
            print(f"{syscall['name']}: Found (Nt) i0x{syscall['offset']:X} f0x{syscall_numbers.get(expected_nt_name, 0):X} (MISMATCH)")
    print(f"\nValid: {valid}, Invalid: {invalid}")

if __name__ == "__main__":
    asm_file = input("Enter path to syscaller.asm: ")
    dll_path = "C:\\Windows\\System32\\ntdll.dll"
    validate_syscalls(asm_file, dll_path)
