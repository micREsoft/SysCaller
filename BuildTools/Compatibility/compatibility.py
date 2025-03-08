import pefile
import re
import capstone
import os

class Colors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def read_syscalls(asm_file):
    syscalls = []
    unique_offsets = {}
    unique_names = {}
    with open(asm_file, 'r') as file:
        lines = file.readlines()
    syscall = None
    for line in lines:
        proc_match = re.search(r"(Sys\w+)\s+PROC", line)
        if proc_match:
            if syscall and syscall not in syscalls:
                syscalls.append(syscall)
            syscall = {'name': proc_match.group(1)}
            # Check for duplicate names
            if syscall['name'] in unique_names:
                syscall['duplicate_name'] = True
                syscall['duplicate_name_with'] = unique_names[syscall['name']]
            else:
                syscall['duplicate_name'] = False
                unique_names[syscall['name']] = syscall['name']
        
        offset_match = re.search(r"mov\s+(eax|rax),\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)h?", line)
        if syscall and offset_match:
            syscall['offset'] = int(offset_match.group(2), 16)
            # Check for duplicate offsets
            if syscall['offset'] in unique_offsets:
                syscall['duplicate_offset'] = True
                syscall['duplicate_offset_with'] = unique_offsets[syscall['offset']]
            else:
                syscall['duplicate_offset'] = False
                unique_offsets[syscall['offset']] = syscall['name']
        
        if syscall and "ENDP" in line and syscall not in syscalls:
            syscalls.append(syscall)
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
        # Only read first 16 bytes
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

def print_legend():
    print()
    print(f"{Colors.BOLD}SysCaller Legend:{Colors.ENDC}")
    print(f"{Colors.BOLD}DUP = Duplicate Offset & or Name with Another Syscall{Colors.ENDC}")
    print(f"{Colors.BOLD}f = Found Offset (in DLL){Colors.ENDC}")
    print(f"{Colors.BOLD}Found = Found Syscall in DLL{Colors.ENDC}")
    print(f"{Colors.BOLD}i = Invalid Offset{Colors.ENDC}")
    print(f"{Colors.BOLD}Nt = Nt Syscall{Colors.ENDC}")
    print(f"{Colors.BOLD}Not Found = Syscall not Found in DLL{Colors.ENDC}")
    print(f"{Colors.BOLD}MATCH = Syscall Offset & Name Match ntdll Version{Colors.ENDC}")
    print(f"{Colors.BOLD}MISMATCH = Syscall Offset & or Name dont Match ntdll Version{Colors.ENDC}")
    print(f"{Colors.BOLD}v = Valid Offset{Colors.ENDC}")
    print(f"{Colors.BOLD}Zw = Zw Syscall (Coming Soon!){Colors.ENDC}")
    print()

def validate_syscalls(asm_file, dll_path):
    syscalls = read_syscalls(asm_file)
    syscall_numbers = get_syscalls(dll_path)
    print(f"{Colors.BOLD}Found {len(syscalls)} syscalls in {asm_file}{Colors.ENDC}")
    print_legend()
    valid, invalid, duplicates = 0, 0, 0
    for syscall in syscalls:
        if syscall.get('duplicate_offset', False) or syscall.get('duplicate_name', False):
            duplicates += 1
            expected_nt_name = "Nt" + syscall['name'][3:]
            expected_zw_name = "Zw" + syscall['name'][3:]
            actual_offset = syscall_numbers.get(expected_nt_name, syscall_numbers.get(expected_zw_name, 0))
            # Determine duplicate type message
            if syscall.get('duplicate_offset', False) and syscall.get('duplicate_name', False):
                dup_type = "Duplicate Offset & Name"
                # Check if offset and name are duplicated with the same syscall
                if syscall['duplicate_offset_with'] == syscall['duplicate_name_with']:
                    dup_with = f"Offset & Name with {syscall['duplicate_offset_with']}"
                else:
                    dup_with = f"Offset with {syscall['duplicate_offset_with']} | Name with {syscall['duplicate_name_with']}"
            elif syscall.get('duplicate_offset', False):
                dup_type = "Duplicate Offset"
                dup_with = f"with {syscall['duplicate_offset_with']}"
            else:
                dup_type = "Duplicate Name"
                dup_with = f"with {syscall['duplicate_name_with']}"
            # Determine if its a valid offset despite being duplicate
            prefix = 'v' if syscall['offset'] == actual_offset else 'i'
            
            print(f"{Colors.WARNING}{syscall['name']}: {dup_type} {prefix}0x{syscall['offset']:X} f0x{actual_offset:X} (DUP) {dup_with}{Colors.ENDC}")
            continue
        expected_nt_name = "Nt" + syscall['name'][3:]
        expected_zw_name = "Zw" + syscall['name'][3:]
        # Check for valid syscall and correct offset
        if expected_nt_name in syscall_numbers:
            if syscall['offset'] == syscall_numbers[expected_nt_name]:
                valid += 1
                print(f"{Colors.OKGREEN}{syscall['name']}: Found (Nt) v0x{syscall['offset']:X} f0x{syscall_numbers[expected_nt_name]:X} (MATCH){Colors.ENDC}")
            else:
                invalid += 1
                print(f"{Colors.FAIL}{syscall['name']}: Found (Nt) i0x{syscall['offset']:X} f0x{syscall_numbers[expected_nt_name]:X} (MISMATCH){Colors.ENDC}")
        elif expected_zw_name in syscall_numbers:
            if syscall['offset'] == syscall_numbers[expected_zw_name]:
                valid += 1
                print(f"{Colors.OKGREEN}{syscall['name']}: Found (Zw) v0x{syscall['offset']:X} f0x{syscall_numbers[expected_zw_name]:X} (MATCH){Colors.ENDC}")
            else:
                invalid += 1
                print(f"{Colors.FAIL}{syscall['name']}: Found (Zw) i0x{syscall['offset']:X} f0x{syscall_numbers[expected_zw_name]:X} (MISMATCH){Colors.ENDC}")
        else:
            invalid += 1
            print(f"{Colors.FAIL}{syscall['name']}: Not Found i0x{syscall['offset']:X} f0x{syscall_numbers.get(expected_nt_name, 0):X} (MISMATCH){Colors.ENDC}")
    print(f"\n{Colors.BOLD}Valid: {Colors.OKGREEN}{valid}{Colors.ENDC}{Colors.BOLD}, Invalid: {Colors.FAIL}{invalid}{Colors.ENDC}{Colors.BOLD}, Duplicates: {Colors.WARNING}{duplicates}{Colors.ENDC}")

if __name__ == "__main__":
    asm_file = os.path.join(os.path.dirname(__file__), '..', '..', 'Wrapper', 'src', 'syscaller.asm')
    dll_path = "C:\\Windows\\System32\\ntdll.dll"
    validate_syscalls(asm_file, dll_path)
