import pefile
import re
import capstone
import os

try:
    from PyQt5.QtCore import QSettings
except ImportError:
    class QSettings:
        def __init__(self, *args):
            self.settings = {}
        def value(self, key, default, type):
            return default

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
        proc_match = re.search(r"((?:Sys|SysK)\w+)\s+PROC", line)
        if proc_match:
            if syscall and syscall not in syscalls:
                syscalls.append(syscall)
            syscall = {'name': proc_match.group(1)}
            if syscall['name'] in unique_names:
                syscall['duplicate_name'] = True
                syscall['duplicate_name_with'] = unique_names[syscall['name']]
            else:
                syscall['duplicate_name'] = False
                unique_names[syscall['name']] = syscall['name']
        offset_match = re.search(r"mov\s+(eax|rax),\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)h?", line)
        if syscall and offset_match:
            try:
                offset_value = offset_match.group(2)
                if offset_value.startswith("0x"):
                    syscall['offset'] = int(offset_value, 16)
                else:
                    syscall['offset'] = int(offset_value.rstrip("h"), 16)
                if syscall['offset'] in unique_offsets:
                    syscall['duplicate_offset'] = True
                    syscall['duplicate_offset_with'] = unique_offsets[syscall['offset']]
                else:
                    syscall['duplicate_offset'] = False
                    unique_offsets[syscall['offset']] = syscall['name']
            except ValueError:
                print(f"Warning: Could not parse offset value: {offset_match.group(2)}")
        
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
    print(f"{Colors.BOLD}Nt/Zw = Indicates type of syscall stub found {Colors.ENDC}")
    print(f"{Colors.BOLD}DUP = Duplicate Offset or Name (conflicts with another syscall){Colors.ENDC}")
    print(f"{Colors.BOLD}Found = Found Syscall Name (resolved in DLL){Colors.ENDC}")
    print(f"{Colors.BOLD}Not Found = Syscall not Found in DLL{Colors.ENDC}")
    print(f"{Colors.BOLD}MATCH = Syscall Name and Offset Match ntdll Version{Colors.ENDC}")
    print(f"{Colors.BOLD}MISMATCH = Syscall Name or Offset Mismatch with ntdll Version{Colors.ENDC}")
    print(f"{Colors.BOLD}f = Found Offset (resolved in DLL){Colors.ENDC}")
    print(f"{Colors.BOLD}i = Invalid Offset (could not be resolved or malformed){Colors.ENDC}")
    print(f"{Colors.BOLD}v = Valid Offset (resolved in DLL){Colors.ENDC}")
    print()

def validate_syscalls(asm_file, dll_path):
    settings = QSettings('SysCaller', 'BuildTools')
    syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
    is_zw_mode = syscall_mode == 'Zw'
    mode_display = "Zw" if is_zw_mode else "Nt"
    syscalls = read_syscalls(asm_file)
    syscall_numbers = get_syscalls(dll_path)
    print(f"{Colors.BOLD}Found {len(syscalls)} syscalls in syscaller.asm{Colors.ENDC}")
    print_legend()
    valid, invalid, duplicates = 0, 0, 0
    for syscall in syscalls:
        if syscall['name'].startswith('SysK'):
            base_name = syscall['name'][4:]
        elif syscall['name'].startswith('Sys'):
            base_name = syscall['name'][3:]
        else:
            base_name = syscall['name']
        expected_name = "Nt" + base_name
        actual_offset = syscall_numbers.get(expected_name, 0)
        if syscall.get('duplicate_offset', False) or syscall.get('duplicate_name', False):
            duplicates += 1
            if syscall.get('duplicate_offset', False) and syscall.get('duplicate_name', False):
                dup_type = "Duplicate Offset & Name"
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
            prefix = 'v' if syscall['offset'] == actual_offset else 'i'
            print(f"{Colors.WARNING}{syscall['name']}: {dup_type} ({mode_display}) {prefix}0x{syscall['offset']:X} f0x{actual_offset:X} (DUP) {dup_with}{Colors.ENDC}")
            continue
        if expected_name in syscall_numbers:
            if syscall['offset'] == syscall_numbers[expected_name]:
                valid += 1
                print(f"{Colors.OKGREEN}{syscall['name']}: Found ({mode_display}) v0x{syscall['offset']:X} f0x{syscall_numbers[expected_name]:X} (MATCH){Colors.ENDC}")
            else:
                invalid += 1
                print(f"{Colors.FAIL}{syscall['name']}: Found ({mode_display}) i0x{syscall['offset']:X} f0x{syscall_numbers[expected_name]:X} (MISMATCH){Colors.ENDC}")
        else:
            invalid += 1
            print(f"{Colors.FAIL}{syscall['name']}: Not Found ({mode_display}) i0x{syscall['offset']:X} f0x{actual_offset:X} (MISMATCH){Colors.ENDC}")
    print(f"\n{Colors.BOLD}Valid: {Colors.OKGREEN}{valid}{Colors.ENDC}{Colors.BOLD}, Invalid: {Colors.FAIL}{invalid}{Colors.ENDC}{Colors.BOLD}, Duplicates: {Colors.WARNING}{duplicates}{Colors.ENDC}")

if __name__ == "__main__":
    asm_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'Wrapper', 'src', 'syscaller.asm')
    dll_path = os.getenv('NTDLL_PATH', "C:\\Windows\\System32\\ntdll.dll")
    validate_syscalls(asm_file, dll_path)