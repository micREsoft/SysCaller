import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'GUI')))
import pefile
import re
import capstone

try:
    from PyQt5.QtCore import QSettings
except ImportError:
    class QSettings:
        def __init__(self, *args):
            self.settings = {}
        def value(self, key, default, type):
            return default
from settings.utils import get_ini_path

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
            syscall_name = proc_match.group(1)
            version_match = re.search(r"((?:Sys|SysK)\w+?)(\d+)?$", syscall_name)
            if version_match:
                base_name = version_match.group(1)
                version = int(version_match.group(2)) if version_match.group(2) else 1
            else:
                base_name = syscall_name
                version = 1
            syscall = {
                'name': syscall_name,
                'base_name': base_name,
                'version': version
            }
            name_key = f"{base_name}_{version}"
            if name_key in unique_names:
                syscall['duplicate_name'] = True
                syscall['duplicate_name_with'] = unique_names[name_key]
            else:
                syscall['duplicate_name'] = False
                unique_names[name_key] = syscall_name
        offset_match = re.search(r"mov\s+(eax|rax),\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)h?", line)
        if syscall and offset_match:
            try:
                offset_value = offset_match.group(2)
                if offset_value.startswith("0x"):
                    syscall['offset'] = int(offset_value, 16)
                else:
                    syscall['offset'] = int(offset_value.rstrip("h"), 16)
                offset_key = f"{syscall['offset']}_{syscall['version']}"
                if offset_key in unique_offsets:
                    syscall['duplicate_offset'] = True
                    syscall['duplicate_offset_with'] = unique_offsets[offset_key]
                else:
                    syscall['duplicate_offset'] = False
                    unique_offsets[offset_key] = syscall['name']
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

def validate_syscalls(asm_file, dll_paths):
    settings = QSettings(get_ini_path(), QSettings.IniFormat)
    syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
    is_zw_mode = syscall_mode == 'Zw'
    mode_display = "Zw" if is_zw_mode else "Nt"
    syscalls = read_syscalls(asm_file)
    print(f"{Colors.BOLD}Found {len(syscalls)} syscalls in syscaller.asm{Colors.ENDC}")
    syscall_tables = {}
    for i, dll_path in enumerate(dll_paths):
        syscall_tables[i+1] = get_syscalls(dll_path)
    print_legend()
    valid, invalid, duplicates = 0, 0, 0
    for syscall in syscalls:
        version = syscall['version']
        dll_index = min(version, len(syscall_tables))
        syscall_numbers = syscall_tables[dll_index]
        if syscall['name'].startswith('SysK'):
            expected_name = 'Nt' + syscall['name'][4:]
        elif syscall['name'].startswith('Sys'):
            expected_name = 'Nt' + syscall['name'][3:]
        else:
            expected_name = syscall['name']
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

    settings = QSettings(get_ini_path(), QSettings.IniFormat)
    syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
    is_kernel_mode = syscall_mode == 'Zw'
    if is_kernel_mode:
        asm_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'SysCallerK', 'Wrapper', 'src', 'syscaller.asm')
    else:
        asm_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'SysCaller', 'Wrapper', 'src', 'syscaller.asm')
    main_dll_path = os.getenv('NTDLL_PATH', "C:\\Windows\\System32\\ntdll.dll")
    dll_path_count = int(os.getenv('NTDLL_PATH_COUNT', '1'))
    dll_paths = [main_dll_path]
    for i in range(2, dll_path_count + 1):
        additional_dll_path = os.getenv(f'NTDLL_PATH_{i}')
        if additional_dll_path:
            dll_paths.append(additional_dll_path)
    validate_syscalls(asm_file, dll_paths)
