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

def update_syscalls(asm_file, syscall_numbers):
    asm_file_path = os.path.join(os.path.dirname(__file__), '..', '..', 'Wrapper', 'src', 'syscaller.asm')
    with open(asm_file_path, 'r') as file:
        lines = file.readlines()
    updated_lines = []
    skip_block = False
    syscall_name = None
    settings = QSettings('SysCaller', 'BuildTools')
    selected_syscalls = settings.value('integrity/selected_syscalls', [], type=list)
    use_all_syscalls = len(selected_syscalls) == 0
    for i, line in enumerate(lines):
        proc_match = re.search(r"(Sys\w+)\s+PROC", line)
        if proc_match:
            syscall_name = proc_match.group(1)
            expected_nt_name = "Nt" + syscall_name[3:]
            expected_zw_name = "Zw" + syscall_name[3:]
            syscall_id = syscall_numbers.get(expected_nt_name, syscall_numbers.get(expected_zw_name, None))
            if (not use_all_syscalls and syscall_name not in selected_syscalls) or syscall_id is None:
                if syscall_id is None:
                    print(f"Removing {syscall_name} (not found in ntdll.dll)")
                else:
                    print(f"Removing {syscall_name} (not selected in settings)")
                skip_block = True
            else:
                print(f"Updating {syscall_name} with syscall ID: 0x{syscall_id:X}")
                updated_lines.append(line)
                skip_block = False
            continue
        if skip_block:
            if "ENDP" in line:
                skip_block = False
            continue
        if "<syscall_id>" in line and syscall_name:
            syscall_id = syscall_numbers.get("Nt" + syscall_name[3:], syscall_numbers.get("Zw" + syscall_name[3:], None))
            if syscall_id is not None:
                updated_lines.append(line.replace("<syscall_id>", f"0{syscall_id:X}"))
            else:
                updated_lines.append(line)
        else:
            updated_lines.append(line)
    cleaned_lines = []
    prev_empty = False
    for line in updated_lines:
        if line.strip() == "":
            if not prev_empty:
                cleaned_lines.append(line)
                prev_empty = True
        else:
            cleaned_lines.append(line)
            prev_empty = False
    if len(cleaned_lines) > 0 and not any(".code" in line for line in cleaned_lines):
        cleaned_lines.insert(0, ".code\n\n")
    if len(cleaned_lines) > 0 and not any("end" in line.lower() for line in cleaned_lines[-3:]):
        cleaned_lines.append("\nend\n")
    with open(asm_file, 'w') as file:
        file.writelines(cleaned_lines)
    update_header_file(selected_syscalls, use_all_syscalls)
    print(f"Updated syscalls written to {asm_file}")

def update_header_file(selected_syscalls, use_all_syscalls):
    header_file_path = os.path.join(os.path.dirname(__file__), '..', '..', 'Wrapper', 'include', 'Nt', 'sysNtFunctions.h')
    with open(header_file_path, 'r') as file:
        lines = file.readlines()
    updated_lines = []
    skip_block = False
    header_part_ended = False
    ending_lines = []
    for i in range(len(lines)-1, -1, -1):
        line = lines[i].strip()
        if line == "#endif" or line.startswith("#endif "):
            ending_lines.insert(0, lines[i])
            j = i - 1
            while j >= 0 and (lines[j].strip() == "" or lines[j].strip().startswith("//")):
                ending_lines.insert(0, lines[j])
                j -= 1
            break
    for i, line in enumerate(lines):
        if any(line == end_line for end_line in ending_lines):
            continue
        if not header_part_ended and 'extern "C" NTSTATUS Sys' in line:
            header_part_ended = True
        if not header_part_ended:
            if "_WIN64" in line and "#ifdef" in line:
                updated_lines.append(line)
                updated_lines.append("\n")
                continue
            updated_lines.append(line)
            continue
        if 'extern "C" NTSTATUS Sys' in line:
            match = re.search(r'extern "C" NTSTATUS (Sys\w+)\(', line)
            if match:
                syscall_name = match.group(1)
                if use_all_syscalls or syscall_name in selected_syscalls:
                    skip_block = False
                    updated_lines.append(line)
                else:
                    skip_block = True
                continue
        if not skip_block:
            updated_lines.append(line)
        elif line.strip() == ");":
            skip_block = False
    cleaned_lines = []
    prev_empty = False
    for line in updated_lines:
        if line.strip() == "":
            if not prev_empty:
                cleaned_lines.append(line)
                prev_empty = True
        else:
            cleaned_lines.append(line)
            prev_empty = False
    if ending_lines:
        if cleaned_lines and cleaned_lines[-1].strip() != "":
            cleaned_lines.append("\n")
        non_empty_ending_found = False
        filtered_ending_lines = []
        for line in ending_lines:
            if line.strip() != "" or non_empty_ending_found:
                filtered_ending_lines.append(line)
                non_empty_ending_found = True
            else:
                continue
        cleaned_lines.extend(filtered_ending_lines)
    if cleaned_lines and not cleaned_lines[-1].endswith('\n'):
        cleaned_lines[-1] += '\n'
    with open(header_file_path, 'w') as file:
        file.writelines(cleaned_lines)
    print(f"Updated header file with selected syscalls")

def get_syscalls(dll_path):
    pe = pefile.PE(dll_path)
    syscall_numbers = {}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not export.name:
            continue
        func_name = export.name.decode()
        func_rva = export.address
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

if __name__ == "__main__":
    asm_file = os.path.join(os.path.dirname(__file__), '..', '..', 'Wrapper', 'src', 'syscaller.asm')
    dll_path = os.getenv('NTDLL_PATH', "C:\\Windows\\System32\\ntdll.dll")
    syscall_numbers = get_syscalls(dll_path)
    update_syscalls(asm_file, syscall_numbers)
