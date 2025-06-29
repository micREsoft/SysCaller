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

def update_syscalls(asm_file, syscall_tables):
    with open(asm_file, 'r') as file:
        lines = file.readlines()
    num_tables = len(syscall_tables)
    if num_tables == 0:
        print("No syscall tables provided. Aborting.")
        return
    print(f"Processing {num_tables} syscall table(s)...")
    updated_lines = []
    settings = QSettings('SysCaller', 'BuildTools')
    selected_syscalls = settings.value('integrity/selected_syscalls', [], type=list)
    use_all_syscalls = len(selected_syscalls) == 0
    syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
    syscall_prefix = "Sys" if syscall_mode == "Nt" else "SysK"
    syscalls = {}
    current_syscall = None
    start_index = -1
    for i, line in enumerate(lines):
        proc_match = re.search(r"(SC\w+)\s+PROC", line)
        if proc_match:
            if current_syscall:
                syscalls[current_syscall]['end'] = i - 1
            current_syscall = proc_match.group(1)
            syscalls[current_syscall] = {'start': i, 'end': -1, 'content': []}
        elif current_syscall and "ENDP" in line:
            syscalls[current_syscall]['end'] = i
            current_syscall = None
    if current_syscall:
        syscalls[current_syscall]['end'] = len(lines) - 1
    for syscall_name, indices in syscalls.items():
        syscalls[syscall_name]['content'] = lines[indices['start']:indices['end']+1]
    new_lines = []
    skip_until = -1
    for i, line in enumerate(lines):
        if i <= skip_until:
            continue
        proc_match = re.search(r"(SC\w+)\s+PROC", line)
        if proc_match:
            original_name = proc_match.group(1)
            base_name = original_name[2:]
            syscall_name = syscall_prefix + base_name
            if not use_all_syscalls and syscall_name not in selected_syscalls:
                print(f"Skipping {syscall_name} (not selected in settings)")
                skip_until = syscalls[original_name]['end']
                continue
            found_in_any = False
            for table_idx, syscall_numbers in syscall_tables.items():
                if syscall_mode == "Nt":
                    expected_dll_name = "Nt" + base_name
                    expected_alt_name = "Zw" + base_name
                else:
                    expected_dll_name = "Zw" + base_name
                    expected_alt_name = "Nt" + base_name
                syscall_id = syscall_numbers.get(expected_dll_name, syscall_numbers.get(expected_alt_name, None))
                if syscall_id is not None:
                    found_in_any = True
                    version_suffix = "" if table_idx == 0 else str(table_idx + 1)
                    versioned_syscall_name = f"{syscall_prefix}{base_name}{version_suffix}"
                    proc_line = line.replace(original_name, versioned_syscall_name)
                    new_lines.append(proc_line)
                    for content_line in syscalls[original_name]['content'][1:-1]:
                        if "<syscall_id>" in content_line:
                            new_lines.append(content_line.replace("<syscall_id>", f"0{syscall_id:X}"))
                        elif "SC" in content_line:
                            new_lines.append(re.sub(r'\bSC(\w+)\b', fr'{syscall_prefix}\1{version_suffix}', content_line))
                        else:
                            new_lines.append(content_line)
                    endp_line = syscalls[original_name]['content'][-1].replace(original_name, versioned_syscall_name)
                    new_lines.append(endp_line)
                    new_lines.append("\n")
            if not found_in_any:
                print(f"Removing {syscall_name} (not found in any ntdll.dll)")
            skip_until = syscalls[original_name]['end']
        else:
            new_lines.append(line)
    cleaned_lines = []
    prev_empty = False
    for line in new_lines:
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
    update_header_file(syscall_tables, selected_syscalls, use_all_syscalls)
    print(f"Updated syscalls written to {asm_file}")

def update_header_file(syscall_tables, selected_syscalls, use_all_syscalls):
    base_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..')
    settings = QSettings('SysCaller', 'BuildTools')
    syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
    is_kernel_mode = syscall_mode == 'Zw'
    if is_kernel_mode:
        header_file_path = os.path.join(base_dir, 'SysCallerK', 'Wrapper', 'include', 'SysK', 'sysFunctions_k.h')
    else:
        header_file_path = os.path.join(base_dir, 'SysCaller', 'Wrapper', 'include', 'Sys', 'sysFunctions.h')
    with open(header_file_path, 'r') as file:
        lines = file.readlines()
    updated_lines = []
    header_part_ended = False
    ending_lines = []
    syscall_prefix = "Sys" if syscall_mode == "Nt" else "SysK"
    func_decl_regex = re.compile(r'(?:extern\s+"C"\s+)?(?:NTSTATUS|ULONG|BOOLEAN|VOID)\s+((?:SC|Sys|SysK)\w+)\s*\(')
    for i in range(len(lines)-1, -1, -1):
        line = lines[i].strip()
        if line == "#endif" or line.startswith("#endif "):
            ending_lines.insert(0, lines[i])
            j = i - 1
            while j >= 0 and (lines[j].strip() == "" or lines[j].strip().startswith("//")):
                ending_lines.insert(0, lines[j])
                j -= 1
            break
    function_declarations = {}
    current_function = None
    function_content = []
    for i, line in enumerate(lines):
        if any(line == end_line for end_line in ending_lines):
            continue
        if not header_part_ended and func_decl_regex.search(line):
            header_part_ended = True
        if not header_part_ended:
            if "_WIN64" in line and "#ifdef" in line:
                updated_lines.append(line)
                updated_lines.append("\n")
                continue
            updated_lines.append(line)
            continue
        if func_decl_regex.search(line):
            if current_function and function_content:
                function_declarations[current_function] = function_content
                function_content = []
            match = func_decl_regex.search(line)
            if match:
                original_name = match.group(1)
                if original_name.startswith("SC"):
                    base_name = original_name[2:]
                    syscall_name = syscall_prefix + base_name
                elif original_name.startswith("Sys"):
                    if syscall_prefix == "Sys":
                        base_name = original_name[3:]
                        syscall_name = original_name
                    else:
                        base_name = original_name[3:]
                        syscall_name = syscall_prefix + base_name
                elif original_name.startswith("SysK"):
                    if syscall_prefix == "SysK":
                        base_name = original_name[4:]
                        syscall_name = original_name
                    else:
                        base_name = original_name[4:]
                        syscall_name = syscall_prefix + base_name
                if use_all_syscalls or syscall_name in selected_syscalls:
                    current_function = syscall_name
                    modified_line = re.sub(r'\b' + re.escape(original_name) + r'\b', syscall_name, line)
                    function_content.append(modified_line)
                else:
                    current_function = None
        elif current_function:
            if "SC" in line:
                modified_line = line
                sc_matches = re.finditer(r'\bSC(\w+)\b', line)
                for match in sc_matches:
                    sc_name = match.group(0)
                    base_name = match.group(1)
                    sys_name = f"{syscall_prefix}{base_name}"
                    modified_line = modified_line.replace(sc_name, sys_name)
                function_content.append(modified_line)
            else:
                function_content.append(line)
            if line.strip() == ");":
                function_declarations[current_function] = function_content
                function_content = []
                current_function = None
    if current_function and function_content:
        function_declarations[current_function] = function_content
    num_tables = len(syscall_tables)
    for func_name, content in function_declarations.items():
        if func_name.startswith(syscall_prefix):
            base_name = func_name[len(syscall_prefix):]
        else:
            base_name = func_name
        # DEBUG print(f"Checking function: {func_name} -> base_name: {base_name}")
        found_in_any_table = False
        for table_idx in range(num_tables):
            if table_idx not in syscall_tables:
                continue
            if syscall_mode == "Nt":
                expected_dll_name = "Nt" + base_name
                expected_alt_name = "Zw" + base_name
            else:
                expected_dll_name = "Zw" + base_name
                expected_alt_name = "Nt" + base_name
            syscall_id = syscall_tables[table_idx].get(expected_dll_name, syscall_tables[table_idx].get(expected_alt_name, None))
            if syscall_id is not None:
                print(f"  Found {expected_dll_name} in table {table_idx} with ID {syscall_id}")
                found_in_any_table = True
                break
            else:
                print(f"  Not found: {expected_dll_name} or {expected_alt_name} in table {table_idx}")
        if not found_in_any_table:
            print(f"Removing {func_name} from header (not found in any ntdll.dll)")
            continue
        if 0 in syscall_tables:
            if syscall_mode == "Nt":
                expected_dll_name = "Nt" + base_name
                expected_alt_name = "Zw" + base_name
            else:
                expected_dll_name = "Zw" + base_name
                expected_alt_name = "Nt" + base_name
            syscall_id = syscall_tables[0].get(expected_dll_name, syscall_tables[0].get(expected_alt_name, None))
            if syscall_id is not None:
                for line in content:
                    updated_lines.append(line)
                updated_lines.append("\n")
        for table_idx in range(1, num_tables):
            if table_idx not in syscall_tables:
                continue
            if syscall_mode == "Nt":
                expected_dll_name = "Nt" + base_name
                expected_alt_name = "Zw" + base_name
            else:
                expected_dll_name = "Zw" + base_name
                expected_alt_name = "Nt" + base_name
            syscall_id = syscall_tables[table_idx].get(expected_dll_name, syscall_tables[table_idx].get(expected_alt_name, None))
            if syscall_id is not None:
                for line in content:
                    versioned_name = f"{func_name}{table_idx+1}"
                    versioned_line = re.sub(
                        r'\b' + re.escape(func_name) + r'\b', 
                        versioned_name, 
                        line
                    )
                    updated_lines.append(versioned_line)
                updated_lines.append("\n")
    if updated_lines and updated_lines[-1].strip() != "":
        updated_lines.append("\n")

    def extern_close_missing(buf):
        search_window = 50 if len(buf) > 50 else len(buf)
        tail = "".join(buf[-search_window:])
        return not re.search(r"#ifdef\s+__cplusplus[\s\S]*?\}\s*\n\s*#endif", tail)

    if extern_close_missing(updated_lines):
        updated_lines.append("#ifdef __cplusplus\n")
        updated_lines.append("}\n")
        updated_lines.append("#endif\n\n")
    extern_open_idx = None
    for idx, line in enumerate(updated_lines):
        if line.strip().startswith("extern \"C\" {"):
            extern_open_idx = idx
            break
    if extern_open_idx is not None:
        found_close = False
        for look_ahead in range(1, 6):
            if extern_open_idx + look_ahead < len(updated_lines):
                if updated_lines[extern_open_idx + look_ahead].strip().startswith("#endif"):
                    found_close = True
                    break
        if not found_close:
            insertion_idx = extern_open_idx + 1
            updated_lines.insert(insertion_idx, "#endif\n\n")
    non_empty_ending_found = False
    filtered_ending_lines = []
    for line in ending_lines:
        if line.strip() != "" or non_empty_ending_found:
            filtered_ending_lines.append(line)
            non_empty_ending_found = True
        else:
            continue
    updated_lines.extend(filtered_ending_lines)
    if updated_lines and not updated_lines[-1].endswith('\n'):
        updated_lines[-1] += '\n'
    with open(header_file_path, 'w') as file:
        file.writelines(updated_lines)
    print(f"Updated header file with versioned syscall declarations")

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

    settings = QSettings('SysCaller', 'BuildTools')
    syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
    is_kernel_mode = syscall_mode == 'Zw'
    base_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..')
    if is_kernel_mode:
        asm_file = os.path.join(base_dir, 'SysCallerK', 'Wrapper', 'src', 'syscaller.asm')
    else:
        asm_file = os.path.join(base_dir, 'SysCaller', 'Wrapper', 'src', 'syscaller.asm')
    main_dll_path = os.getenv('NTDLL_PATH', "C:\\Windows\\System32\\ntdll.dll")
    dll_path_count = int(os.getenv('NTDLL_PATH_COUNT', '1'))
    syscall_tables = {}
    print(f"Processing primary ntdll: {main_dll_path}")
    syscall_tables[0] = get_syscalls(main_dll_path)
    for i in range(2, dll_path_count + 1):
        additional_dll_path = os.getenv(f'NTDLL_PATH_{i}')
        if additional_dll_path:
            print(f"Processing additional ntdll {i-1}: {additional_dll_path}")
            syscall_tables[i-1] = get_syscalls(additional_dll_path)
    update_syscalls(asm_file, syscall_tables)
