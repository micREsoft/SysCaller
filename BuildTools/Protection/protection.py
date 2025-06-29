import random
import os
import re
import mapping.stub_mapper as stub_mapper
from encryption.encryptor import get_encryption_method, encrypt_offset
from stub.junkgen import generate_junk_instructions
from stub.namer import generate_random_name, generate_random_offset_name, generate_random_offset
from stub.stubgen import generate_masked_sequence, generate_chunked_sequence, generate_align_padding

try:
    from PyQt5.QtCore import QSettings
except ImportError:
    class QSettings:
        def __init__(self, *args):
            self.settings = {}
        def value(self, key, default, type):
            return default

def extract_syscall_offset(line):
    offset_part = line.split('mov eax,')[1].split(';')[0].strip()
    return int(offset_part[:-1], 16)

def generate_exports():
    settings = QSettings('SysCaller', 'BuildTools')
    syscall_settings = settings.value('stub_mapper/syscall_settings', {}, type=dict)
    force_normal = settings.value('obfuscation/force_normal', False, type=bool)
    force_stub_mapper = settings.value('obfuscation/force_stub_mapper', False, type=bool)
    if force_stub_mapper or (syscall_settings and not force_normal):
        try:
            # DEBUG print("Using Stub Mapper obfuscation mode...")
            stub_mapper.generate_custom_exports()
            return
        except Exception as e:
            print(f"Warning: Error using stub_mapper: {e}")
            print("Falling back to standard obfuscation.")
    # DEBUG print("Using Normal obfuscation mode...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
    is_kernel_mode = syscall_mode == 'Zw'
    if is_kernel_mode:
        asm_path = os.path.join(project_root, 'SysCallerK', 'Wrapper', 'src', 'syscaller.asm')
        header_path = os.path.join(project_root, 'SysCallerK', 'Wrapper', 'include', 'SysK', 'sysFunctions_k.h')
    else:
        asm_path = os.path.join(project_root, 'SysCaller', 'Wrapper', 'src', 'syscaller.asm')
        header_path = os.path.join(project_root, 'SysCaller', 'Wrapper', 'include', 'Sys', 'sysFunctions.h')
    selected_syscalls = settings.value('integrity/selected_syscalls', [], type=list)
    use_all_syscalls = len(selected_syscalls) == 0
    syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
    syscall_prefix = "Sys" if syscall_mode == "Nt" else "SysK"
    used_names = set()
    used_offsets = set()
    used_offset_names = set()
    offset_name_map = {}  # Maps fake offset to random name
    syscall_map = {}  # Maps original syscall to random name
    syscall_offsets = {}  # Maps original syscall to its offset
    real_to_fake_offset = {}  # Maps real offset to fake offset
    syscall_stubs = []
    current_stub = []
    with open(asm_path, 'r') as f:
        content = f.readlines()
        in_stub = False
        current_syscall = None
        for line in content:
            proc_match = re.search(r"((?:SC|Sys|SysK)\w+)\s+PROC", line)
            if proc_match:
                current_syscall = proc_match.group(1)
                if current_syscall.startswith("SC"):
                    current_syscall = syscall_prefix + current_syscall[2:] 
                in_stub = True
                current_stub = [line]
                if use_all_syscalls or current_syscall in selected_syscalls:
                    if current_syscall not in syscall_map:
                        syscall_map[current_syscall] = generate_random_name(used_names)
            elif in_stub:
                current_stub.append(line)
                if 'mov eax,' in line and current_syscall:
                    try:
                        real_offset = extract_syscall_offset(line)
                        syscall_offsets[current_syscall] = real_offset
                        if real_offset not in real_to_fake_offset:
                            real_to_fake_offset[real_offset] = generate_random_offset(used_offsets)
                    except ValueError as e:
                        print(f"Error parsing offset for {current_syscall}: {e}")
                elif ' ENDP' in line:
                    in_stub = False
                    if use_all_syscalls or current_syscall in selected_syscalls:
                        syscall_stubs.append((current_syscall, current_stub))
    settings = QSettings('SysCaller', 'BuildTools')
    shuffle_sequence = settings.value('obfuscation/shuffle_sequence', True, bool)
    if shuffle_sequence:
        random.shuffle(syscall_stubs)
    publics = []
    aliases = []
    for original, random_name in syscall_map.items():
        publics.append(f'PUBLIC {random_name}')
        aliases.append(f'ALIAS <{original}> = <{random_name}>')
    new_content = []
    data_section = ['.data\n']
    data_section.append('ALIGN 8\n')
    settings = QSettings('SysCaller', 'BuildTools')
    enable_encryption = settings.value('obfuscation/enable_encryption', True, bool)
    enable_interleaved = settings.value('obfuscation/enable_interleaved', True, bool)
    encryption_method = get_encryption_method()
    encryption_data_map = {}
    for real_offset, fake_offset in real_to_fake_offset.items():
        offset_name = generate_random_offset_name(used_offset_names)
        offset_name_map[fake_offset] = offset_name
        if enable_encryption:
            encrypted_offset, encryption_data = encrypt_offset(real_offset, encryption_method)
            encryption_data_map[offset_name] = encryption_data
            data_section.append(f'{offset_name} dd 0{encrypted_offset:X}h  ; Encrypted syscall ID (method {encryption_method})\n')
        else:
            data_section.append(f'{offset_name} dd 0{real_offset:X}h\n')
    new_content.append('.code\n\n')
    new_content.append('; Public declarations\n' + '\n'.join(publics) + '\n\n')
    new_content.append('; Export aliases\n' + '\n'.join(aliases) + '\n\n')
    for original_syscall, stub_lines in syscall_stubs:
        if enable_interleaved:
            new_content.append(generate_align_padding())
        for line in stub_lines:
            if ' PROC' in line or ' ENDP' in line:
                syscall_match = re.search(r"((?:SC|Sys|SysK)\w+)\s+(?:PROC|ENDP)", line)
                if syscall_match:
                    syscall = syscall_match.group(1)
                    if syscall.startswith("SC"):
                        syscall = syscall_prefix + syscall[2:]
                    if syscall in syscall_map:
                        line = re.sub(r"(SC|Sys|SysK)(\w+)\s+(PROC|ENDP)", 
                                     lambda m: f"{syscall_map[syscall]} {m.group(3)}", 
                                     line)
            elif 'mov eax,' in line and 'syscall' in ''.join(stub_lines):
                for syscall, offset in syscall_offsets.items():
                    if syscall == original_syscall:
                        fake_offset = real_to_fake_offset[offset]
                        offset_name = offset_name_map[fake_offset]
                        encryption_data = encryption_data_map.get(offset_name) if enable_encryption else None
                        line = generate_chunked_sequence(offset_name, encryption_data, encryption_method)
                        break
            new_content.append(line)
        if enable_interleaved:
            new_content.append(generate_align_padding())
    new_content.append('\nend\n')
    for i, line in enumerate(new_content):
        if '.code' in line:
            new_content[i:i] = data_section
            break
    with open(asm_path, 'w') as f:
        f.writelines(new_content)
    all_syscalls = []
    all_header_lines = []
    current_block = []
    in_block = False
    current_syscall = None
    with open(header_path, 'r') as f:
        header_content = f.readlines()
    new_header_content = []
    skip_block = False
    ending_lines = []
    for i in range(len(header_content)-1, -1, -1):
        line = header_content[i].strip()
        if line == "#endif" or line.startswith("#endif "):
            ending_lines.insert(0, header_content[i])
            j = i - 1
            while j >= 0 and (header_content[j].strip() == "" or header_content[j].strip().startswith("//")):
                ending_lines.insert(0, header_content[j])
                j -= 1
            break
    has_extern_c_block = False
    for line in header_content:
        if "#ifdef __cplusplus" in line and "extern" in line and "{" in line:
            has_extern_c_block = True
            break
        if "#ifdef __cplusplus" in line and any("extern" in l and "{" in l for l in header_content[header_content.index(line)+1:header_content.index(line)+5]):
            has_extern_c_block = True
            break
    header_part_ended = False
    for i, line in enumerate(header_content):
        if any(line == end_line for end_line in ending_lines):
            continue
        if not header_part_ended and (
            f'NTSTATUS {syscall_prefix}' in line or 
            f'ULONG {syscall_prefix}' in line or
            f'BOOLEAN {syscall_prefix}' in line or
            f'VOID {syscall_prefix}' in line or
            'NTSTATUS SC' in line or
            'ULONG SC' in line or
            'BOOLEAN SC' in line or
            'VOID SC' in line or
            "#ifdef __cplusplus" in line
        ):
            header_part_ended = True
        if not header_part_ended:
            if "_WIN64" in line and "#ifdef" in line:
                new_header_content.append(line)
                new_header_content.append("\n")
                continue
            new_header_content.append(line)
            continue
        if "#ifdef __cplusplus" in line or 'extern "C"' in line or line.strip() == "{" or line.strip() == "}" or "#endif" in line:
            continue
        if (
            'NTSTATUS SC' in line or 
            'ULONG SC' in line or
            'BOOLEAN SC' in line or
            'VOID SC' in line or
            f'NTSTATUS {syscall_prefix}' in line or 
            f'ULONG {syscall_prefix}' in line or
            f'BOOLEAN {syscall_prefix}' in line or
            f'VOID {syscall_prefix}' in line
        ):
            match = re.search(rf'extern "C" (?:NTSTATUS|ULONG|BOOLEAN|VOID) ((?:SC|{syscall_prefix})\w+)\(', line)
            if not match:
                match = re.search(rf'(?:NTSTATUS|ULONG|BOOLEAN|VOID) ((?:SC|{syscall_prefix})\w+)\(', line)
            if match:
                original_name = match.group(1)
                if original_name.startswith("SC"):
                    current_syscall = syscall_prefix + original_name[2:]
                else:
                    current_syscall = original_name
                if use_all_syscalls or current_syscall in selected_syscalls:
                    skip_block = False
                    if current_syscall in syscall_map:
                        line = line.replace(original_name, syscall_map[current_syscall])
                    line = re.sub(r'extern\s+"C"\s+', '', line)
                    new_header_content.append(line)
                else:
                    skip_block = True
                continue
        if not skip_block:
            if "SC" in line:
                updated_line = re.sub(r'\bSC(\w+)\b', fr'{syscall_prefix}\1', line)
                new_header_content.append(updated_line)
            else:
                new_header_content.append(line)
        elif line.strip() == ");":
            skip_block = False
    function_part_start = None
    function_part_end = None
    for i, line in enumerate(new_header_content):
        if any(t in line for t in ["NTSTATUS", "ULONG", "BOOLEAN", "VOID"]) and "(" in line:
            if function_part_start is None:
                function_part_start = i             
        if line.strip() == ");" and function_part_start is not None:
            function_part_end = i
    if function_part_start is not None and function_part_end is not None:
        new_header_content.insert(function_part_start, "\n")
        new_header_content.insert(function_part_start, "#ifdef __cplusplus\nextern \"C\" {\n#endif\n")
        function_part_end += 4
        new_header_content.insert(function_part_end + 1, "\n#ifdef __cplusplus\n}\n#endif\n")
    new_header_content.append("\n// Syscall name mappings\n")
    for original, random_name in syscall_map.items():
        new_header_content.append(f"#define {original} {random_name}\n")
    cleaned_header_content = []
    prev_empty = False
    for line in new_header_content:
        if line.strip() == "":
            if not prev_empty:
                cleaned_header_content.append(line)
                prev_empty = True
        else:
            cleaned_header_content.append(line)
            prev_empty = False
    if ending_lines:
        if cleaned_header_content and cleaned_header_content[-1].strip() != "":
            cleaned_header_content.append("\n")
        non_empty_ending_found = False
        filtered_ending_lines = []
        for line in ending_lines:
            if line.strip() != "" or non_empty_ending_found:
                filtered_ending_lines.append(line)
                non_empty_ending_found = True
            else:
                continue
        cleaned_header_content.extend(filtered_ending_lines)
    if cleaned_header_content and not cleaned_header_content[-1].endswith('\n'):
        cleaned_header_content[-1] += '\n'
    with open(header_path, 'w') as f:
        f.writelines(cleaned_header_content)
    print(f"Generated {len(syscall_map)} unique syscalls with obfuscated names, offsets, and junk instructions")
    if shuffle_sequence:
        print("Syscall sequence has been randomized")

if __name__ == "__main__":
    generate_exports()
