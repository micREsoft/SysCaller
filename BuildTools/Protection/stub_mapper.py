import random
import os
import re
from encryptor import get_encryption_method, encrypt_offset
from junkgen import generate_junk_instructions
from namer import generate_random_name, generate_random_offset_name, generate_random_offset
from stubgen import generate_masked_sequence, generate_chunked_sequence, generate_align_padding

try:
    from PyQt5.QtCore import QSettings
except ImportError:
    class QSettings:
        def __init__(self, *args):
            self.settings = {}
        def value(self, key, default, type=None):
            return default

def apply_custom_syscall_settings(syscall_name, real_offset, settings=None):
    global_settings = QSettings('SysCaller', 'BuildTools')
    if settings is None:
        syscall_settings = global_settings.value('stub_mapper/syscall_settings', {}, type=dict)
        if syscall_name in syscall_settings:
            settings = syscall_settings[syscall_name]
        else:
            settings = {
                'enable_junk': True,
                'min_instructions': global_settings.value('obfuscation/min_instructions', 2, int),
                'max_instructions': global_settings.value('obfuscation/max_instructions', 8, int),
                'use_advanced_junk': global_settings.value('obfuscation/use_advanced_junk', False, bool),
                'enable_encryption': global_settings.value('obfuscation/enable_encryption', True, bool),
                'encryption_method': global_settings.value('obfuscation/encryption_method', 1, int),
                'enable_chunking': global_settings.value('obfuscation/enable_chunking', True, bool),
                'enable_interleaved': global_settings.value('obfuscation/enable_interleaved', True, bool),
                'shuffle_sequence': global_settings.value('obfuscation/shuffle_sequence', True, bool),
                'syscall_prefix_length': global_settings.value('obfuscation/syscall_prefix_length', 8, int),
                'syscall_number_length': global_settings.value('obfuscation/syscall_number_length', 6, int),
                'offset_name_length': global_settings.value('obfuscation/offset_name_length', 8, int),
            }
    used_offsets = set()
    used_offset_names = set()
    fake_offset = generate_random_offset(used_offsets)
    offset_name = generate_random_offset_name(used_offset_names, length=settings.get('offset_name_length', 8))
    encryption_data = None
    encryption_method = settings.get('encryption_method', 1)
    if settings.get('enable_encryption', True):
        encrypted_offset, encryption_data = encrypt_offset(real_offset, encryption_method)
    else:
        encrypted_offset = real_offset
    chunked_sequence = None
    if settings.get('enable_chunking', True):
        chunked_sequence = generate_chunked_sequence(offset_name, encryption_data, encryption_method)
    return (fake_offset, offset_name, encryption_data, encryption_method, encrypted_offset, chunked_sequence)

def generate_custom_exports():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    asm_path = os.path.join(project_root, 'Wrapper', 'src', 'syscaller.asm')
    header_path = os.path.join(project_root, 'Wrapper', 'include', 'Sys', 'sysFunctions.h')
    settings = QSettings('SysCaller', 'BuildTools')
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
    syscall_settings = settings.value('stub_mapper/syscall_settings', {}, type=dict)
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
                        if current_syscall in syscall_settings:
                            name_settings = syscall_settings[current_syscall]
                            prefix_length = name_settings.get('syscall_prefix_length', 8)
                            number_length = name_settings.get('syscall_number_length', 6)
                        else:
                            prefix_length = settings.value('obfuscation/syscall_prefix_length', 8, int)
                            number_length = settings.value('obfuscation/syscall_number_length', 6, int)
                        syscall_map[current_syscall] = generate_random_name(
                            used_names, 
                            prefix_length=prefix_length, 
                            number_length=number_length
                        )
            elif in_stub:
                current_stub.append(line)
                if 'mov eax,' in line and current_syscall:
                    try:
                        offset_part = line.split('mov eax,')[1].split(';')[0].strip()
                        real_offset = int(offset_part[:-1], 16)
                        syscall_offsets[current_syscall] = real_offset
                        if current_syscall in syscall_settings:
                            custom_settings = syscall_settings[current_syscall]
                            fake_offset, offset_name, _, _, _, _ = apply_custom_syscall_settings(
                                current_syscall, 
                                real_offset, 
                                custom_settings
                            )
                            real_to_fake_offset[real_offset] = fake_offset
                            offset_name_map[fake_offset] = offset_name
                            used_offsets.add(fake_offset)
                            used_offset_names.add(offset_name)
                        elif real_offset not in real_to_fake_offset:
                            fake_offset = generate_random_offset(used_offsets)
                            offset_name = generate_random_offset_name(used_offset_names)
                            real_to_fake_offset[real_offset] = fake_offset
                            offset_name_map[fake_offset] = offset_name
                    except ValueError as e:
                        print(f"Error parsing offset for {current_syscall}: {e}")
                elif ' ENDP' in line:
                    in_stub = False
                    if use_all_syscalls or current_syscall in selected_syscalls:
                        syscall_stubs.append((current_syscall, current_stub))
    global_shuffle = settings.value('obfuscation/shuffle_sequence', True, bool)
    syscalls_to_shuffle = []
    syscalls_to_keep_order = []
    for syscall, stub in syscall_stubs:
        if syscall in syscall_settings and 'shuffle_sequence' in syscall_settings[syscall]:
            if syscall_settings[syscall]['shuffle_sequence']:
                syscalls_to_shuffle.append((syscall, stub))
            else:
                syscalls_to_keep_order.append((syscall, stub))
        elif global_shuffle:
            syscalls_to_shuffle.append((syscall, stub))
        else:
            syscalls_to_keep_order.append((syscall, stub))
    random.shuffle(syscalls_to_shuffle)
    syscall_stubs = syscalls_to_shuffle + syscalls_to_keep_order
    publics = []
    aliases = []
    for original, random_name in syscall_map.items():
        publics.append(f'PUBLIC {random_name}')
        aliases.append(f'ALIAS <{original}> = <{random_name}>')
    new_content = []
    data_section = ['.data\n']
    data_section.append('ALIGN 8\n')
    encryption_data_map = {}
    for syscall, real_offset in syscall_offsets.items():
        if syscall in selected_syscalls or use_all_syscalls:
            custom_settings = syscall_settings.get(syscall, None)
            fake_offset = real_to_fake_offset[real_offset]
            offset_name = offset_name_map[fake_offset]
            if custom_settings:
                enable_encryption = custom_settings.get('enable_encryption', True)
                encryption_method = custom_settings.get('encryption_method', 1)
            else:
                enable_encryption = settings.value('obfuscation/enable_encryption', True, bool)
                encryption_method = settings.value('obfuscation/encryption_method', 1, int)
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
        if original_syscall in syscall_settings:
            enable_interleaved = syscall_settings[original_syscall].get('enable_interleaved', True)
        else:
            enable_interleaved = settings.value('obfuscation/enable_interleaved', True, bool)
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
                        if syscall in syscall_settings:
                            enable_chunking = syscall_settings[syscall].get('enable_chunking', True)
                            encryption_method = syscall_settings[syscall].get('encryption_method', 1)
                        else:
                            enable_chunking = settings.value('obfuscation/enable_chunking', True, bool)
                            encryption_method = get_encryption_method()
                        encryption_data = encryption_data_map.get(offset_name)
                        if enable_chunking:
                            line = generate_chunked_sequence(offset_name, encryption_data, encryption_method)
                        else:
                            if encryption_data:
                                line = f'    mov eax, {offset_name}\n'
                            else:
                                line = f'    mov eax, {offset_name}\n'
                        break
            if original_syscall in syscall_settings and 'enable_junk' in syscall_settings[original_syscall]:
                custom_settings = syscall_settings[original_syscall]
                if custom_settings['enable_junk'] and ('ret' in line or 'syscall' in line):
                    min_inst = custom_settings.get('min_instructions', 2)
                    max_inst = custom_settings.get('max_instructions', 8)
                    use_advanced = custom_settings.get('use_advanced_junk', False)
                    junk = generate_junk_instructions(min_inst, max_inst, use_advanced)
                    if junk:
                        new_content.append(line)
                        new_content.extend(junk)
                        continue
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
    header_part_ended = False
    for i, line in enumerate(header_content):
        if any(line == end_line for end_line in ending_lines):
            continue
        if not header_part_ended and (
            f'extern "C" NTSTATUS {syscall_prefix}' in line or 
            f'extern "C" ULONG {syscall_prefix}' in line or
            'extern "C" NTSTATUS SC' in line or
            'extern "C" ULONG SC' in line
        ):
            header_part_ended = True
        if not header_part_ended:
            if "_WIN64" in line and "#ifdef" in line:
                new_header_content.append(line)
                new_header_content.append("\n")
                continue
            new_header_content.append(line)
            continue
        if (
            'extern "C" NTSTATUS SC' in line or 
            'extern "C" ULONG SC' in line or
            f'extern "C" NTSTATUS {syscall_prefix}' in line or 
            f'extern "C" ULONG {syscall_prefix}' in line
        ):
            match = re.search(rf'extern "C" (?:NTSTATUS|ULONG) ((?:SC|{syscall_prefix})\w+)\(', line)
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
    print(f"Generated {len(syscall_map)} unique syscalls with custom obfuscation settings")
    print(f"Applied stub_mapper settings to syscalls")

if __name__ == "__main__":
    generate_custom_exports()
