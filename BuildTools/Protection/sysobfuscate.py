import random
import string
import os
try:
    from PyQt5.QtCore import QSettings
except ImportError:
    class QSettings:
        def __init__(self, *args):
            self.settings = {}
        def value(self, key, default, type):
            return default

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def generate_random_name(used_names):
    settings = QSettings('SysCaller', 'BuildTools')
    prefix_length = settings.value('obfuscation/syscall_prefix_length', 8, type=int)
    number_length = settings.value('obfuscation/syscall_number_length', 6, type=int)
    
    while True:
        prefix = generate_random_string(prefix_length)
        number = str(random.randint(10**(number_length-1), (10**number_length)-1))
        name = f'{prefix}_{number}'
        if name not in used_names:
            used_names.add(name)
            return name

def generate_random_offset_name(used_names):
    settings = QSettings('SysCaller', 'BuildTools')
    name_length = settings.value('obfuscation/offset_name_length', 8, type=int)
    while True:
        name = generate_random_string(name_length)
        if name not in used_names:
            used_names.add(name)
            return name

def generate_random_offset(used_offsets):
    while True:
        offset = random.randint(0x1000, 0xFFFF)
        if offset not in used_offsets:
            used_offsets.add(offset)
            return offset

def extract_syscall_offset(line):
    offset_part = line.split('mov eax,')[1].split(';')[0].strip()
    return int(offset_part[:-1], 16)

def generate_masked_sequence(offset_name, encryption_key=None):
    settings = QSettings('SysCaller', 'BuildTools')
    enable_encryption = settings.value('obfuscation/enable_encryption', True, bool)
    mov_r10_rcx_variants = [
        "    lea r10, [rcx]\n",
        "    push rcx\n    pop r10\n",
        "    mov r11, rcx\n    xchg r10, r11\n"
    ]
    if enable_encryption and encryption_key is not None:
        mov_eax_offset_variants = [
            f"    mov eax, dword ptr [{offset_name}]\n"
            f"    mov ebx, 0{encryption_key:X}h\n"
            f"    xor eax, ebx\n"
        ]
    else:
        mov_eax_offset_variants = [
            f"    xor eax, eax\n    add eax, dword ptr [{offset_name}]\n",
            f"    mov ebx, dword ptr [{offset_name}]\n    xchg eax, ebx\n"
        ]
    syscall_variants = [
        "    syscall\n",
    ]
    sequence = [
        random.choice(mov_r10_rcx_variants),
        generate_junk_instructions(),
        mov_eax_offset_variants[0],
        generate_junk_instructions(),
        random.choice(syscall_variants),
        "    ret\n"
    ]
    return ''.join(sequence)

def generate_junk_instructions():
    settings = QSettings('SysCaller', 'BuildTools')
    min_inst = settings.value('obfuscation/min_instructions', 2, int)
    max_inst = settings.value('obfuscation/max_instructions', 8, int)
    use_advanced = settings.value('obfuscation/use_advanced_junk', False, bool)
    junk_instructions = [
        "    nop\n",
        "    xchg r8, r8\n",
        "    xchg r9, r9\n",
        "    xchg r10, r10\n",
        "    xchg r11, r11\n",
        "    xchg r12, r12\n",
        "    xchg r13, r13\n",
        "    xchg r14, r14\n",
        "    xchg r15, r15\n",
        "    xchg rax, rax\n",
        "    xchg rbx, rbx\n",
        "    xchg rcx, rcx\n",
        "    xchg rdx, rdx\n",
        "    xchg rsi, rsi\n",
        "    xchg rdi, rdi\n",
        "    push r8\n    pop r8\n",
        "    push r9\n    pop r9\n",
        "    push r10\n    pop r10\n",
        "    push r11\n    pop r11\n",
        "    push r12\n    pop r12\n",
        "    push r13\n    pop r13\n",
        "    push r14\n    pop r14\n",
        "    push r15\n    pop r15\n",
        "    pushfq\n    popfq\n",
        "    test r8, r8\n",
        "    test r9, r9\n",
        "    test r10, r10\n",
        "    test r11, r11\n",
        "    test r12, r12\n",
        "    test r13, r13\n",
        "    test r14, r14\n",
        "    test r15, r15\n",
        "    lea r8, [r8]\n",
        "    lea r9, [r9]\n",
        "    lea r10, [r10]\n",
        "    lea r11, [r11]\n",
        "    lea r12, [r12]\n",
        "    lea r13, [r13]\n",
        "    lea r14, [r14]\n",
        "    lea r15, [r15]\n",
        "    mov r8, r8\n",
        "    mov r9, r9\n",
        "    mov r10, r10\n",
        "    mov r11, r11\n",
        "    mov r12, r12\n",
        "    mov r13, r13\n",
        "    mov r14, r14\n",
        "    mov r15, r15\n",
    ]
    if use_advanced:
        advanced_junk = [ # (STILL WIP DO NOT USE)
            "    test r8, r8\n",
        ]
        junk_instructions.extend(random.choices(advanced_junk, k=random.randint(2, 8)))
    return ''.join(random.choices(junk_instructions, k=random.randint(min_inst, max_inst)))

def generate_random_label():
    return generate_random_string(8)

def generate_chunked_sequence(offset_name, encryption_key=None):
    settings = QSettings('SysCaller', 'BuildTools')
    enable_chunking = settings.value('obfuscation/enable_chunking', True, bool)
    enable_encryption = settings.value('obfuscation/enable_encryption', True, bool)
    if not enable_chunking:
        return generate_masked_sequence(offset_name, encryption_key)
    entry_label = generate_random_label()
    middle_label = generate_random_label()
    exit_label = generate_random_label()
    if enable_encryption and encryption_key is not None:
        syscall_sequence = [
            f"    mov eax, dword ptr [{offset_name}]\n",
            f"    mov ebx, 0{encryption_key:X}h\n",
            f"    xor eax, ebx\n"
        ]
    else:
        syscall_sequence = [
            f"    xor eax, eax\n    add eax, dword ptr [{offset_name}]\n"
        ]
    chunks = [
        f"{entry_label}:\n"
        f"    mov r10, rcx\n"
        f"    {generate_junk_instructions()}\n"
        f"    jmp {middle_label}\n",
        
        f"{middle_label}:\n"
        f"    {''.join(syscall_sequence)}"
        f"    {generate_junk_instructions()}\n"
        f"    jmp {exit_label}\n",
        
        f"{exit_label}:\n"
        f"    syscall\n"
        f"    {generate_junk_instructions()}\n"
        f"    ret\n"
    ]
    entry = chunks[0]
    rest = chunks[1:]
    random.shuffle(rest)
    chunks = [entry] + rest
    return ''.join(chunks)

def generate_align_padding():
    align_size = random.choice([4, 8, 16])
    padding = []
    for _ in range(random.randint(1, 3)):
        padding.append(generate_junk_instructions())
    padding.append(f"ALIGN {align_size}\n")
    return ''.join(padding)

def generate_exports():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    asm_path = os.path.join(project_root, 'Wrapper', 'src', 'syscaller.asm')
    header_path = os.path.join(project_root, 'Wrapper', 'include', 'Nt', 'sysNtFunctions.h')
    used_names = set()
    used_offsets = set()
    used_offset_names = set()
    offset_name_map = {}
    syscall_map = {}
    syscall_offsets = {}
    real_to_fake_offset = {}
    syscall_stubs = []
    current_stub = []
    with open(asm_path, 'r') as f:
        content = f.readlines()
        in_stub = False
        current_syscall = None
        for line in content:
            if ' PROC' in line:
                current_syscall = line.split()[0]
                in_stub = True
                current_stub = [line]
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
    encryption_keys = {}
    for real_offset, fake_offset in real_to_fake_offset.items():
        offset_name = generate_random_offset_name(used_offset_names)
        offset_name_map[fake_offset] = offset_name
        if enable_encryption:
            encryption_key = random.randint(0x11, 0xFF)
            encryption_keys[offset_name] = encryption_key
            encrypted_offset = real_offset ^ encryption_key
            data_section.append(f'{offset_name} dd 0{encrypted_offset:X}h  ; Encrypted syscall ID\n')
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
                syscall = line.split()[0]
                if syscall in syscall_map:
                    line = line.replace(syscall, syscall_map[syscall])
            elif 'mov eax,' in line and 'syscall' in ''.join(stub_lines):
                for syscall, offset in syscall_offsets.items():
                    if syscall == original_syscall:
                        fake_offset = real_to_fake_offset[offset]
                        offset_name = offset_name_map[fake_offset]
                        encryption_key = encryption_keys.get(offset_name) if enable_encryption else None
                        line = generate_chunked_sequence(offset_name, encryption_key)
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
    with open(header_path, 'r') as f:
        header_content = f.readlines()
    new_header_content = []
    for line in header_content:
        if line.startswith('extern "C" NTSTATUS Sys'):
            syscall = line.split('NTSTATUS ')[1].split('(')[0].strip()
            if syscall in syscall_map:
                line = line.replace(syscall, syscall_map[syscall])
        new_header_content.append(line)
    new_header_content.append("\n// Syscall name mappings\n")
    for original, random_name in syscall_map.items():
        new_header_content.append(f"#define {original} {random_name}\n")
    with open(header_path, 'w') as f:
        f.writelines(new_header_content)
    print(f"Generated {len(syscall_map)} unique syscalls with obfuscated names, offsets, and junk instructions")
    if shuffle_sequence:
        print("Syscall sequence has been randomized")
if __name__ == "__main__":
    generate_exports()
