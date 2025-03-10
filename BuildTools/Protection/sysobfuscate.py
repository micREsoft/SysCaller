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

def generate_junk_instructions():
    settings = QSettings('SysCaller', 'BuildTools')
    min_inst = settings.value('obfuscation/min_instructions', 2, int)
    max_inst = settings.value('obfuscation/max_instructions', 8, int)
    use_advanced = settings.value('obfuscation/use_advanced_junk', False, bool)
    junk_instructions = [
        "    nop\n",
        "    xchg rax, rax\n",
        "    xchg rbx, rbx\n",
        "    xchg rcx, rcx\n",
        "    xchg rdx, rdx\n",
        "    xchg rsi, rsi\n",
        "    xchg rdi, rdi\n",
        "    push r11\n    pop r11\n",
        "    push r12\n    pop r12\n",
        "    push r13\n    pop r13\n",
        "    push r14\n    pop r14\n",
        "    push r15\n    pop r15\n",
        "    pushfq\n    popfq\n",
        "    test r12, r12\n",
        "    test r13, r13\n",
        "    test r14, r14\n",
        "    test r15, r15\n",
        "    lea r12, [r12]\n",
        "    lea r13, [r13]\n",
        "    lea r14, [r14]\n",
        "    lea r15, [r15]\n",
        "    mov r8, r8\n",
        "    mov r9, r9\n",
        "    mov r10, r10\n",
        "    mov r11, r11\n",
        "    mov r15, r15\n",
    ]
    if use_advanced:
        advanced_junk = [ ## WIP IGNORE FOR NOW
            "    mov r12, r12",
        ]
        junk_instructions.extend(random.choices(advanced_junk, k=random.randint(2, 8)))
    return ''.join(random.choices(junk_instructions, k=random.randint(min_inst, max_inst)))

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
    with open(asm_path, 'r') as f:
        current_syscall = None
        for line in f:
            if ' PROC' in line:
                current_syscall = line.split()[0]
                if current_syscall not in syscall_map:
                    syscall_map[current_syscall] = generate_random_name(used_names)
            elif 'mov eax,' in line and current_syscall:
                try:
                    real_offset = extract_syscall_offset(line)
                    syscall_offsets[current_syscall] = real_offset
                    if real_offset not in real_to_fake_offset:
                        real_to_fake_offset[real_offset] = generate_random_offset(used_offsets)
                except ValueError as e:
                    print(f"Error parsing offset for {current_syscall}: {e}")
                    continue
    publics = []
    aliases = []
    for original, random_name in syscall_map.items():
        publics.append(f'PUBLIC {random_name}')
        aliases.append(f'ALIAS <{original}> = <{random_name}>')
    with open(asm_path, 'r') as f:
        content = f.readlines()
    new_content = []
    data_section = ['.data\n']
    data_section.append('ALIGN 8\n')
    for real_offset, fake_offset in real_to_fake_offset.items():
        offset_name = generate_random_offset_name(used_offset_names)
        offset_name_map[fake_offset] = offset_name
        data_section.append(f'{offset_name} dd 0{real_offset:X}h\n')
    for line in content:
        if ' PROC' in line or ' ENDP' in line:
            syscall = line.split()[0]
            if syscall in syscall_map:
                line = line.replace(syscall, syscall_map[syscall])
        elif 'mov eax,' in line and 'syscall' in ''.join(content[content.index(line):content.index(line)+3]):
            for syscall, offset in syscall_offsets.items():
                if syscall in ''.join(content[max(0,content.index(line)-2):content.index(line)]):
                    fake_offset = real_to_fake_offset[offset]
                    offset_name = offset_name_map[fake_offset]
                    new_stub = [
                        "    mov r10, rcx\n",
                        generate_junk_instructions(),
                        f"    mov eax, dword ptr [{offset_name}]\n",
                        generate_junk_instructions(),
                        "    syscall\n",
                        "    ret\n"
                    ]
                    line = ''.join(new_stub)
                    break
        new_content.append(line)
    for i, line in enumerate(new_content):
        if '.code' in line:
            new_content[i:i] = data_section
            break
    for i, line in enumerate(new_content):
        if '.code' in line:
            new_content.insert(i + 1, '\n; Public declarations\n' + 
                '\n'.join(publics) + '\n\n; Export aliases\n' + 
                '\n'.join(aliases) + '\n\n')
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
if __name__ == "__main__":
    generate_exports() 
