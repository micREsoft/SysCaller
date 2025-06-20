import random
from PyQt5.QtCore import QSettings
from encryption.encryptor import generate_decryption_sequence
from stub.junkgen import generate_junk_instructions
from stub.namer import generate_random_label

def generate_masked_sequence(offset_name, encryption_data=None, method=1):
    settings = QSettings('SysCaller', 'BuildTools')
    enable_encryption = settings.value('obfuscation/enable_encryption', True, bool)
    mov_r10_rcx_variants = [
        "    lea r10, [rcx]\n",
        "    push rcx\n    pop r10\n",
        "    mov r11, rcx\n    xchg r10, r11\n"
    ]
    if enable_encryption and encryption_data is not None:
        syscall_sequence = generate_decryption_sequence(offset_name, encryption_data, method)
    else:
        mov_eax_offset_variants = [
            f"    xor eax, eax\n    add eax, dword ptr [{offset_name}]\n",
            f"    mov ebx, dword ptr [{offset_name}]\n    xchg eax, ebx\n"
        ]
        syscall_sequence = [random.choice(mov_eax_offset_variants)]
    syscall_variants = [
        "    syscall\n",
    ]
    sequence = [
        random.choice(mov_r10_rcx_variants),
        generate_junk_instructions(),
        ''.join(syscall_sequence),
        generate_junk_instructions(),
        random.choice(syscall_variants),
        "    ret\n"
    ]
    return ''.join(sequence)

def generate_chunked_sequence(offset_name, encryption_data=None, method=1):
    settings = QSettings('SysCaller', 'BuildTools')
    enable_chunking = settings.value('obfuscation/enable_chunking', True, bool)
    enable_encryption = settings.value('obfuscation/enable_encryption', True, bool)
    if not enable_chunking:
        return generate_masked_sequence(offset_name, encryption_data, method)
    entry_label = generate_random_label()
    middle_label = generate_random_label()
    exit_label = generate_random_label()
    if enable_encryption and encryption_data is not None:
        syscall_sequence = generate_decryption_sequence(offset_name, encryption_data, method)
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
