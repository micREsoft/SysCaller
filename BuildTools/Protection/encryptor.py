import random
from PyQt5.QtCore import QSettings

def get_encryption_method():
    settings = QSettings('SysCaller', 'BuildTools')
    return settings.value('obfuscation/encryption_method', 1, int)

def encrypt_offset(real_offset, method=1):
    if method == 1: # Basic XOR
        key = random.randint(0x11, 0xFF)
        encrypted_offset = real_offset ^ key
        return encrypted_offset, {"key": key}
    elif method == 2: # Multi Key XOR
        key1 = random.randint(0x11, 0xFF)
        key2 = random.randint(0x11, 0xFF)
        encrypted_offset = (real_offset ^ key1) ^ key2
        return encrypted_offset, {"key1": key1, "key2": key2}
    elif method == 3: # Add + XOR combination
        add_val = random.randint(0x100, 0xFFF)
        xor_key = random.randint(0x11, 0xFF)
        encrypted_offset = (real_offset + add_val) ^ xor_key
        return encrypted_offset, {"add_val": add_val, "xor_key": xor_key}
    elif method == 4: # Enhanced XOR
        xor_key = random.randint(0x1000, 0xFFFF)
        encrypted_offset = real_offset ^ xor_key
        return encrypted_offset, {"xor_key": xor_key}
    elif method == 5: # Offset Shifting
        mask = random.randint(0x100, 0xFFF)
        encrypted_offset = (real_offset + mask) & 0xFFFFFFFF
        return encrypted_offset, {"mask": mask}
    key = random.randint(0x11, 0xFF) # default to basic XOR if invalid
    encrypted_offset = real_offset ^ key
    return encrypted_offset, {"key": key}

def generate_decryption_sequence(offset_name, encryption_data, method=1):
    if method == 1: # Basic XOR
        return [
            f"    mov eax, dword ptr [{offset_name}]\n",
            f"    mov ebx, 0{encryption_data['key']:X}h\n",
            f"    xor eax, ebx\n"
        ]
    elif method == 2: # Multi Key XOR
        return [
            f"    mov eax, dword ptr [{offset_name}]\n",
            f"    mov ebx, 0{encryption_data['key1']:X}h\n",
            f"    xor eax, ebx\n",
            f"    mov ebx, 0{encryption_data['key2']:X}h\n",
            f"    xor eax, ebx\n"
        ]
    elif method == 3: # Add + XOR combination
        return [
            f"    mov eax, dword ptr [{offset_name}]\n",
            f"    mov ebx, 0{encryption_data['xor_key']:X}h\n",
            f"    xor eax, ebx\n",
            f"    sub eax, 0{encryption_data['add_val']:X}h\n"
        ]
    elif method == 4: # Enhanced XOR
        xor_key = encryption_data['xor_key']
        return [
            f"    mov eax, dword ptr [{offset_name}]\n",
            f"    mov ebx, 0{xor_key:X}h\n",
            f"    xor eax, ebx\n"
        ]
    elif method == 5: # Offset Shifting
        mask = encryption_data['mask']
        return [
            f"    mov eax, dword ptr [{offset_name}]\n",
            f"    sub eax, 0{mask:X}h\n"
        ]
    return [ # default to basic XOR if invalid
        f"    mov eax, dword ptr [{offset_name}]\n",
        f"    mov ebx, 0{encryption_data['key']:X}h\n",
        f"    xor eax, ebx\n"
    ] 
