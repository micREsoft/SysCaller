import random
import string
from PyQt5.QtCore import QSettings

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def generate_random_name(used_names, prefix_length=None, number_length=None):
    settings = QSettings('SysCaller', 'BuildTools')
    if prefix_length is None:
        prefix_length = settings.value('obfuscation/syscall_prefix_length', 8, type=int)
    if number_length is None:
        number_length = settings.value('obfuscation/syscall_number_length', 6, type=int)
    while True:
        prefix = generate_random_string(prefix_length)
        number = str(random.randint(10**(number_length-1), (10**number_length)-1))
        name = f'{prefix}_{number}'
        if name not in used_names:
            used_names.add(name)
            return name

def generate_random_offset_name(used_names, length=None):
    settings = QSettings('SysCaller', 'BuildTools')
    if length is None:
        length = settings.value('obfuscation/offset_name_length', 8, type=int)
    while True:
        name = generate_random_string(length)
        if name not in used_names:
            used_names.add(name)
            return name

def generate_random_offset(used_offsets):
    while True:
        offset = random.randint(0x1000, 0xFFFF)
        if offset not in used_offsets:
            used_offsets.add(offset)
            return offset

def generate_random_label():
    return generate_random_string(8)