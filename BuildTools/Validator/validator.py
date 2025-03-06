import pefile
import re
import capstone
import os

def update_syscalls(asm_file, syscall_numbers):
    asm_file_path = os.path.join(os.path.dirname(__file__), '..', '..', 'Wrapper', 'src', 'syscaller.asm')
    with open(asm_file_path, 'r') as file:  # open the file for reading
        lines = file.readlines()
    updated_lines = []
    for line in lines:
        proc_match = re.search(r"(Sys\w+)\s+PROC", line)
        if proc_match:
            syscall_name = proc_match.group(1)
            expected_nt_name = "Nt" + syscall_name[3:]
            expected_zw_name = "Zw" + syscall_name[3:]
            syscall_id = syscall_numbers.get(expected_nt_name, syscall_numbers.get(expected_zw_name, None)) # get syscall id from ntdll
            if syscall_id is not None:
                print(f"Updating {syscall_name} with syscall ID: 0x{syscall_id:X}")
                updated_lines.append(line)
            else:
                print(f"Warning: No matching syscall ID found for {syscall_name}")
                updated_lines.append(line)
            continue
        if "<syscall_id>" in line: # replace <syscall_id> with actual syscall id
            if syscall_id is not None:
                updated_lines.append(line.replace("<syscall_id>", f"0{syscall_id:X}"))
            else:
                updated_lines.append(line)
        else:
            updated_lines.append(line)
    with open(asm_file, 'w') as file: # write & update syscaller.asm
        file.writelines(updated_lines)
    
    print(f"Updated syscalls written to {asm_file}")

def get_syscalls(dll_path):
    pe = pefile.PE(dll_path)
    syscall_numbers = {}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64) # setup/initialize disassembler
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols: # read export directory
        if not export.name:
            continue
        func_name = export.name.decode()
        func_rva = export.address
        func_bytes = pe.get_data(func_rva, 16) # read first 16 bytes of function
        for instruction in md.disasm(func_bytes, func_rva): # disassemble function
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
    dll_path = "C:\\Windows\\System32\\ntdll.dll"
    syscall_numbers = get_syscalls(dll_path)
    update_syscalls(asm_file, syscall_numbers)
