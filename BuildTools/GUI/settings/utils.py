import os
import re
import shutil
import json
import hashlib
from datetime import datetime
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtCore import QSettings

def format_timestamp(timestamp):
    try:
        if '_' in timestamp:
            date_part, time_part = timestamp.split('_')
            year = date_part[:4]
            month = date_part[4:6]
            day = date_part[6:8]
            hour = time_part[:2]
            minute = time_part[2:4]
            return f"{year}-{month}-{day} {hour}:{minute}"
        return timestamp
    except:
        return timestamp

def get_project_paths():
    settings_dir = os.path.dirname(os.path.abspath(__file__))
    gui_dir = os.path.dirname(settings_dir)
    buildtools_dir = os.path.dirname(gui_dir)
    project_root = os.path.dirname(buildtools_dir)
    backups_dir = os.path.join(project_root, 'Backups')
    hash_backups_dir = os.path.join(project_root, 'Backups', 'Hashes')
    default_dir = os.path.join(buildtools_dir, 'Default')
    try:
        from PyQt5.QtCore import QSettings
        settings = QSettings('SysCaller', 'BuildTools')
        syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
        is_kernel_mode = syscall_mode == 'Zw'
    except ImportError:
        is_kernel_mode = False
    if is_kernel_mode:
        asm_path = os.path.join(project_root, 'SysCallerK', 'Wrapper', 'src', 'syscaller.asm')
        header_path = os.path.join(project_root, 'SysCallerK', 'Wrapper', 'include', 'SysK', 'sysFunctions_k.h')
        default_asm_path = os.path.join(default_dir, 'syscaller.asm')
        default_header_path = os.path.join(default_dir, 'sysFunctions_k.h')
    else:
        asm_path = os.path.join(project_root, 'SysCaller', 'Wrapper', 'src', 'syscaller.asm')
        header_path = os.path.join(project_root, 'SysCaller', 'Wrapper', 'include', 'Sys', 'sysFunctions.h')
        default_asm_path = os.path.join(default_dir, 'syscaller.asm')
        default_header_path = os.path.join(default_dir, 'sysFunctions.h')
    # DEBUG print(f"Project paths:")
    # DEBUG print(f"  Project root: {project_root}")
    # DEBUG print(f"  BuildTools dir: {buildtools_dir}")
    # DEBUG print(f"  Backups dir: {backups_dir}")
    # DEBUG print(f"  Hash backups dir: {hash_backups_dir}")
    # DEBUG print(f"  Default dir: {default_dir}")
    # DEBUG print(f"  ASM path: {asm_path}")
    # DEBUG print(f"  Header path: {header_path}")
    return {
        'project_root': project_root,
        'buildtools_dir': buildtools_dir,
        'backups_dir': backups_dir,
        'hash_backups_dir': hash_backups_dir,
        'default_dir': default_dir,
        'asm_path': asm_path,
        'header_path': header_path,
        'default_asm_path': default_asm_path,
        'default_header_path': default_header_path,
        'is_kernel_mode': is_kernel_mode
    }

def create_backup(parent, settings):
    paths = get_project_paths()
    backups_dir = paths['backups_dir']
    asm_path = paths['asm_path']
    header_path = paths['header_path']
    if not os.path.exists(backups_dir):
        os.makedirs(backups_dir)
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_asm_path = os.path.join(backups_dir, f'syscaller_{timestamp}.asm')
    backup_header_path = os.path.join(backups_dir, f'sysFunctions_{timestamp}.h')
    try:
        shutil.copy2(asm_path, backup_asm_path)
        shutil.copy2(header_path, backup_header_path)
        print(f"Backup created at: {backups_dir}")
        return True, timestamp
    except Exception as e:
        print(f"Warning: Could not create backup: {e}")
        QMessageBox.warning(parent, "Backup Failed", 
                          f"Could not create backup files: {str(e)}")
        return False, None

def get_available_backups():
    paths = get_project_paths()
    backups_dir = paths['backups_dir']
    if not os.path.exists(backups_dir):
        return {}
    all_files = os.listdir(backups_dir)
    backup_asm_files = [f for f in all_files if f.startswith('syscaller_') and f.endswith('.asm')]
    backup_header_files = [f for f in all_files if f.startswith('sysFunctions_') and f.endswith('.h')]
    # DEBUG print(f"Found {len(backup_asm_files)} ASM backups and {len(backup_header_files)} header backups")
    backup_timestamps = {}
    for asm_file in backup_asm_files:
        try:
            timestamp = asm_file[10:-4]
            backup_timestamps[timestamp] = {'asm': asm_file}
            # DEBUG print(f"Found ASM backup with timestamp: {timestamp}")
        except Exception as e:
            print(f"Error processing ASM file {asm_file}: {e}")
            continue
    for header_file in backup_header_files:
        try:
            if header_file.startswith('sysFunctions_') and len(header_file) > 15:
                timestamp = header_file[13:-2]
                if timestamp in backup_timestamps:
                    backup_timestamps[timestamp]['header'] = header_file
                    # DEBUG print(f"Matched header file {header_file} with timestamp {timestamp}")
                    continue
            matched = False
            for ts in backup_timestamps.keys():
                if ts in header_file:
                    backup_timestamps[ts]['header'] = header_file
                    # DEBUG print(f"Matched header file {header_file} with timestamp {ts} (by substring)")
                    matched = True
                    break
            if not matched:
                print(f"Could not match header file: {header_file}")
        except Exception as e:
            print(f"Error processing header file {header_file}: {e}")
            continue
    complete_backups = {ts: files for ts, files in backup_timestamps.items() 
                      if 'asm' in files and 'header' in files}
    # DEBUG print(f"Found {len(complete_backups)} complete backup sets")
    return complete_backups 

def generate_stub_hashes(asm_file_path, header_file_path=None, obfuscation_method=None):
    try:
        from PyQt5.QtCore import QSettings
        settings = QSettings('SysCaller', 'BuildTools')
        using_stub_mapper = False
        if obfuscation_method:
            using_stub_mapper = (obfuscation_method == 'stub_mapper')
        else:
            force_stub_mapper = settings.value('obfuscation/force_stub_mapper', False, bool)
            force_normal = settings.value('obfuscation/force_normal', False, bool)
            syscall_settings = settings.value('stub_mapper/syscall_settings', {}, type=dict)
            using_stub_mapper = force_stub_mapper or (bool(syscall_settings) and not force_normal)
        syscall_settings = settings.value('stub_mapper/syscall_settings', {}, type=dict)
        if using_stub_mapper and syscall_settings:
            config = {
                "obfuscation_method": "Stub Mapper",
                "global_settings": {
                    "junk_instructions": {
                        "min": settings.value('obfuscation/min_instructions', 2, int),
                        "max": settings.value('obfuscation/max_instructions', 8, int),
                        "advanced": settings.value('obfuscation/use_advanced_junk', False, bool)
                    },
                    "name_randomization": {
                        "prefix_length": settings.value('obfuscation/syscall_prefix_length', 8, int),
                        "number_length": settings.value('obfuscation/syscall_number_length', 6, int),
                        "offset_length": settings.value('obfuscation/offset_name_length', 8, int)
                    },
                    "sequence_shuffling": settings.value('obfuscation/shuffle_sequence', True, bool),
                    "encryption": {
                        "enabled": settings.value('obfuscation/enable_encryption', True, bool),
                        "method": settings.value('obfuscation/encryption_method', 1, int)
                    },
                    "function_chunking": settings.value('obfuscation/enable_chunking', True, bool),
                    "interleaved_execution": settings.value('obfuscation/enable_interleaved', True, bool)
                },
                "syscall_specific_settings": {}
            }
            for syscall_name, custom_settings in syscall_settings.items():
                config["syscall_specific_settings"][syscall_name] = custom_settings
        else:
            config = {
                "obfuscation_method": "Normal",
                "junk_instructions": {
                    "min": settings.value('obfuscation/min_instructions', 2, int),
                    "max": settings.value('obfuscation/max_instructions', 8, int),
                    "advanced": settings.value('obfuscation/use_advanced_junk', False, bool)
                },
                "name_randomization": {
                    "prefix_length": settings.value('obfuscation/syscall_prefix_length', 8, int),
                    "number_length": settings.value('obfuscation/syscall_number_length', 6, int),
                    "offset_length": settings.value('obfuscation/offset_name_length', 8, int)
                },
                "sequence_shuffling": settings.value('obfuscation/shuffle_sequence', True, bool),
                "encryption": {
                    "enabled": settings.value('obfuscation/enable_encryption', True, bool),
                    "method": settings.value('obfuscation/encryption_method', 1, int)
                },
                "function_chunking": settings.value('obfuscation/enable_chunking', True, bool),
                "interleaved_execution": settings.value('obfuscation/enable_interleaved', True, bool)
            }
        stub_hashes = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "config": config,
            "stubs": {}
        }
        if os.path.exists(asm_file_path):
            with open(asm_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                asm_content = f.read()
            alias_pattern = re.compile(r'ALIAS\s+<(Sys[A-Za-z0-9_]+)>\s*=\s*<([A-Za-z0-9_]+)>', re.IGNORECASE)
            aliases = alias_pattern.findall(asm_content)
            obfuscated_to_syscall = {obfuscated: syscall for syscall, obfuscated in aliases}
            proc_pattern = re.compile(r'([A-Za-z0-9_]+)\s+PROC', re.IGNORECASE)
            procs = proc_pattern.findall(asm_content)
            for proc_name in procs:
                if proc_name not in obfuscated_to_syscall:
                    continue
                syscall_name = obfuscated_to_syscall[proc_name]
                stub_start_pattern = re.compile(f"{proc_name}\\s+PROC.*?\\n", re.IGNORECASE)
                stub_end_pattern = re.compile(f"{proc_name}\\s+ENDP", re.IGNORECASE)
                start_match = stub_start_pattern.search(asm_content)
                end_match = stub_end_pattern.search(asm_content)
                if start_match and end_match:
                    stub_code = asm_content[start_match.start():end_match.end()]
                    md5_hash = hashlib.md5(stub_code.encode('utf-8')).hexdigest()
                    sha256_hash = hashlib.sha256(stub_code.encode('utf-8')).hexdigest()
                    stub_hashes["stubs"][syscall_name] = {
                        "md5": md5_hash,
                        "sha256": sha256_hash,
                        "size": len(stub_code),
                        "obfuscated_name": proc_name
                    }
                    if using_stub_mapper and syscall_name in syscall_settings:
                        stub_hashes["stubs"][syscall_name]["custom_config"] = syscall_settings[syscall_name]
        if header_file_path and os.path.exists(header_file_path):
            with open(header_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                header_content = f.read()
            func_pattern = re.compile(r'EXTERN_C\s+(?:__kernel_entry\s+)?(?:NTSYSCALLAPI\s+)?(?:NTSTATUS|BOOL|VOID|HANDLE|PVOID|ULONG|.*?)\s+(?:NTAPI|WINAPI)?\s*(Sys[A-Za-z0-9_]+)\s*\(([^;]*)\);', re.IGNORECASE)
            funcs = func_pattern.findall(header_content)
            for name, params in funcs:
                if name in stub_hashes["stubs"]:
                    stub_hashes["stubs"][name]["header_hash"] = hashlib.sha256(params.encode('utf-8')).hexdigest()
                    stub_hashes["stubs"][name]["params"] = params.strip()
        return stub_hashes
    except Exception as e:
        print(f"Error generating stub hashes: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

def save_stub_hashes(stub_hashes, timestamp=None):
    try:
        paths = get_project_paths()
        hash_backups_dir = paths['hash_backups_dir']
        if not os.path.exists(hash_backups_dir):
            os.makedirs(hash_backups_dir)
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(hash_backups_dir, f'stub_hashes_{timestamp}.json')
        formatted_output = {
            "timestamp": stub_hashes["timestamp"],
            "config": stub_hashes["config"],
            "stubs": {}
        }
        for syscall_name, hash_data in stub_hashes["stubs"].items():
            formatted_output["stubs"][syscall_name] = f"MD5: {hash_data['md5']} SHA-256: {hash_data['sha256']}"
        all_hashes = []
        for syscall_name, hash_data in sorted(stub_hashes["stubs"].items()):
            all_hashes.append(f"{syscall_name}:{hash_data['md5']}:{hash_data['sha256']}")
        build_id_input = ":".join(all_hashes) + str(stub_hashes["config"])
        build_id = hashlib.sha256(build_id_input.encode('utf-8')).hexdigest()
        formatted_output["build_id"] = build_id
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(formatted_output, f, indent=2)
        # DEBUG print(f"Stub Hashes saved to: {json_path}")
        return True, json_path
    except Exception as e:
        print(f"Error saving stub hashes: {e}")
        import traceback
        traceback.print_exc()
        return False, str(e) 
