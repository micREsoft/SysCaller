import os
import re
import shutil
from PyQt5.QtWidgets import QMessageBox

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
    default_dir = os.path.join(buildtools_dir, 'Default')
    asm_path = os.path.join(project_root, 'Wrapper', 'src', 'syscaller.asm')
    header_path = os.path.join(project_root, 'Wrapper', 'include', 'Sys', 'sysFunctions.h')
    # DEBUG print(f"Project paths:")
    # DEBUG print(f"  Project root: {project_root}")
    # DEBUG print(f"  BuildTools dir: {buildtools_dir}")
    # DEBUG print(f"  Backups dir: {backups_dir}")
    # DEBUG print(f"  Default dir: {default_dir}")
    # DEBUG print(f"  ASM path: {asm_path}")
    # DEBUG print(f"  Header path: {header_path}")
    return {
        'project_root': project_root,
        'buildtools_dir': buildtools_dir,
        'backups_dir': backups_dir,
        'default_dir': default_dir,
        'asm_path': asm_path,
        'header_path': header_path
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
