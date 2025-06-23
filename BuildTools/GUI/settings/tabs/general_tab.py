import os
import shutil
import time
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                           QGroupBox, QPushButton, QRadioButton, QButtonGroup, 
                           QCheckBox, QMessageBox, QMenu)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

from settings.utils import format_timestamp, get_project_paths, create_backup, get_available_backups

def is_file_locked(file_path):
    if not os.path.exists(file_path):
        return False
    try:
        with open(file_path, 'r+') as f:
            pass
        return False
    except IOError:
        try:
            temp_file = file_path + ".tmp"
            os.rename(file_path, temp_file)
            os.rename(temp_file, file_path)
            return False
        except:
            return True

class GeneralTab(QWidget):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        syscall_mode_group = QGroupBox("Syscall Mode")
        syscall_mode_layout = QVBoxLayout()
        description = QLabel("Select which syscall mode to use. This affects how syscalls are generated and processed.")
        description.setWordWrap(True)
        syscall_mode_layout.addWidget(description)
        self.mode_button_group = QButtonGroup(self)
        self.nt_mode_radio = QRadioButton("Nt Mode (User Mode)")
        self.nt_mode_radio.setToolTip("Use Nt prefix for syscalls (default for user-mode applications)")
        self.zw_mode_radio = QRadioButton("Zw Mode (Kernel Mode)")
        self.zw_mode_radio.setToolTip("Use Zw prefix for syscalls (primarily used in kernel-mode drivers)")
        current_mode = self.settings.value('general/syscall_mode', 'Nt', str)
        if current_mode == 'Zw':
            self.zw_mode_radio.setChecked(True)
        else:
            self.nt_mode_radio.setChecked(True)
        self.mode_button_group.addButton(self.nt_mode_radio)
        self.mode_button_group.addButton(self.zw_mode_radio)
        syscall_mode_layout.addWidget(self.nt_mode_radio)
        syscall_mode_layout.addWidget(self.zw_mode_radio)
        syscall_mode_group.setLayout(syscall_mode_layout)
        layout.addWidget(syscall_mode_group)
        hash_stubs_group = QGroupBox("Hash Stubs")
        hash_stubs_layout = QVBoxLayout()
        description = QLabel("Optionally hash each stub/build with unique hash for future lookups.")
        description.setWordWrap(True)
        hash_stubs_layout.addWidget(description)
        self.hash_stubs = QCheckBox("Enable Hash Stubs")
        self.hash_stubs.setChecked(self.settings.value('general/hash_stubs', False, bool))
        self.hash_stubs.setToolTip("If checked, will generate hashes for all stubs after obfuscation and save them to a JSON file in the Backups directory")
        hash_stubs_layout.addWidget(self.hash_stubs)
        hash_stubs_group.setLayout(hash_stubs_layout)
        layout.addWidget(hash_stubs_group)
        reset_group = QGroupBox("Reset to Default/Backup")
        reset_layout = QVBoxLayout()
        description = QLabel("Reset Syscaller to it's default state or restore from a backup. This will revert any changes made by obfuscation or manual editing.")
        description.setWordWrap(True)
        reset_layout.addWidget(description)
        restore_btn = QPushButton("Restore Files")
        restore_btn.setMinimumHeight(40)
        restore_btn.setIcon(QIcon("GUI/icons/reset.png"))
        restore_btn.clicked.connect(self.show_restore_options)
        reset_layout.addWidget(restore_btn)
        self.create_backup = QCheckBox("Create Backup")
        self.create_backup.setChecked(self.settings.value('general/create_backup', True, bool))
        self.create_backup.setToolTip("If checked, will create backup files in the Backups directory before restoring defaults")
        reset_layout.addWidget(self.create_backup)
        reset_group.setLayout(reset_layout)
        layout.addWidget(reset_group)
        layout.addStretch()
        
    def save_settings(self):
        self.settings.setValue('general/create_backup', self.create_backup.isChecked())
        self.settings.setValue('general/hash_stubs', self.hash_stubs.isChecked())
        if self.zw_mode_radio.isChecked():
            self.settings.setValue('general/syscall_mode', 'Zw')
        else:
            self.settings.setValue('general/syscall_mode', 'Nt')
        if self.create_backup.isChecked():
            paths = get_project_paths()
            backups_dir = paths['backups_dir']
            if not os.path.exists(backups_dir):
                try:
                    os.makedirs(backups_dir)
                except Exception as e:
                    print(f"Warning: Could not create Backups directory: {e}")
    
    def show_restore_options(self):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #333333;
                color: white;
                border: 1px solid #444444;
                border-radius: 5px;
                padding: 5px;
            }
            QMenu::item {
                background-color: transparent;
                padding: 8px 20px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #0b5394;
            }
        """)
        default_action = menu.addAction(QIcon("GUI/icons/reset.png"), "Restore Default Files")
        default_action.triggered.connect(self.restore_default_files)
        complete_backups = get_available_backups()
        if complete_backups:
            sorted_timestamps = sorted(complete_backups.keys(), reverse=True)
            if len(sorted_timestamps) > 1:
                backup_submenu = QMenu("Select Backup", menu)
                backup_submenu.setStyleSheet(menu.styleSheet())
                latest_ts = sorted_timestamps[0]
                latest_date = format_timestamp(latest_ts)
                backup_action = menu.addAction(QIcon("GUI/icons/reset.png"), f"Restore Latest Backup ({latest_date})")
                backup_action.triggered.connect(lambda: self.restore_backup(latest_ts))
                for ts in sorted_timestamps:
                    date_str = format_timestamp(ts)
                    action = backup_submenu.addAction(f"Backup from {date_str}")
                    action.triggered.connect(lambda checked, timestamp=ts: self.restore_backup(timestamp))
                menu.addMenu(backup_submenu)
            else:
                ts = sorted_timestamps[0]
                date_str = format_timestamp(ts)
                backup_action = menu.addAction(QIcon("GUI/icons/reset.png"), f"Restore Backup ({date_str})")
                backup_action.triggered.connect(lambda: self.restore_backup(ts))
        else:
            backup_action = menu.addAction("No Backups Available")
            backup_action.setEnabled(False)
        menu.exec_(self.mapToGlobal(self.sender().rect().bottomLeft()))
    
    def restore_default_files(self):
        reply = QMessageBox.question(self, "SysCaller v1.1.0", 
                                    "Are you sure you want to restore default files?\nThis will overwrite your current syscaller.asm and sysFunctions.h files.",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return
        try:
            paths = get_project_paths()
            default_asm_path = os.path.join(paths['default_dir'], 'syscaller.asm')
            default_header_path = os.path.join(paths['default_dir'], 'sysFunctions.h')
            asm_path = paths['asm_path']
            header_path = paths['header_path']
            if not os.path.exists(default_asm_path) or not os.path.exists(default_header_path):
                QMessageBox.warning(self, "Missing Default Files", 
                                   "Default files not found in BuildTools/Default directory.")
                return
            if self.create_backup.isChecked():
                self.settings.setValue('general/create_backup', True)
                create_backup(self, self.settings)
            else:
                self.settings.setValue('general/create_backup', False)
            shutil.copy2(default_asm_path, asm_path)
            shutil.copy2(default_header_path, header_path)
            QMessageBox.information(self, "SysCaller v1.1.0", 
                                   "Default files have been restored successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred while restoring default files: {str(e)}")
    
    def restore_backup(self, timestamp):
        try:
            paths = get_project_paths()
            backups_dir = paths['backups_dir']
            complete_backups = get_available_backups()
            if timestamp not in complete_backups:
                QMessageBox.warning(self, "Missing Backup Files", 
                                  f"Could not find complete backup set for timestamp {timestamp}")
                return
            backup_info = complete_backups[timestamp]
            backup_asm_path = os.path.join(backups_dir, backup_info['asm'])
            backup_header_path = os.path.join(backups_dir, backup_info['header'])
            missing_files = []
            if not os.path.exists(backup_asm_path):
                missing_files.append(f"ASM file: {backup_asm_path}")
            if not os.path.exists(backup_header_path):
                missing_files.append(f"Header file: {backup_header_path}")
            if missing_files:
                QMessageBox.warning(self, "Missing Backup Files", 
                                  f"Could not find the following backup files:\n" + "\n".join(missing_files))
                return
            reply = QMessageBox.question(self, "SysCaller v1.1.0", 
                                        f"Are you sure you want to restore from backup files dated {format_timestamp(timestamp)}?\n"
                                        "This will overwrite your current syscaller.asm and sysFunctions.h files.",
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return
            asm_path = paths['asm_path']
            header_path = paths['header_path']
            asm_dir = os.path.dirname(asm_path)
            header_dir = os.path.dirname(header_path)
            if not os.path.exists(asm_dir):
                os.makedirs(asm_dir, exist_ok=True)
                print(f"Created ASM directory: {asm_dir}")
            if not os.path.exists(header_dir):
                os.makedirs(header_dir, exist_ok=True)
                print(f"Created header directory: {header_dir}")
            if os.path.exists(asm_path):
                if is_file_locked(asm_path):
                    print(f"WARNING: ASM file is locked by another process: {asm_path}")
                    QMessageBox.warning(self, "File Locked", 
                                      f"The ASM file appears to be locked by another process. Close any applications that might be using it and try again.")
                elif not os.access(asm_path, os.W_OK):
                    print(f"WARNING: ASM file exists but is not writable: {asm_path}")
                    try:
                        os.chmod(asm_path, 0o666)
                        print(f"Changed permissions on ASM file to make it writable")
                    except Exception as e:
                        print(f"Failed to change permissions: {e}")
            if os.path.exists(header_path):
                if is_file_locked(header_path):
                    print(f"WARNING: Header file is locked by another process: {header_path}")
                    QMessageBox.warning(self, "File Locked", 
                                      f"The header file appears to be locked by another process. Close any applications that might be using it and try again.")
                elif not os.access(header_path, os.W_OK):
                    print(f"WARNING: Header file exists but is not writable: {header_path}")
                    try:
                        os.chmod(header_path, 0o666)
                        print(f"Changed permissions on header file to make it writable")
                    except Exception as e:
                        print(f"Failed to change permissions: {e}")
            if self.create_backup.isChecked():
                self.settings.setValue('general/create_backup', True)
                create_backup(self, self.settings)
            print(f"Restoring ASM file from {backup_asm_path} to {asm_path}")
            asm_restored = False
            max_retries = 3
            retry_count = 0
            while not asm_restored and retry_count < max_retries:
                try:
                    with open(backup_asm_path, 'rb') as src_file:
                        asm_content = src_file.read()
                        print(f"Read {len(asm_content)} bytes from ASM backup file")
                    with open(asm_path, 'wb') as dst_file:
                        dst_file.write(asm_content)
                        print(f"Wrote {len(asm_content)} bytes to ASM destination file")
                    if os.path.exists(asm_path):
                        file_size = os.path.getsize(asm_path)
                        print(f"Verified ASM file exists with size: {file_size} bytes")
                        if file_size > 0:
                            asm_restored = True
                        else:
                            print(f"WARNING: ASM file was created but is empty at {asm_path}")
                    else:
                        print(f"ERROR: ASM file was not created at {asm_path}")
                    if not asm_restored:
                        print(f"Trying alternative method for ASM file (shutil.copy2)")
                        shutil.copy2(backup_asm_path, asm_path)
                        if os.path.exists(asm_path) and os.path.getsize(asm_path) > 0:
                            print(f"Alternative method succeeded for ASM file")
                            asm_restored = True
                        else:
                            print(f"Trying system command for ASM file")
                            import subprocess
                            try:
                                cmd = f'copy "{backup_asm_path}" "{asm_path}" /Y'
                                print(f"Running command: {cmd}")
                                subprocess.run(cmd, shell=True, check=True)
                                
                                if os.path.exists(asm_path) and os.path.getsize(asm_path) > 0:
                                    print(f"System command succeeded for ASM file")
                                    asm_restored = True
                            except Exception as e:
                                print(f"System command failed: {e}")
                except Exception as e:
                    retry_count += 1
                    print(f"ERROR restoring ASM file (attempt {retry_count}/{max_retries}): {e}")
                    import traceback
                    traceback.print_exc()
                    if retry_count < max_retries:
                        print(f"Retrying in 1 second...")
                        time.sleep(1)
                    else:
                        QMessageBox.warning(self, "Restore Error", f"Failed to restore ASM file after {max_retries} attempts: {str(e)}")
            print(f"Restoring Header file from {backup_header_path} to {header_path}")
            header_restored = False
            retry_count = 0
            while not header_restored and retry_count < max_retries:
                try:
                    with open(backup_header_path, 'rb') as src_file:
                        header_content = src_file.read()
                        print(f"Read {len(header_content)} bytes from header backup file")
                    with open(header_path, 'wb') as dst_file:
                        dst_file.write(header_content)
                        print(f"Wrote {len(header_content)} bytes to header destination file")
                    if os.path.exists(header_path):
                        file_size = os.path.getsize(header_path)
                        print(f"Verified header file exists with size: {file_size} bytes")
                        if file_size > 0:
                            header_restored = True
                        else:
                            print(f"WARNING: Header file was created but is empty at {header_path}")
                    else:
                        print(f"ERROR: Header file was not created at {header_path}")
                    if not header_restored:
                        print(f"Trying alternative method for header file (shutil.copy2)")
                        shutil.copy2(backup_header_path, header_path)
                        if os.path.exists(header_path) and os.path.getsize(header_path) > 0:
                            print(f"Alternative method succeeded for header file")
                            header_restored = True
                        else:
                            print(f"Trying system command for header file")
                            import subprocess
                            try:
                                cmd = f'copy "{backup_header_path}" "{header_path}" /Y'
                                print(f"Running command: {cmd}")
                                subprocess.run(cmd, shell=True, check=True)
                                if os.path.exists(header_path) and os.path.getsize(header_path) > 0:
                                    print(f"System command succeeded for header file")
                                    header_restored = True
                            except Exception as e:
                                print(f"System command failed: {e}")
                except Exception as e:
                    retry_count += 1
                    print(f"ERROR restoring header file (attempt {retry_count}/{max_retries}): {e}")
                    import traceback
                    traceback.print_exc()
                    if retry_count < max_retries:
                        print(f"Retrying in 1 second...")
                        time.sleep(1)
                    else:
                        QMessageBox.warning(self, "Restore Error", f"Failed to restore header file after {max_retries} attempts: {str(e)}")
            asm_restored = os.path.exists(asm_path) and os.path.getsize(asm_path) > 0
            header_restored = os.path.exists(header_path) and os.path.getsize(header_path) > 0
            if asm_restored and header_restored:
                QMessageBox.information(self, "SysCaller v1.1.0", 
                                      f"Files have been restored from backup successfully!\nBackup date: {format_timestamp(timestamp)}")
            elif not asm_restored and header_restored:
                QMessageBox.warning(self, "Partial Restore", 
                                   f"Only the header file was restored successfully. The ASM file could not be restored.")
            elif asm_restored and not header_restored:
                QMessageBox.warning(self, "Partial Restore", 
                                   f"Only the ASM file was restored successfully. The header file could not be restored.")
            else:
                QMessageBox.critical(self, "Restore Failed", 
                                    f"Failed to restore both files from backup.")
        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Error", f"An error occurred while restoring backup files: {str(e)}") 
