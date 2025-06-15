from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                            QSpinBox, QFrame, QPushButton, QTabWidget,
                            QWidget, QCheckBox, QGroupBox, QFormLayout,
                            QScrollArea, QListWidget, QListWidgetItem, QLineEdit,
                            QMessageBox, QRadioButton, QButtonGroup, QComboBox)
from PyQt5.QtCore import Qt, QSettings
from PyQt5.QtGui import QIcon, QFont
import os
import re
import pefile
import shutil

class SysCallerSettings(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SysCaller v1.1.0")
        self.setMinimumWidth(500)
        self.setMinimumHeight(600)
        self.setStyleSheet("""
            QDialog {
                background: #252525;
                color: white;
            }
            QTabWidget::pane {
                border: 1px solid #333333;
                border-radius: 5px;
                background: #1E1E1E;
            }
            QTabBar::tab {
                background: #333333;
                color: white;
                padding: 8px 20px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background: #0b5394;
            }
            QGroupBox {
                border: 1px solid #333333;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
                color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QSpinBox {
                background: #333333;
                border: none;
                border-radius: 3px;
                padding: 5px;
                color: white;
            }
            QPushButton {
                background: #0b5394;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                color: white;
            }
            QPushButton:hover {
                background: #67abdb;
            }
            QCheckBox, QRadioButton {
                color: white;
            }
            QLabel {
                color: white;
            }
            QListWidget {
                background: #333333;
                color: white;
                border-radius: 5px;
                padding: 5px;
            }
            QLineEdit {
                background: #333333;
                border: 1px solid #444444;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        self.settings = QSettings('SysCaller', 'BuildTools')
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        tabs = QTabWidget()
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)
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
        general_layout.addWidget(syscall_mode_group)
        reset_group = QGroupBox("Reset to Default")
        reset_layout = QVBoxLayout()
        description = QLabel("Reset Syscaller to it's default state. This will revert any changes made by obfuscation or manual editing.")
        description.setWordWrap(True)
        reset_layout.addWidget(description)
        default_btn = QPushButton("Restore Default Files")
        default_btn.setMinimumHeight(40)
        default_btn.setIcon(QIcon("GUI/icons/reset.png"))
        default_btn.clicked.connect(self.restore_default_files)
        reset_layout.addWidget(default_btn)
        self.create_backup = QCheckBox("Create Backup")
        self.create_backup.setChecked(self.settings.value('general/create_backup', True, bool))
        self.create_backup.setToolTip("If checked, will create backup files in the Backups directory before restoring defaults")
        reset_layout.addWidget(self.create_backup)
        reset_group.setLayout(reset_layout)
        general_layout.addWidget(reset_group)
        general_layout.addStretch()
        obfuscation_tab = QWidget()
        obfuscation_layout = QVBoxLayout(obfuscation_tab)
        junk_group = QGroupBox("Junk Instructions")
        junk_layout = QFormLayout()
        self.min_instructions = QSpinBox()
        self.min_instructions.setRange(1, 10)
        self.min_instructions.setValue(self.settings.value('obfuscation/min_instructions', 2, int))
        self.max_instructions = QSpinBox()
        self.max_instructions.setRange(1, 20)
        self.max_instructions.setValue(self.settings.value('obfuscation/max_instructions', 8, int))
        junk_layout.addRow("Minimum Instructions:", self.min_instructions)
        junk_layout.addRow("Maximum Instructions:", self.max_instructions)
        self.use_advanced_junk = QCheckBox("Advanced Junk Instructions")
        self.use_advanced_junk.setChecked(self.settings.value('obfuscation/use_advanced_junk', False, bool))
        junk_layout.addRow(self.use_advanced_junk)
        junk_group.setLayout(junk_layout)
        obfuscation_layout.addWidget(junk_group)
        name_group = QGroupBox("Name Randomization")
        name_layout = QFormLayout()
        syscall_prefix_layout = QHBoxLayout()
        self.syscall_prefix_length = QSpinBox()
        self.syscall_prefix_length.setRange(4, 16)
        prefix_length = self.settings.value('obfuscation/syscall_prefix_length', 8, type=int)
        self.syscall_prefix_length.setToolTip("Length of the syscall prefix in the syscall stub")
        self.syscall_prefix_length.setValue(prefix_length)
        self.syscall_number_length = QSpinBox()
        self.syscall_number_length.setRange(4, 16)
        number_length = self.settings.value('obfuscation/syscall_number_length', 6, type=int)
        self.syscall_number_length.setToolTip("Length of the syscall number in the syscall stub")
        self.syscall_number_length.setValue(number_length)
        syscall_prefix_layout.addWidget(QLabel("Chars:"))
        syscall_prefix_layout.addWidget(self.syscall_prefix_length)
        syscall_prefix_layout.addWidget(QLabel("Numbers:"))
        syscall_prefix_layout.addWidget(self.syscall_number_length)
        name_layout.addRow("Syscall Name Length:", syscall_prefix_layout)
        self.offset_name_length = QSpinBox()
        self.offset_name_length.setRange(4, 16)
        offset_length = self.settings.value('obfuscation/offset_name_length', 8, type=int)
        self.offset_name_length.setValue(offset_length)
        self.offset_name_length.setToolTip("Length of the offset name in the syscall stub")
        name_layout.addRow("Offset Name Length:", self.offset_name_length)
        name_group.setLayout(name_layout)
        obfuscation_layout.addWidget(name_group)
        sequence_group = QGroupBox("Sequence Shuffling")
        sequence_layout = QFormLayout()
        self.shuffle_sequence = QCheckBox("Enable Sequence Shuffling")
        self.shuffle_sequence.setChecked(self.settings.value('obfuscation/shuffle_sequence', True, bool))
        self.shuffle_sequence.setToolTip("Randomize the order of syscall stubs in the assembly file")
        sequence_layout.addRow(self.shuffle_sequence)
        sequence_group.setLayout(sequence_layout)
        obfuscation_layout.addWidget(sequence_group)
        encryption_group = QGroupBox("Syscall Encryption")
        encryption_layout = QFormLayout()
        self.enable_encryption = QCheckBox("Enable Syscall ID Encryption")
        self.enable_encryption.setChecked(self.settings.value('obfuscation/enable_encryption', True, bool))
        self.enable_encryption.setToolTip("Encrypt syscall IDs in the data section to make static analysis harder")
        encryption_layout.addRow(self.enable_encryption)
        self.encryption_method = QComboBox()
        self.encryption_method.addItem("Basic XOR (Simple)", 1)
        self.encryption_method.addItem("Multi-key XOR (Medium)", 2)
        self.encryption_method.addItem("Add + XOR (Medium)", 3)
        self.encryption_method.addItem("Enhanced XOR (Strong)", 4)
        self.encryption_method.addItem("Offset Shifting (Strong)", 5)
        current_method = self.settings.value('obfuscation/encryption_method', 1, int)
        index = self.encryption_method.findData(current_method)
        if index >= 0:
            self.encryption_method.setCurrentIndex(index)
        self.encryption_method.setToolTip("Select the encryption method to use for syscall ID obfuscation")
        encryption_layout.addRow("Encryption Method:", self.encryption_method)
        encryption_group.setLayout(encryption_layout)
        obfuscation_layout.addWidget(encryption_group)
        chunking_group = QGroupBox("Function Chunking")
        chunking_layout = QFormLayout()
        self.enable_chunking = QCheckBox("Enable Function Chunking")
        self.enable_chunking.setChecked(self.settings.value('obfuscation/enable_chunking', True, bool))
        self.enable_chunking.setToolTip("Split syscall stubs into multiple fragments to make analysis harder")
        chunking_layout.addRow(self.enable_chunking)
        chunking_group.setLayout(chunking_layout)
        obfuscation_layout.addWidget(chunking_group)
        interleaved_group = QGroupBox("Interleaved Execution")
        interleaved_layout = QFormLayout()
        self.enable_interleaved = QCheckBox("Enable Interleaved Execution")
        self.enable_interleaved.setChecked(self.settings.value('obfuscation/enable_interleaved', True, bool))
        self.enable_interleaved.setToolTip("Mix code from different syscalls using ALIGN directives and random padding")
        interleaved_layout.addRow(self.enable_interleaved)
        interleaved_group.setLayout(interleaved_layout)
        obfuscation_layout.addWidget(interleaved_group)
        obfuscation_layout.addStretch()
        integrity_tab = QWidget()
        integrity_layout = QVBoxLayout(integrity_tab)
        syscall_group = QGroupBox("Syscall Selection")
        syscall_group.setToolTip("Select which syscalls to include in the final build")
        syscall_layout = QVBoxLayout()
        description = QLabel("Select the syscalls to include in the final build. Only selected syscalls will be processed during integrity checks and included in the final build!")
        description.setWordWrap(True)
        syscall_layout.addWidget(description)
        select_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all_syscalls)
        select_none_btn = QPushButton("Select None")
        select_none_btn.clicked.connect(self.select_no_syscalls)
        self.syscall_filter = QLineEdit()
        self.syscall_filter.setPlaceholderText("Filter syscalls...")
        self.syscall_filter.textChanged.connect(self.filter_syscalls)
        select_layout.addWidget(select_all_btn)
        select_layout.addWidget(select_none_btn)
        select_layout.addWidget(self.syscall_filter)
        syscall_layout.addLayout(select_layout)
        self.syscall_list = QListWidget()
        self.syscall_list.setSelectionMode(QListWidget.NoSelection)
        self.load_syscalls()
        syscall_layout.addWidget(self.syscall_list)
        syscall_group.setLayout(syscall_layout)
        integrity_layout.addWidget(syscall_group)
        tabs.addTab(general_tab, "General")
        tabs.addTab(obfuscation_tab, "Obfuscation")
        tabs.addTab(integrity_tab, "Integrity")
        layout.addWidget(tabs)
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_settings)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

    def restore_default_files(self):
        reply = QMessageBox.question(self, "SysCaller v1.1.0", 
                                    "Are you sure you want to restore default files?\nThis will overwrite your current syscaller.asm and sysFunctions.h files.",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(script_dir))
            default_asm_path = os.path.join(project_root, 'BuildTools', 'Default', 'syscaller.asm')
            default_header_path = os.path.join(project_root, 'BuildTools', 'Default', 'sysFunctions.h')
            asm_path = os.path.join(project_root, 'Wrapper', 'src', 'syscaller.asm')
            header_path = os.path.join(project_root, 'Wrapper', 'include', 'Sys', 'sysFunctions.h')
            if not os.path.exists(default_asm_path) or not os.path.exists(default_header_path):
                QMessageBox.warning(self, "Missing Default Files", 
                                   "Default files not found in BuildTools/Default directory.")
                return
            if self.create_backup.isChecked():
                self.settings.setValue('general/create_backup', True)
                backups_dir = os.path.join(project_root, 'Backups')
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
                except Exception as e:
                    print(f"Warning: Could not create backup: {e}")
                    QMessageBox.warning(self, "Backup Failed", 
                                      f"Could not create backup files: {str(e)}\nContinuing with restore...")
            else:
                self.settings.setValue('general/create_backup', False)
            shutil.copy2(default_asm_path, asm_path)
            shutil.copy2(default_header_path, header_path)
            QMessageBox.information(self, "SysCaller v1.1.0", 
                                   "Default files have been restored successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred while restoring default files: {str(e)}")

    def load_syscalls(self):
        self.syscalls = []
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(script_dir))
        header_path = os.path.join(project_root, 'Wrapper', 'include', 'Sys', 'sysFunctions.h')
        syscall_mode = self.settings.value('general/syscall_mode', 'Nt', str)
        syscall_prefix = "Sys" if syscall_mode == "Nt" else "SysK"
        if os.path.exists(header_path):
            with open(header_path, 'r') as f:
                for line in f:
                    match = re.search(rf'extern "C" (?:NTSTATUS|ULONG) ({syscall_prefix}\w+)\(', line)
                    if match:
                        self.syscalls.append(match.group(1))
                    sc_match = re.search(r'extern "C" (?:NTSTATUS|ULONG) (SC\w+)\(', line)
                    if sc_match:
                        syscall_name = syscall_prefix + sc_match.group(1)[2:]
                        self.syscalls.append(syscall_name)
        self.syscalls.sort()
        selected_syscalls = self.settings.value('integrity/selected_syscalls', [], type=list)
        if not selected_syscalls:
            selected_syscalls = self.syscalls
        for syscall in self.syscalls:
            item = QListWidgetItem(syscall)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            if syscall in selected_syscalls:
                item.setCheckState(Qt.Checked)
            else:
                item.setCheckState(Qt.Unchecked)
            self.syscall_list.addItem(item)
    
    def select_all_syscalls(self):
        for i in range(self.syscall_list.count()):
            item = self.syscall_list.item(i)
            if not item.isHidden():
                item.setCheckState(Qt.Checked)
    
    def select_no_syscalls(self):
        for i in range(self.syscall_list.count()):
            item = self.syscall_list.item(i)
            if not item.isHidden():
                item.setCheckState(Qt.Unchecked)
    
    def filter_syscalls(self, text):
        for i in range(self.syscall_list.count()):
            item = self.syscall_list.item(i)
            if text.lower() in item.text().lower():
                item.setHidden(False)
            else:
                item.setHidden(True)

    def save_settings(self):
        self.settings.setValue('general/create_backup', self.create_backup.isChecked())
        if self.zw_mode_radio.isChecked():
            self.settings.setValue('general/syscall_mode', 'Zw')
        else:
            self.settings.setValue('general/syscall_mode', 'Nt')
        if self.create_backup.isChecked():
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(script_dir))
            backups_dir = os.path.join(project_root, 'Backups')
            if not os.path.exists(backups_dir):
                try:
                    os.makedirs(backups_dir)
                except Exception as e:
                    print(f"Warning: Could not create Backups directory: {e}")
        self.settings.setValue('obfuscation/min_instructions', self.min_instructions.value())
        self.settings.setValue('obfuscation/max_instructions', self.max_instructions.value())
        self.settings.setValue('obfuscation/use_advanced_junk', self.use_advanced_junk.isChecked())
        self.settings.setValue('obfuscation/syscall_prefix_length', self.syscall_prefix_length.value())
        self.settings.setValue('obfuscation/syscall_number_length', self.syscall_number_length.value())
        self.settings.setValue('obfuscation/offset_name_length', self.offset_name_length.value())
        self.settings.setValue('obfuscation/shuffle_sequence', self.shuffle_sequence.isChecked())
        self.settings.setValue('obfuscation/enable_encryption', self.enable_encryption.isChecked())
        encryption_method = self.encryption_method.currentData()
        self.settings.setValue('obfuscation/encryption_method', encryption_method)
        self.settings.setValue('obfuscation/enable_chunking', self.enable_chunking.isChecked())
        self.settings.setValue('obfuscation/enable_interleaved', self.enable_interleaved.isChecked())
        selected_syscalls = []
        for i in range(self.syscall_list.count()):
            item = self.syscall_list.item(i)
            if item.checkState() == Qt.Checked:
                selected_syscalls.append(item.text())
        self.settings.setValue('integrity/selected_syscalls', selected_syscalls)
        self.accept() 
