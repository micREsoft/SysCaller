from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QGroupBox, QFormLayout, QSpinBox, QCheckBox, QComboBox,
                           QPushButton, QListWidget, QListWidgetItem, QSplitter,
                           QWidget, QTabWidget, QMessageBox, QLineEdit)
from PyQt5.QtCore import Qt, QSettings
from PyQt5.QtGui import QFont
import os
import re
from .validator import validate_stub_settings, show_validation_error
from settings.utils import get_ini_path

class StubMapperDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SysCaller - Stub Mapper")
        self.setMinimumWidth(800)
        self.setMinimumHeight(600)
        self.settings = QSettings(get_ini_path(), QSettings.IniFormat)
        self.syscall_settings = {}
        self.load_syscall_settings()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Horizontal)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        syscall_group = QGroupBox("Available Syscalls")
        syscall_layout = QVBoxLayout()
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter syscalls...")
        self.filter_input.textChanged.connect(self.filter_syscalls)
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_input)
        syscall_layout.addLayout(filter_layout)
        self.syscall_list = QListWidget()
        self.syscall_list.currentItemChanged.connect(self.on_syscall_selected)
        self.load_syscalls()
        syscall_layout.addWidget(self.syscall_list)
        syscall_group.setLayout(syscall_layout)
        left_layout.addWidget(syscall_group)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        settings_group = QGroupBox("Stub Configuration")
        settings_layout = QVBoxLayout()
        self.current_syscall_label = QLabel("Select a syscall from the list")
        font = QFont()
        font.setBold(True)
        self.current_syscall_label.setFont(font)
        settings_layout.addWidget(self.current_syscall_label)
        self.settings_tabs = QTabWidget()
        junk_tab = QWidget()
        junk_layout = QFormLayout(junk_tab)
        self.enable_junk = QCheckBox("Enable Junk Instructions")
        self.enable_junk.stateChanged.connect(self.on_setting_changed)
        junk_layout.addRow(self.enable_junk)
        self.min_instructions = QSpinBox()
        self.min_instructions.setRange(1, 10)
        self.min_instructions.setValue(2)
        self.min_instructions.valueChanged.connect(self.on_setting_changed)
        junk_layout.addRow("Minimum Instructions:", self.min_instructions)
        self.max_instructions = QSpinBox()
        self.max_instructions.setRange(1, 20)
        self.max_instructions.setValue(8)
        self.max_instructions.valueChanged.connect(self.on_setting_changed)
        junk_layout.addRow("Maximum Instructions:", self.max_instructions)
        self.use_advanced_junk = QCheckBox("Advanced Junk Instructions")
        self.use_advanced_junk.stateChanged.connect(self.on_setting_changed)
        junk_layout.addRow(self.use_advanced_junk)
        encryption_tab = QWidget()
        encryption_layout = QFormLayout(encryption_tab)
        self.enable_encryption = QCheckBox("Enable Syscall ID Encryption")
        self.enable_encryption.stateChanged.connect(self.on_setting_changed)
        encryption_layout.addRow(self.enable_encryption)
        self.encryption_method = QComboBox()
        self.encryption_method.addItem("Basic XOR (Simple)", 1)
        self.encryption_method.addItem("Multi-key XOR (Medium)", 2)
        self.encryption_method.addItem("Add + XOR (Medium)", 3)
        self.encryption_method.addItem("Enhanced XOR (Medium)", 4)
        self.encryption_method.addItem("Offset Shifting (Medium)", 5)
        self.encryption_method.currentIndexChanged.connect(self.on_setting_changed)
        encryption_layout.addRow("Encryption Method:", self.encryption_method)
        structure_tab = QWidget()
        structure_layout = QFormLayout(structure_tab)
        self.enable_chunking = QCheckBox("Enable Function Chunking")
        self.enable_chunking.stateChanged.connect(self.on_setting_changed)
        structure_layout.addRow(self.enable_chunking)
        self.enable_interleaved = QCheckBox("Enable Interleaved Execution")
        self.enable_interleaved.stateChanged.connect(self.on_setting_changed)
        structure_layout.addRow(self.enable_interleaved)
        self.shuffle_sequence = QCheckBox("Enable Sequence Shuffling")
        self.shuffle_sequence.stateChanged.connect(self.on_setting_changed)
        structure_layout.addRow(self.shuffle_sequence)
        name_tab = QWidget()
        name_layout = QFormLayout(name_tab)
        syscall_name_layout = QHBoxLayout()
        self.syscall_prefix_length = QSpinBox()
        self.syscall_prefix_length.setRange(4, 16)
        self.syscall_prefix_length.setValue(8)
        self.syscall_prefix_length.valueChanged.connect(self.on_setting_changed)
        self.syscall_number_length = QSpinBox()
        self.syscall_number_length.setRange(4, 16)
        self.syscall_number_length.setValue(6)
        self.syscall_number_length.valueChanged.connect(self.on_setting_changed)
        syscall_name_layout.addWidget(QLabel("Chars:"))
        syscall_name_layout.addWidget(self.syscall_prefix_length)
        syscall_name_layout.addWidget(QLabel("Numbers:"))
        syscall_name_layout.addWidget(self.syscall_number_length)
        name_layout.addRow("Syscall Name Length:", syscall_name_layout)
        self.offset_name_length = QSpinBox()
        self.offset_name_length.setRange(4, 16)
        self.offset_name_length.setValue(8)
        self.offset_name_length.valueChanged.connect(self.on_setting_changed)
        name_layout.addRow("Offset Name Length:", self.offset_name_length)
        self.settings_tabs.addTab(junk_tab, "Junk Instructions")
        self.settings_tabs.addTab(encryption_tab, "Encryption")
        self.settings_tabs.addTab(structure_tab, "Structure")
        self.settings_tabs.addTab(name_tab, "Name Randomization")
        settings_layout.addWidget(self.settings_tabs)
        settings_group.setLayout(settings_layout)
        right_layout.addWidget(settings_group)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 500])
        layout.addWidget(splitter)
        button_layout = QHBoxLayout()
        self.use_global_btn = QPushButton("Use Global Settings")
        self.use_global_btn.clicked.connect(self.use_global_settings)
        self.reset_btn = QPushButton("Reset")
        self.reset_btn.clicked.connect(self.reset_current_settings)
        validate_btn = QPushButton("Validate")
        validate_btn.clicked.connect(self.validate_current_settings)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_settings)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.use_global_btn)
        button_layout.addWidget(self.reset_btn)
        button_layout.addWidget(validate_btn)
        button_layout.addStretch()
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
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
            QComboBox {
                background: #333333;
                border: 1px solid #444444;
                border-radius: 5px;
                padding: 5px;
                color: white;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: #333333;
                color: white;
                selection-background-color: #0b5394;
            }
        """)
        self.enable_controls(False)
        
    def load_syscalls(self):
        self.syscall_list.clear()
        selected_syscalls = self.settings.value('integrity/selected_syscalls', [], type=list)
        if not selected_syscalls:
            script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            project_root = os.path.dirname(script_dir)
            header_path = os.path.join(project_root, 'SysCaller', 'Wrapper', 'include', 'Sys', 'sysFunctions.h')
            syscall_mode = self.settings.value('general/syscall_mode', 'Nt', str)
            syscall_prefix = "Sys" if syscall_mode == "Nt" else "SysK"
            if os.path.exists(header_path):
                with open(header_path, 'r') as f:
                    for line in f:
                        match = re.search(rf'extern "C" (?:NTSTATUS|ULONG) ({syscall_prefix}\w+)\(', line)
                        if match:
                            selected_syscalls.append(match.group(1))
                        sc_match = re.search(r'extern "C" (?:NTSTATUS|ULONG) (SC\w+)\(', line)
                        if sc_match:
                            syscall_name = syscall_prefix + sc_match.group(1)[2:]
                            selected_syscalls.append(syscall_name)
            selected_syscalls.sort()
        for syscall in selected_syscalls:
            item = QListWidgetItem(syscall)
            if syscall in self.syscall_settings:
                item.setForeground(Qt.green)
            self.syscall_list.addItem(item)
    
    def filter_syscalls(self, text):
        for i in range(self.syscall_list.count()):
            item = self.syscall_list.item(i)
            if text.lower() in item.text().lower():
                item.setHidden(False)
            else:
                item.setHidden(True)
    
    def on_syscall_selected(self, current, previous):
        if current is None:
            self.enable_controls(False)
            self.current_syscall_label.setText("Select a syscall from the list")
            return
        self.enable_controls(True)
        syscall_name = current.text()
        self.current_syscall_label.setText(f"Configuring: {syscall_name}")
        self.load_syscall_specific_settings(syscall_name)
    
    def load_syscall_specific_settings(self, syscall_name):
        if syscall_name in self.syscall_settings:
            settings = self.syscall_settings[syscall_name]
            # junk instructions
            self.enable_junk.setChecked(settings.get('enable_junk', False))
            self.min_instructions.setValue(settings.get('min_instructions', 2))
            self.max_instructions.setValue(settings.get('max_instructions', 8))
            self.use_advanced_junk.setChecked(settings.get('use_advanced_junk', False))
            # encryption
            self.enable_encryption.setChecked(settings.get('enable_encryption', False))
            encryption_method = settings.get('encryption_method', 1)
            index = self.encryption_method.findData(encryption_method)
            if index >= 0:
                self.encryption_method.setCurrentIndex(index)
            # structure
            self.enable_chunking.setChecked(settings.get('enable_chunking', False))
            self.enable_interleaved.setChecked(settings.get('enable_interleaved', False))
            self.shuffle_sequence.setChecked(settings.get('shuffle_sequence', False))
            # name randomization
            self.syscall_prefix_length.setValue(settings.get('syscall_prefix_length', 8))
            self.syscall_number_length.setValue(settings.get('syscall_number_length', 6))
            self.offset_name_length.setValue(settings.get('offset_name_length', 8))
        else:
            self.load_global_settings()
    
    def load_global_settings(self):
        # junk instructions
        self.enable_junk.setChecked(True)
        self.min_instructions.setValue(self.settings.value('obfuscation/min_instructions', 2, int))
        self.max_instructions.setValue(self.settings.value('obfuscation/max_instructions', 8, int))
        self.use_advanced_junk.setChecked(self.settings.value('obfuscation/use_advanced_junk', False, bool))
        # encryption
        self.enable_encryption.setChecked(self.settings.value('obfuscation/enable_encryption', True, bool))
        encryption_method = self.settings.value('obfuscation/encryption_method', 1, int)
        index = self.encryption_method.findData(encryption_method)
        if index >= 0:
            self.encryption_method.setCurrentIndex(index)
        # structure
        self.enable_chunking.setChecked(self.settings.value('obfuscation/enable_chunking', True, bool))
        self.enable_interleaved.setChecked(self.settings.value('obfuscation/enable_interleaved', True, bool))
        self.shuffle_sequence.setChecked(self.settings.value('obfuscation/shuffle_sequence', True, bool))
        # name randomization
        self.syscall_prefix_length.setValue(self.settings.value('obfuscation/syscall_prefix_length', 8, int))
        self.syscall_number_length.setValue(self.settings.value('obfuscation/syscall_number_length', 6, int))
        self.offset_name_length.setValue(self.settings.value('obfuscation/offset_name_length', 8, int))
    
    def use_global_settings(self):
        current_item = self.syscall_list.currentItem()
        if current_item:
            syscall_name = current_item.text()
            if syscall_name in self.syscall_settings:
                del self.syscall_settings[syscall_name]
                current_item.setForeground(Qt.white)
            self.load_global_settings()
    
    def reset_current_settings(self):
        current_item = self.syscall_list.currentItem()
        if current_item:
            syscall_name = current_item.text()
            if syscall_name in self.syscall_settings:
                del self.syscall_settings[syscall_name]
                current_item.setForeground(Qt.white)
            self.enable_junk.setChecked(True)
            self.min_instructions.setValue(2)
            self.max_instructions.setValue(8)
            self.use_advanced_junk.setChecked(False)
            self.enable_encryption.setChecked(True)
            self.encryption_method.setCurrentIndex(0)
            self.enable_chunking.setChecked(True)
            self.enable_interleaved.setChecked(True)
            self.shuffle_sequence.setChecked(True)
            self.syscall_prefix_length.setValue(8)
            self.syscall_number_length.setValue(6)
            self.offset_name_length.setValue(8)
    
    def on_setting_changed(self):
        current_item = self.syscall_list.currentItem()
        if current_item:
            syscall_name = current_item.text()
            self.save_current_syscall_settings(syscall_name)
            current_item.setForeground(Qt.green)
    
    def save_current_syscall_settings(self, syscall_name):
        settings = {
            # junk instructions
            'enable_junk': self.enable_junk.isChecked(),
            'min_instructions': self.min_instructions.value(),
            'max_instructions': self.max_instructions.value(),
            'use_advanced_junk': self.use_advanced_junk.isChecked(),
            # encryption
            'enable_encryption': self.enable_encryption.isChecked(),
            'encryption_method': self.encryption_method.currentData(),
            # structure
            'enable_chunking': self.enable_chunking.isChecked(),
            'enable_interleaved': self.enable_interleaved.isChecked(),
            'shuffle_sequence': self.shuffle_sequence.isChecked(),
            # name randomization
            'syscall_prefix_length': self.syscall_prefix_length.value(),
            'syscall_number_length': self.syscall_number_length.value(),
            'offset_name_length': self.offset_name_length.value(),
        }
        self.syscall_settings[syscall_name] = settings
    
    def validate_current_settings(self):
        current_item = self.syscall_list.currentItem()
        if current_item:
            syscall_name = current_item.text()
            if syscall_name in self.syscall_settings:
                settings = self.syscall_settings[syscall_name]
                is_valid, error_message = validate_stub_settings(settings)
                if is_valid:
                    QMessageBox.information(self, "Validation Success", f"Settings for {syscall_name} are valid!")
                else:
                    show_validation_error(self, f"Settings for {syscall_name} are invalid: {error_message}")
            else:
                QMessageBox.information(self, "Information", f"Using global settings for {syscall_name}.")
        else:
            QMessageBox.warning(self, "Warning", "Please select a syscall first.")
    
    def enable_controls(self, enabled):
        self.settings_tabs.setEnabled(enabled)
        self.use_global_btn.setEnabled(enabled)
        self.reset_btn.setEnabled(enabled)
    
    def load_syscall_settings(self):
        self.syscall_settings = self.settings.value('stub_mapper/syscall_settings', {}, type=dict)
    
    def save_settings(self):
        invalid_syscalls = []
        for syscall_name, settings in self.syscall_settings.items():
            is_valid, error_message = validate_stub_settings(settings)
            if not is_valid:
                invalid_syscalls.append(f"{syscall_name}: {error_message}")
        if invalid_syscalls:
            error_message = "The following syscalls have invalid settings:\n\n" + "\n".join(invalid_syscalls)
            show_validation_error(self, error_message)
            return
        self.settings.setValue('stub_mapper/syscall_settings', self.syscall_settings)
        QMessageBox.information(self, "Settings Saved", "Custom syscall settings have been saved successfully.")
        self.accept()
