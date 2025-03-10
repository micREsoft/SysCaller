from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                            QSpinBox, QFrame, QPushButton, QTabWidget,
                            QWidget, QCheckBox, QGroupBox, QFormLayout)
from PyQt5.QtCore import Qt, QSettings
from PyQt5.QtGui import QIcon, QFont

class SysCallerSettings(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SysCaller Settings")
        self.setMinimumWidth(500)
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
            QCheckBox {
                color: white;
            }
            QLabel {
                color: white;
            }
        """)
        self.settings = QSettings('SysCaller', 'BuildTools')
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        tabs = QTabWidget()
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
        self.use_advanced_junk = QCheckBox("Use Advanced Junk Instructions")
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
        self.syscall_prefix_length.setValue(prefix_length)
        self.syscall_number_length = QSpinBox()
        self.syscall_number_length.setRange(4, 16)
        number_length = self.settings.value('obfuscation/syscall_number_length', 6, type=int)
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
        name_layout.addRow("Offset Name Length:", self.offset_name_length)
        name_group.setLayout(name_layout)
        obfuscation_layout.addWidget(name_group)
        obfuscation_layout.addStretch()
        tabs.addTab(obfuscation_tab, "Obfuscation")
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

    def save_settings(self):
        self.settings.setValue('obfuscation/min_instructions', self.min_instructions.value())
        self.settings.setValue('obfuscation/max_instructions', self.max_instructions.value())
        self.settings.setValue('obfuscation/use_advanced_junk', self.use_advanced_junk.isChecked())
        self.settings.setValue('obfuscation/syscall_prefix_length', self.syscall_prefix_length.value())
        self.settings.setValue('obfuscation/syscall_number_length', self.syscall_number_length.value())
        self.settings.setValue('obfuscation/offset_name_length', self.offset_name_length.value())
        self.accept() 
