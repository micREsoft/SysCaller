from PyQt5.QtWidgets import (QFrame, QVBoxLayout, QLabel, QHBoxLayout, 
                           QPushButton, QFileDialog, QGraphicsOpacityEffect)
from PyQt5.QtCore import Qt, QSize, QPropertyAnimation
from PyQt5.QtGui import QFont, QIcon
from components.buttons.button import SysCallerButton
from components.bars.progress_bar import SysCallerProgressBar
from utils.dll_path import DllPathLineEdit

class LeftPanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setMaximumWidth(350)
        self.setStyleSheet("""
            QFrame {
                background: #252525;
                border-radius: 15px;
            }
        """)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        logo_image = QLabel()
        logo_pixmap = QIcon("GUI/res/icons/syscaller.png").pixmap(QSize(128, 128))
        logo_image.setPixmap(logo_pixmap)
        logo_image.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_image)
        layout.addSpacing(10)
        logo_label = QLabel("SysCaller BuildTools")
        logo_label.setFont(QFont(None, 16, QFont.Bold))
        logo_label.setStyleSheet("""
            color: #0077d4;
            padding: 10px;
            background: rgba(72, 128, 168, 0.2);
            border-radius: 10px;
        """)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        version_label = QLabel("v1.1.0")
        version_label.setStyleSheet("color: #666666; font-size: 12px;")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)
        layout.addSpacing(30)
        dll_frame = QFrame()
        dll_frame.setStyleSheet("""
            QFrame {
                background: #1E1E1E;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        dll_layout = QVBoxLayout(dll_frame)
        dll_layout.setContentsMargins(15, 15, 15, 15)
        dll_header = QLabel("NTDLL PATH")
        dll_header.setStyleSheet("color: #888888; font-size: 12px; font-weight: bold;")
        dll_layout.addWidget(dll_header)
        dll_path_layout = QHBoxLayout()
        self.dll_path = DllPathLineEdit("C:\\Windows\\System32\\ntdll.dll")
        self.dll_path.setStyleSheet("""
            QLineEdit {
                background: #252525;
                border: 1px solid #333333;
                border-radius: 5px;
                padding: 8px;
                color: #FFFFFF;
                font-family: 'IBM Plex Mono';
                font-size: 12px;
            }
            QLineEdit:hover {
                border: 1px solid #4880a8;
            }
            QLineEdit:focus {
                border: 1px solid #5890b8;
                background: #2A2A2A;
            }
        """)
        self.dll_path.setReadOnly(True)
        browse_btn = QPushButton("...")
        browse_btn.setMaximumWidth(40)
        browse_btn.setStyleSheet("""
            QPushButton {
                background: #333333;
                border: none;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            QPushButton:hover {
                background: #404040;
            }
            QPushButton:pressed {
                background: #2A2A2A;
            }
        """)
        browse_btn.clicked.connect(self.browse_dll)
        dll_path_layout.addWidget(self.dll_path)
        dll_path_layout.addWidget(browse_btn)
        dll_layout.addLayout(dll_path_layout)
        layout.addWidget(dll_frame)
        layout.addSpacing(10)
        self.validate_btn = SysCallerButton(
            "Validation Check", 
            "GUI/res/icons/validate.png",
            "Syscall Validation",
            "Analyzes and updates syscall offsets in syscaller.asm by comparing against ntdll.dll. <br><br>"
            "• Disassembles ntdll.dll exports to extract syscall IDs and ensures correct mapping <br>"
            "• Updates or removes syscalls based on their presence in the current systems ntdll.dll"
        )
        layout.addWidget(self.validate_btn)
        self.compatibility_btn = SysCallerButton(
            "Compatibility Check", 
            "GUI/res/icons/compat.png",
            "Syscall Compatibility",
            "Performs compatibility analysis of syscalls against ntdll.dll: <br><br>"
            "• Detects duplicate syscall names and offsets <br>"
            "• Validates both Nt and Zw syscall variants <br>"
            "• Verifies offset matches between implementation and DLL <br>"
            "• Reports valid, invalid, and duplicate syscalls with detailed status"
        )
        layout.addWidget(self.compatibility_btn)
        self.verify_btn = SysCallerButton(
            "Verification Check", 
            "GUI/res/icons/verify.png",
            "Syscall Verification",
            "Performs comprehensive syscall verification: <br><br>"
            "• Validates return types (NTSTATUS, BOOL, HANDLE, etc.) <br>"
            "• Verifies parameter types against system headers <br>"
            "• Checks offset ranges (0x0000-0x0200) <br>"
            "• Traces type definitions in header files"
        )
        layout.addWidget(self.verify_btn)
        self.obfuscate_btn = SysCallerButton(
            "Syscall Obfuscation", 
            "GUI/res/icons/obfuscate.png",
            "Syscall Obfuscation",
            "Obfuscates syscalls to enhance protection: <br><br>"
            "• Randomizes syscall names and offsets <br>"
            "• Adds junk instructions for anti-pattern <br>"
            "• Maintains compatibility with existing code <br>"
            "• Preserves original syscall functionality"
        )
        layout.addWidget(self.obfuscate_btn)
        self.settings_btn = SysCallerButton(
            "Settings",
            "GUI/res/icons/settings.png",
            "SysCaller Settings",
            "Configure SysCaller settings"
        )
        layout.addWidget(self.settings_btn)
        layout.addSpacing(10)
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background: #1E1E1E;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(15, 15, 15, 15)
        self.progress_bar = SysCallerProgressBar()
        status_layout.addWidget(self.progress_bar)
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #666666;
                font-size: 12px;
                padding: 5px;
                border-radius: 5px;
                background: rgba(102, 102, 102, 0.1);
            }
        """)
        self.status_label.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.status_label)
        layout.addWidget(status_frame)
        layout.addStretch()
        
    def browse_dll(self):
        file_dialog = QFileDialog()
        file_dialog.setStyleSheet("""
            QFileDialog {
                background: #252525;
                color: white;
            }
            QFileDialog QLabel { color: white; }
            QFileDialog QPushButton {
                background: #333333;
                border: none;
                border-radius: 5px;
                padding: 8px;
                color: white;
                min-width: 80px;
            }
            QFileDialog QPushButton:hover {
                background: #404040;
            }
            QFileDialog QLineEdit {
                background: #1E1E1E;
                border: 1px solid #333333;
                border-radius: 5px;
                padding: 8px;
                color: white;
            }
            QFileDialog QTreeView {
                background: #1E1E1E;
                color: white;
            }
            QFileDialog QTreeView::item:hover {
                background: #333333;
            }
            QFileDialog QTreeView::item:selected {
                background: #4880a8;
            }
        """)
        dll_path, _ = file_dialog.getOpenFileName(
            self,
            "Select NTDLL",
            "",
            "DLL Files (*.dll);;All Files (*.*)"
        )
        if dll_path:
            self.dll_path.setText(dll_path)
            
    def update_status(self, text):
        self.status_label.setText(text)
        effect = QGraphicsOpacityEffect(self.status_label)
        self.status_label.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity")
        anim.setDuration(200)
        anim.setStartValue(0)
        anim.setEndValue(1)
        anim.start() 
