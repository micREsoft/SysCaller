from PyQt5.QtWidgets import (QFrame, QVBoxLayout, QLabel, QHBoxLayout, 
                           QPushButton, QFileDialog, QGraphicsOpacityEffect,
                           QListWidget, QListWidgetItem, QMenu)
from PyQt5.QtCore import Qt, QSize, QPropertyAnimation, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QCursor
from components.buttons.button import SysCallerButton
from components.bars.progress_bar import SysCallerProgressBar
from utils.dll_path import DllPathLineEdit

class LeftPanel(QFrame):
    dll_paths_changed = pyqtSignal(list)
    
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
        top_section = QVBoxLayout()
        top_section.setSpacing(5)
        logo_image = QLabel()
        logo_pixmap = QIcon("GUI/res/icons/syscaller.png").pixmap(QSize(128, 128))
        logo_image.setPixmap(logo_pixmap)
        logo_image.setAlignment(Qt.AlignCenter)
        top_section.addWidget(logo_image)
        logo_label = QLabel("SysCaller BuildTools")
        logo_label.setFont(QFont(None, 16, QFont.Bold))
        logo_label.setStyleSheet("""
            color: #0077d4;
            padding: 10px;
            background: rgba(72, 128, 168, 0.2);
            border-radius: 10px;
        """)
        logo_label.setAlignment(Qt.AlignCenter)
        top_section.addWidget(logo_label)
        version_label = QLabel("v1.1.0")
        version_label.setStyleSheet("color: #666666; font-size: 12px;")
        version_label.setAlignment(Qt.AlignCenter)
        top_section.addWidget(version_label)
        layout.addLayout(top_section)
        layout.addSpacing(15)
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
        dll_layout.setSpacing(8)
        header_btn_layout = QHBoxLayout()
        dll_header = QLabel("NTDLL PATHS")
        dll_header.setStyleSheet("color: #888888; font-size: 12px; font-weight: bold;")
        header_btn_layout.addWidget(dll_header)
        header_btn_layout.addStretch()
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        add_btn = QPushButton("Add DLL")
        add_btn.setMaximumWidth(100)
        add_btn.setMinimumHeight(26)
        add_btn.setStyleSheet("""
            QPushButton {
                background: #333333;
                border: none;
                border-radius: 5px;
                padding: 5px;
                color: white;
                font-weight: bold;
                font-size: 10px;
            }
            QPushButton:hover {
                background: #404040;
            }
            QPushButton:pressed {
                background: #2A2A2A;
            }
        """)
        add_btn.clicked.connect(self.browse_dll)
        remove_btn = QPushButton("Remove")
        remove_btn.setMaximumWidth(80)
        remove_btn.setMinimumHeight(26)
        remove_btn.setStyleSheet("""
            QPushButton {
                background: #333333;
                border: none;
                border-radius: 5px;
                padding: 5px;
                color: white;
                font-weight: bold;
                font-size: 10px;
            }
            QPushButton:hover {
                background: #404040;
            }
            QPushButton:pressed {
                background: #2A2A2A;
            }
        """)
        remove_btn.clicked.connect(self.remove_selected_dll)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(remove_btn)
        header_btn_layout.addLayout(btn_layout)
        dll_layout.addLayout(header_btn_layout)
        dll_layout.addSpacing(3)
        self.dll_list = QListWidget()
        self.dll_list.setStyleSheet("""
            QListWidget {
                background: #252525;
                border: 1px solid #333333;
                border-radius: 5px;
                padding: 5px;
                color: #FFFFFF;
                font-family: 'IBM Plex Mono';
                font-size: 12px;
            }
            QListWidget::item {
                padding: 5px;
                border-radius: 3px;
            }
            QListWidget::item:hover {
                background: #333333;
            }
            QListWidget::item:selected {
                background: #4880a8;
            }
        """)
        self.dll_list.setFixedHeight(90)
        self.dll_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.dll_list.customContextMenuRequested.connect(self.show_context_menu)
        dll_layout.addWidget(self.dll_list)
        default_path = "C:\\Windows\\System32\\ntdll.dll"
        item = QListWidgetItem(default_path)
        self.dll_list.addItem(item)
        self.dll_path = DllPathLineEdit("C:\\Windows\\System32\\ntdll.dll")
        self.dll_path.setVisible(False)
        dll_frame.setFixedHeight(175)
        layout.addWidget(dll_frame)
        layout.addSpacing(15)
        buttons_section = QVBoxLayout()
        buttons_section.setSpacing(10)
        self.validate_btn = SysCallerButton(
            " Validation Check", 
            "GUI/res/icons/validate.png",
            "Syscall Validation",
            "Analyzes and updates syscall offsets in syscaller.asm by comparing against ntdll.dll. <br><br>"
            "• Disassembles ntdll.dll exports to extract syscall IDs and ensures correct mapping <br>"
            "• Updates or removes syscalls based on their presence in the current systems ntdll.dll"
        )
        buttons_section.addWidget(self.validate_btn)
        self.compatibility_btn = SysCallerButton(
            " Compatibility Check", 
            "GUI/res/icons/compat.png",
            "Syscall Compatibility",
            "Performs compatibility analysis of syscalls against ntdll.dll: <br><br>"
            "• Detects duplicate syscall names and offsets <br>"
            "• Validates both Nt and Zw syscall variants <br>"
            "• Verifies offset matches between implementation and DLL <br>"
            "• Reports valid, invalid, and duplicate syscalls with detailed status"
        )
        buttons_section.addWidget(self.compatibility_btn)
        self.verify_btn = SysCallerButton(
            " Verification Check", 
            "GUI/res/icons/verify.png",
            "Syscall Verification",
            "Performs comprehensive syscall verification: <br><br>"
            "• Validates return types (NTSTATUS, BOOL, HANDLE, etc.) <br>"
            "• Verifies parameter types against system headers <br>"
            "• Checks offset ranges (0x0000-0x0200) <br>"
            "• Traces type definitions in header files"
        )
        buttons_section.addWidget(self.verify_btn)
        self.obfuscate_btn = SysCallerButton(
            " Syscall Obfuscation", 
            "GUI/res/icons/obfuscate.png",
            "Syscall Obfuscation",
            "Obfuscates syscalls to enhance protection: <br><br>"
            "• Randomizes syscall names and offsets <br>"
            "• Adds junk instructions for anti-pattern <br>"
            "• Maintains compatibility with existing code <br>"
            "• Preserves original syscall functionality"
        )
        buttons_section.addWidget(self.obfuscate_btn)
        self.settings_btn = SysCallerButton(
            " Settings",
            "GUI/res/icons/settings.png",
            "SysCaller Settings",
            "Configure SysCaller settings"
        )
        buttons_section.addWidget(self.settings_btn)
        layout.addLayout(buttons_section)
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
            existing_items = [self.dll_list.item(i).text() for i in range(self.dll_list.count())]
            if dll_path not in existing_items:
                self.dll_list.addItem(QListWidgetItem(dll_path))
                self.dll_path.setText(dll_path)
                self.emit_dll_paths()
            
    def remove_selected_dll(self):
        selected_items = self.dll_list.selectedItems()
        if not selected_items:
            return
        if self.dll_list.count() <= 1:
            return
        for item in selected_items:
            row = self.dll_list.row(item)
            self.dll_list.takeItem(row)
        if self.dll_list.count() > 0:
            self.dll_path.setText(self.dll_list.item(0).text())
        self.emit_dll_paths()
    
    def show_context_menu(self, position):
        if self.dll_list.count() <= 1:
            return
        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: #252525;
                color: white;
                border: 1px solid #333333;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #4880a8;
            }
        """)
        remove_action = menu.addAction("Remove")
        action = menu.exec_(QCursor.pos())
        if action == remove_action:
            self.remove_selected_dll()
    
    def get_dll_paths(self):
        return [self.dll_list.item(i).text() for i in range(self.dll_list.count())]
    
    def emit_dll_paths(self):
        self.dll_paths_changed.emit(self.get_dll_paths())
            
    def update_status(self, text):
        self.status_label.setText(text)
        effect = QGraphicsOpacityEffect(self.status_label)
        self.status_label.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity")
        anim.setDuration(200)
        anim.setStartValue(0)
        anim.setEndValue(1)
        anim.start() 
