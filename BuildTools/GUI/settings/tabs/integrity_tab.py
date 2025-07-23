import os
import re
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                           QGroupBox, QPushButton, QListWidget, QListWidgetItem, 
                           QLineEdit)
from PyQt5.QtCore import Qt

# NOTE: this tab requires a QSettings instance.

class IntegrityTab(QWidget):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.syscalls = []
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
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
        layout.addWidget(syscall_group)
        
    def load_syscalls(self):
        self.syscalls = []
        script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        project_root = os.path.dirname(script_dir)
        syscall_mode = self.settings.value('general/syscall_mode', 'Nt', str)
        is_kernel_mode = syscall_mode == 'Zw'
        syscall_prefix = "Sys" if syscall_mode == "Nt" else "SysK"
        if is_kernel_mode:
            header_path = os.path.join(project_root, 'SysCallerK', 'Wrapper', 'include', 'SysK', 'sysFunctions_k.h')
        else:
            header_path = os.path.join(project_root, 'SysCaller', 'Wrapper', 'include', 'Sys', 'sysFunctions.h')
        selected_syscalls = self.settings.value('integrity/selected_syscalls', [], type=list)
        if os.path.exists(header_path):
            with open(header_path, 'r') as f:
                header_content = f.read()
            extern_c_block = re.search(r'#ifdef\s+__cplusplus\s+extern\s+"C"\s+\{', header_content, re.DOTALL)
            with open(header_path, 'r') as f:
                for line in f:
                    match = re.search(rf'extern "C" (?:NTSTATUS|ULONG|BOOLEAN|VOID) ({syscall_prefix}\w+)\(', line)
                    if not match:
                        match = re.search(rf'(?:NTSTATUS|ULONG|BOOLEAN|VOID) ({syscall_prefix}\w+)\(', line)
                    if match:
                        self.syscalls.append(match.group(1))
                    sc_match = re.search(r'extern "C" (?:NTSTATUS|ULONG|BOOLEAN|VOID) (SC\w+)\(', line)
                    if not sc_match:
                        sc_match = re.search(r'(?:NTSTATUS|ULONG|BOOLEAN|VOID) (SC\w+)\(', line)
                    if sc_match:
                        syscall_name = syscall_prefix + sc_match.group(1)[2:]
                        self.syscalls.append(syscall_name)
        self.syscalls.sort()
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
        selected_syscalls = []
        for i in range(self.syscall_list.count()):
            item = self.syscall_list.item(i)
            if item.checkState() == Qt.Checked:
                selected_syscalls.append(item.text())
        self.settings.setValue('integrity/selected_syscalls', selected_syscalls) 
