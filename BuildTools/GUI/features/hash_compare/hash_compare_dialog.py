import os
import json
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QPushButton, QListWidget, QSplitter, QTableWidget, 
                           QTableWidgetItem, QHeaderView, QAbstractItemView,
                           QGroupBox, QCheckBox, QComboBox, QMessageBox,
                           QFileDialog, QApplication)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QColor, QIcon

from settings.utils import get_project_paths

class HashCompareDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SysCaller - Hash Compare")
        self.setMinimumSize(900, 600)
        self.setStyleSheet("""
            QDialog {
                background: #252525;
                color: white;
            }
            QSplitter::handle {
                background: #444444;
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
            QPushButton:disabled {
                background: #555555;
                color: #aaaaaa;
            }
            QLabel {
                color: white;
            }
            QListWidget, QTableWidget {
                background: #333333;
                color: white;
                border-radius: 5px;
                padding: 5px;
                border: 1px solid #444444;
            }
            QTableWidget::item:alternate {
                background: #2A2A2A;
            }
            QHeaderView::section {
                background: #0b5394;
                color: white;
                padding: 5px;
                border: 1px solid #444444;
            }
            QCheckBox, QComboBox {
                color: white;
            }
            QComboBox {
                background: #333333;
                border: 1px solid #444444;
                border-radius: 3px;
                padding: 5px;
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
        self.hash_files = []
        self.hash_data = {}
        self.hash_type = "MD5"  # Default hash type
        self.init_ui()
        self.load_hash_files()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        top_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setIcon(QIcon("GUI/res/icons/reset.png"))
        self.refresh_btn.clicked.connect(self.load_hash_files)
        hash_type_layout = QHBoxLayout()
        hash_type_label = QLabel("Hash Type:")
        self.hash_type_selector = QComboBox()
        self.hash_type_selector.addItems(["MD5", "SHA-256"])
        self.hash_type_selector.setCurrentText(self.hash_type)
        self.hash_type_selector.currentTextChanged.connect(self.on_hash_type_changed)
        hash_type_layout.addWidget(hash_type_label)
        hash_type_layout.addWidget(self.hash_type_selector)
        self.export_btn = QPushButton("Export Comparison")
        self.export_btn.setIcon(QIcon("GUI/res/icons/export.png"))
        self.export_btn.clicked.connect(self.export_comparison)
        self.export_btn.setEnabled(False)
        top_layout.addWidget(self.refresh_btn)
        top_layout.addLayout(hash_type_layout)
        top_layout.addStretch()
        top_layout.addWidget(self.export_btn)
        layout.addLayout(top_layout)
        splitter = QSplitter(Qt.Horizontal)
        left_panel = QGroupBox("Hash Files")
        left_layout = QVBoxLayout(left_panel)
        self.show_duplicates = QCheckBox("Highlight Duplicates")
        self.show_duplicates.setChecked(True)
        self.show_duplicates.stateChanged.connect(self.update_hash_table)
        self.hash_list = QListWidget()
        self.hash_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.hash_list.itemSelectionChanged.connect(self.selection_changed)
        left_layout.addWidget(self.show_duplicates)
        left_layout.addWidget(self.hash_list)
        compare_btn = QPushButton("Compare Selected")
        compare_btn.clicked.connect(self.compare_selected)
        left_layout.addWidget(compare_btn)
        right_panel = QGroupBox("Hash Comparison")
        right_layout = QVBoxLayout(right_panel)
        self.hash_table = QTableWidget(0, 3)  # Initial columns: Syscall, Hash File 1, Hash File 2
        self.hash_table.setHorizontalHeaderLabels(["Syscall", "Hash File 1", "Hash File 2"])
        self.hash_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.hash_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.hash_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.hash_table.verticalHeader().setVisible(False)
        self.hash_table.setAlternatingRowColors(True)
        self.hash_table.setSortingEnabled(True)
        right_layout.addWidget(self.hash_table)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 600])
        layout.addWidget(splitter)
        button_layout = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)
    
    def on_hash_type_changed(self, hash_type):
        self.hash_type = hash_type
        self.update_hash_table()
    
    def load_hash_files(self):
        try:
            paths = get_project_paths()
            hash_backups_dir = paths.get('hash_backups_dir')
            if not hash_backups_dir or not os.path.exists(hash_backups_dir):
                self.hash_list.clear()
                self.hash_list.addItem("No hash directory found")
                return
            self.hash_list.clear()
            self.hash_files = []
            self.hash_data = {}
            files = [f for f in os.listdir(hash_backups_dir) if f.endswith('.json') and f.startswith('stub_hashes_')]
            files.sort(reverse=True)
            for file in files:
                try:
                    file_path = os.path.join(hash_backups_dir, file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    timestamp = data.get('timestamp', 'Unknown')
                    config = data.get('config', {})
                    obf_method = "Normal"
                    if isinstance(config, dict):
                        if config.get('obfuscation_method'):
                            obf_method = config.get('obfuscation_method')
                        elif isinstance(config.get('global_settings'), dict):
                            obf_method = "Stub Mapper"
                    display_name = f"{timestamp} ({obf_method})"
                    self.hash_list.addItem(display_name)
                    self.hash_files.append(file_path)
                    self.hash_data[file_path] = data
                except Exception as e:
                    print(f"Error loading hash file {file}: {e}")
            if not self.hash_files:
                self.hash_list.addItem("No hash files found")
        except Exception as e:
            print(f"Error loading hash files: {e}")
            self.hash_list.clear()
            self.hash_list.addItem(f"Error: {str(e)}")
    
    def selection_changed(self):
        selected_items = self.hash_list.selectedItems()
        self.export_btn.setEnabled(len(selected_items) >= 1)
    
    def update_hash_table(self):
        selected_indexes = [item.listWidget().row(item) for item in self.hash_list.selectedItems()]
        if selected_indexes:
            selected_files = [self.hash_files[idx] for idx in selected_indexes]
            self.display_comparison(selected_files)
    
    def compare_selected(self):
        selected_indexes = [item.listWidget().row(item) for item in self.hash_list.selectedItems()]
        if len(selected_indexes) < 1:
            QMessageBox.warning(self, "Selection Required", "Please select at least one hash file to view.")
            return
        if len(selected_indexes) > 5:
            QMessageBox.warning(self, "Too Many Selected", "Please select at most 5 hash files to compare.")
            return
        selected_files = [self.hash_files[idx] for idx in selected_indexes]
        self.display_comparison(selected_files)
    
    def extract_hash(self, hash_value, hash_type):
        if not hash_value or hash_value == "N/A":
            return "N/A"
        if hash_type == "MD5" and "MD5:" in hash_value:
            return hash_value.split("MD5:")[1].split("SHA-256:")[0].strip()
        elif hash_type == "SHA-256" and "SHA-256:" in hash_value:
            return hash_value.split("SHA-256:")[1].strip()
        return "N/A"
    
    def display_comparison(self, files):
        if not files:
            return
        self.hash_table.clear()
        self.hash_table.setSortingEnabled(False)
        self.hash_table.setColumnCount(len(files) + 1)
        headers = ["Syscall"]
        for i, file_path in enumerate(files):
            file_name = os.path.basename(file_path)
            data = self.hash_data.get(file_path, {})
            timestamp = data.get('timestamp', 'Unknown')
            config = data.get('config', {})
            if isinstance(config, dict):
                if config.get('obfuscation_method'):
                    obf_method = config.get('obfuscation_method')
                elif isinstance(config.get('global_settings'), dict):
                    obf_method = "Stub Mapper"
                else:
                    obf_method = "Normal"
            else:
                obf_method = "Unknown"
            headers.append(f"{timestamp}\n({obf_method})")
        self.hash_table.setHorizontalHeaderLabels(headers)
        all_syscalls = set()
        for file_path in files:
            data = self.hash_data.get(file_path, {})
            stubs = data.get('stubs', {})
            all_syscalls.update(stubs.keys())
        self.hash_table.setRowCount(len(all_syscalls))
        hash_mapping = {}
        for syscall in sorted(all_syscalls):
            for col, file_path in enumerate(files, start=1):
                data = self.hash_data.get(file_path, {})
                stubs = data.get('stubs', {})
                hash_value = stubs.get(syscall, "")
                if hash_value:
                    extracted_hash = self.extract_hash(hash_value, self.hash_type)
                    if extracted_hash != "N/A":
                        if extracted_hash not in hash_mapping:
                            hash_mapping[extracted_hash] = []
                        hash_mapping[extracted_hash].append((syscall, col))
        for row, syscall in enumerate(sorted(all_syscalls)):
            self.hash_table.setItem(row, 0, QTableWidgetItem(syscall))
            for col, file_path in enumerate(files, start=1):
                data = self.hash_data.get(file_path, {})
                stubs = data.get('stubs', {})
                hash_value = stubs.get(syscall, "")
                if hash_value:
                    extracted_hash = self.extract_hash(hash_value, self.hash_type)
                    item = QTableWidgetItem(extracted_hash)
                    is_duplicate = False
                    if extracted_hash != "N/A":
                        is_duplicate = len(hash_mapping.get(extracted_hash, [])) > 1
                    if is_duplicate and self.show_duplicates.isChecked() and row % 2 == 0:
                        item.setForeground(QColor(255, 0, 0)) # red
                else:
                    item = QTableWidgetItem("N/A")
                    item.setBackground(QColor(80, 80, 80))
                self.hash_table.setItem(row, col, item)
        if self.show_duplicates.isChecked():
            duplicate_colors = [
                QColor(255, 150, 150),  # red
                QColor(150, 255, 150),  # green
                QColor(150, 150, 255),  # blue
                QColor(255, 255, 150),  # yellow
                QColor(255, 150, 255),  # purple
                QColor(150, 255, 255),  # cyan
                QColor(255, 200, 150),  # orange
            ]
            color_index = 0
            for hash_value, positions in hash_mapping.items():
                if len(positions) > 1:
                    color = duplicate_colors[color_index % len(duplicate_colors)]
                    color_index += 1
                    for syscall, col in positions:
                        row = sorted(all_syscalls).index(syscall)
                        item = self.hash_table.item(row, col)
                        if item and row % 2 == 1:
                            item.setBackground(color)
        for i in range(self.hash_table.columnCount()):
            self.hash_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.Stretch)
        self.hash_table.setSortingEnabled(True)
    
    def export_comparison(self):
        selected_indexes = [item.listWidget().row(item) for item in self.hash_list.selectedItems()]
        if not selected_indexes:
            QMessageBox.warning(self, "Selection Required", "Please select at least one hash file to export.")
            return
        selected_files = [self.hash_files[idx] for idx in selected_indexes]
        export_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export Comparison", "", "CSV Files (*.csv);;HTML Files (*.html);;All Files (*)"
        )
        if not export_path:
            return
        try:
            if export_path.lower().endswith('.csv'):
                self.export_as_csv(export_path, selected_files)
            elif export_path.lower().endswith('.html'):
                self.export_as_html(export_path, selected_files)
            else:
                if not export_path.lower().endswith('.csv'):
                    export_path += '.csv'
                self.export_as_csv(export_path, selected_files)
            QMessageBox.information(self, "Export Successful", 
                                  f"Hash comparison exported successfully to:\n{export_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export comparison: {str(e)}")
    
    def export_as_csv(self, export_path, selected_files):
        if not selected_files:
            return
        all_syscalls = set()
        for file_path in selected_files:
            data = self.hash_data.get(file_path, {})
            stubs = data.get('stubs', {})
            all_syscalls.update(stubs.keys())
        with open(export_path, 'w', encoding='utf-8') as f:
            header = ["Syscall"]
            for file_path in selected_files:
                data = self.hash_data.get(file_path, {})
                timestamp = data.get('timestamp', 'Unknown')
                config = data.get('config', {})
                if isinstance(config, dict):
                    if config.get('obfuscation_method'):
                        obf_method = config.get('obfuscation_method')
                    elif isinstance(config.get('global_settings'), dict):
                        obf_method = "Stub Mapper"
                    else:
                        obf_method = "Normal"
                else:
                    obf_method = "Unknown"
                
                header.append(f"{timestamp} ({obf_method})")
            f.write(','.join([f'"{h}"' for h in header]) + '\n')
            for syscall in sorted(all_syscalls):
                row = [syscall]
                for file_path in selected_files:
                    data = self.hash_data.get(file_path, {})
                    stubs = data.get('stubs', {})
                    hash_value = stubs.get(syscall, "N/A")
                    row.append(hash_value)
                f.write(','.join([f'"{cell}"' for cell in row]) + '\n')
    
    def export_as_html(self, export_path, selected_files):
        if not selected_files:
            return
        all_syscalls = set()
        for file_path in selected_files:
            data = self.hash_data.get(file_path, {})
            stubs = data.get('stubs', {})
            all_syscalls.update(stubs.keys())
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write('''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SysCaller - Hash Comparison</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f8f8f8; }
        h1 { color: #0b5394; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0b5394; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:nth-child(odd) { background-color: #ffffff; }
        tr:hover { background-color: #ddd; }
        .duplicate { background-color: #ffe0e0; }
        .timestamp { font-weight: bold; }
        .method { font-style: italic; color: #666; }
        .hash-type { font-weight: bold; color: #0b5394; }
    </style>
</head>
<body>
    <h1>SysCaller Hash Comparison</h1>
    <p>Generated on: ''' + self.hash_data.get(selected_files[0], {}).get('timestamp', 'Unknown') + '''</p>
    <p><span class="hash-type">Hash Type: ''' + self.hash_type + '''</span></p>
    <table>
        <tr>
            <th>Syscall</th>
''')
            for file_path in selected_files:
                data = self.hash_data.get(file_path, {})
                timestamp = data.get('timestamp', 'Unknown')
                config = data.get('config', {})
                if isinstance(config, dict):
                    if config.get('obfuscation_method'):
                        obf_method = config.get('obfuscation_method')
                    elif isinstance(config.get('global_settings'), dict):
                        obf_method = "Stub Mapper"
                    else:
                        obf_method = "Normal"
                else:
                    obf_method = "Unknown"
                f.write(f'            <th><span class="timestamp">{timestamp}</span><br><span class="method">({obf_method})</span></th>\n')
            f.write('        </tr>\n')
            hash_mapping = {}
            for syscall in sorted(all_syscalls):
                for file_path in selected_files:
                    data = self.hash_data.get(file_path, {})
                    stubs = data.get('stubs', {})
                    hash_value = stubs.get(syscall, "")
                    if hash_value:
                        extracted_hash = self.extract_hash(hash_value, self.hash_type)
                        if extracted_hash != "N/A":
                            if extracted_hash not in hash_mapping:
                                hash_mapping[extracted_hash] = []
                            hash_mapping[extracted_hash].append((syscall, file_path))
            for syscall in sorted(all_syscalls):
                f.write(f'        <tr>\n            <td>{syscall}</td>\n')
                for file_path in selected_files:
                    data = self.hash_data.get(file_path, {})
                    stubs = data.get('stubs', {})
                    hash_value = stubs.get(syscall, "N/A")
                    extracted_hash = self.extract_hash(hash_value, self.hash_type) if hash_value != "N/A" else "N/A"
                    duplicate_class = ""
                    if extracted_hash != "N/A":
                        if extracted_hash in hash_mapping and len(hash_mapping[extracted_hash]) > 1:
                            duplicate_class = ' class="duplicate"'
                    f.write(f'            <td{duplicate_class}>{extracted_hash}</td>\n')
                f.write('        </tr>\n')
            f.write('''    </table>
</body>
</html>''') 