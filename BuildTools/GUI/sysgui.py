import sys
import os
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, 
                            QWidget, QTextEdit, QLabel, QFrame, QHBoxLayout, QProgressBar, 
                            QStyleFactory, QGraphicsDropShadowEffect, QToolButton, QLineEdit, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QColor, QIcon

class WorkerThread(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, script_path, dll_path):
        super().__init__()
        self.script_path = script_path
        self.dll_path = dll_path

    def run(self):
        try:
            env = os.environ.copy()
            env['NTDLL_PATH'] = self.dll_path
            result = subprocess.run(
                ['python', self.script_path],
                capture_output=True,
                text=True,
                env=env
            )
            self.output.emit(result.stdout)
        except Exception as e:
            self.output.emit(f"Error: {str(e)}")
        finally:
            self.finished.emit()

class SysCallerProgressBar(QProgressBar):
    def __init__(self):
        super().__init__()
        self.setTextVisible(False)
        self.setMaximumHeight(4)
        self.setStyleSheet("""
            QProgressBar {
                border: none;
                background: rgba(68, 68, 68, 0.5);
                border-radius: 2px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #5890b8, stop:1 #67abdb);
                border-radius: 2px;
            }
        """)

class SysCallerButton(QPushButton):
    def __init__(self, text, icon_path=None):
        super().__init__(text)
        self.setFont(QFont("Segoe UI", 10))
        self.setMinimumHeight(60)
        self.setCursor(Qt.PointingHandCursor)
        if icon_path:
            self.setIcon(QIcon(icon_path))
            self.setIconSize(QSize(24, 24))
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setOffset(0, 0)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.setGraphicsEffect(shadow)
        self.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #5890b8, stop:1 #67abdb);
                border: none;
                border-radius: 10px;
                padding: 15px 25px;
                color: white;
                font-weight: 500;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #67abdb, stop:1 #5890b8);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #244d6b, stop:1 #244d6b);
                padding: 16px 24px 14px 26px;
            }
        """)

class SysCallerConsole(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #E0E0E0;
                border: none;
                border-radius: 10px;
                padding: 15px;
                font-family: 'Consolas';
                font-size: 13px;
                selection-background-color: #264F78;
            }
            QScrollBar:vertical {
                border: none;
                background: #1E1E1E;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: #424242;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: #616161;
            }
        """)

    def append(self, text):
        color_map = {
            '\033[94m': '<span style="color: #5890b8;">', # Blue
            '\033[92m': '<span style="color: #00CA4E;">', # Green
            '\033[93m': '<span style="color: #FFB900;">', # Yellow/Warning
            '\033[91m': '<span style="color: #FF605C;">', # Red/Fail
            '\033[0m': '</span>',                         # Reset
            '\033[1m': '<span style="font-weight: bold;">', # Bold
            '\033[4m': '<span style="text-decoration: underline;">' # Underline
        }
        for ansi, html in color_map.items():
            text = text.replace(ansi, html)
        if text.count('<span') > text.count('</span>'):
            text += '</span>' * (text.count('<span') - text.count('</span>'))
        text = text.replace('\n', '<br>')
        cursor = self.textCursor()
        cursor.movePosition(cursor.End)
        self.setTextCursor(cursor)
        self.insertHtml(text)

class SysCallerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SysCaller")
        self.setMinimumSize(1400, 900)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        main_widget = QWidget()
        main_widget.setStyleSheet("""
            QWidget {
                background: #1A1A1A;
                border-radius: 15px;
            }
        """)
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        title_bar = self.syscaller_title_bar()
        main_layout.addWidget(title_bar)
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(20)
        main_layout.addLayout(content_layout)
        left_panel = self.syscaller_left_panel()
        content_layout.addWidget(left_panel)
        right_panel = self.syscaller_right_panel()
        content_layout.addWidget(right_panel, stretch=2)
        self.worker = None

    def syscaller_title_bar(self):
        title_bar = QFrame()
        title_bar.setMaximumHeight(60)
        title_bar.setStyleSheet("""
            QFrame {
                background: #252525;
                border-top-left-radius: 15px;
                border-top-right-radius: 15px;
            }
        """)
        layout = QHBoxLayout(title_bar)
        layout.setContentsMargins(20, 0, 20, 0)
        title = QLabel("1.0.0")
        title.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        layout.addWidget(title)
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(15)
        minimize_btn = QToolButton()
        minimize_btn.setStyleSheet("""
            QToolButton {
                background: #FFB900;
                border-radius: 7px;
                width: 14px;
                height: 14px;
            }
            QToolButton:hover { background: #FFC933; }
        """)
        minimize_btn.clicked.connect(self.showMinimized)
        maximize_btn = QToolButton()
        maximize_btn.setStyleSheet("""
            QToolButton {
                background: #00CA4E;
                border-radius: 7px;
                width: 14px;
                height: 14px;
            }
            QToolButton:hover { background: #00E45B; }
        """)
        maximize_btn.clicked.connect(self.toggle_maximize)
        close_btn = QToolButton()
        close_btn.setStyleSheet("""
            QToolButton {
                background: #FF605C;
                border-radius: 7px;
                width: 14px;
                height: 14px;
            }
            QToolButton:hover { background: #FF8078; }
        """)
        close_btn.clicked.connect(self.close)
        controls_layout.addWidget(minimize_btn)
        controls_layout.addWidget(maximize_btn)
        controls_layout.addWidget(close_btn)
        layout.addLayout(controls_layout)
        return title_bar

    def syscaller_left_panel(self):
        left_panel = QFrame()
        left_panel.setMaximumWidth(350)
        left_panel.setStyleSheet("""
            QFrame {
                background: #252525;
                border-radius: 15px;
            }
        """)
        layout = QVBoxLayout(left_panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        logo_label = QLabel("SysCaller BuildTools")
        logo_label.setFont(QFont("Segoe UI", 24, QFont.Bold))
        logo_label.setStyleSheet("color: #4880a8;")
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        version_label = QLabel("v1.0.0")
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
        dll_header = QLabel("NTDLL Path")
        dll_header.setStyleSheet("color: #888888; font-size: 12px; font-weight: bold;")
        dll_layout.addWidget(dll_header)
        dll_path_layout = QHBoxLayout()
        self.dll_path = QLineEdit("C:\\Windows\\System32\\ntdll.dll")
        self.dll_path.setStyleSheet("""
            QLineEdit {
                background: #252525;
                border: 1px solid #333333;
                border-radius: 5px;
                padding: 8px;
                color: #FFFFFF;
                font-family: 'Consolas';
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
        layout.addSpacing(20)
        validate_btn = SysCallerButton("Validation Check", "GUI/icons/validate.png")
        validate_btn.clicked.connect(self.run_validation)
        layout.addWidget(validate_btn)
        compat_btn = SysCallerButton("Compatibility Check", "GUI/icons/compat.png")
        compat_btn.clicked.connect(self.run_compatibility)
        layout.addWidget(compat_btn)
        layout.addSpacing(20)
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
        self.status_label.setStyleSheet("color: #666666; font-size: 12px;")
        self.status_label.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.status_label)
        layout.addWidget(status_frame)
        layout.addStretch()
        return left_panel

    def syscaller_right_panel(self):
        right_panel = QFrame()
        right_panel.setStyleSheet("""
            QFrame {
                background: #252525;
                border-radius: 15px;
            }
        """)
        
        layout = QVBoxLayout(right_panel)
        layout.setContentsMargins(20, 20, 20, 20)
        header = QLabel("SysCaller Console")
        header.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        layout.addWidget(header)
        self.output_text = SysCallerConsole()
        layout.addWidget(self.output_text)
        return right_panel

    def toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def run_validation(self):
        if self.worker is None:
            self.status_label.setText("Running validation...")
            self.progress_bar.setMaximum(0)
            self.output_text.clear()
            script_path = os.path.join(os.path.dirname(__file__), '..', 'Validator', 'validator.py')
            self.worker = WorkerThread(script_path, self.dll_path.text())
            self.worker.output.connect(self.update_output)
            self.worker.finished.connect(self.on_worker_finished)
            self.worker.start()

    def run_compatibility(self):
        if self.worker is None:
            self.status_label.setText("Running compatibility check...")
            self.progress_bar.setMaximum(0)
            self.output_text.clear()
            script_path = os.path.join(os.path.dirname(__file__), '..', 'Compatibility', 'compatibility.py')
            self.worker = WorkerThread(script_path, self.dll_path.text())
            self.worker.output.connect(self.update_output)
            self.worker.finished.connect(self.on_worker_finished)
            self.worker.start()

    def update_output(self, text):
        self.output_text.append(text)

    def on_worker_finished(self):
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(100)
        self.status_label.setText("Ready")
        self.worker = None

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.drag_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self.drag_pos)
            event.accept()

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

def main():
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))
    app.setStyleSheet("""
        QToolTip {
            background-color: #1E1E1E;
            color: white;
            border: 1px solid #2196F3;
            border-radius: 4px;
            padding: 5px;
        }
    """)
    window = SysCallerWindow()
    window.show()
    sys.exit(app.exec_())
if __name__ == '__main__':
    main() 
