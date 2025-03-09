import sys
import os
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, 
                            QWidget, QTextEdit, QLabel, QFrame, QHBoxLayout, QProgressBar, 
                            QStyleFactory, QGraphicsDropShadowEffect, QToolButton, QLineEdit, QFileDialog, QGraphicsOpacityEffect)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QPropertyAnimation
from PyQt5.QtGui import QFont, QColor, QIcon, QFontDatabase

class WorkerThread(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, script_path, dll_path=None, *args):
        super().__init__()
        self.script_path = script_path
        self.dll_path = dll_path
        self.args = args
        self.process = None
        self.complete_output = []

    def run(self):
        try:
            cmd = ['python', self.script_path]
            if self.dll_path:
                os.environ['NTDLL_PATH'] = self.dll_path
            if self.args:
                cmd.extend(self.args)
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        
            def read_output():
                while True:
                    if self.process.poll() is not None and not self.complete_output:
                        break
                    output = self.process.stdout.readline()
                    if not output and self.process.poll() is not None:
                        break
                    if output:
                        self.complete_output.append(output.rstrip())
                if self.complete_output:
                    self.output.emit('\n'.join(self.complete_output))
                self.process.stdout.close()
                self.process.wait()
                self.finished.emit()
            from threading import Thread
            output_thread = Thread(target=read_output, daemon=True)
            output_thread.start()
        except Exception as e:
            self.output.emit(f"Error: {str(e)}")
            self.finished.emit()

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait()

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
                    stop:0 #0b5394, stop:1 #67abdb);
                border-radius: 2px;
            }
        """)

class SysCallerButton(QPushButton):
    def __init__(self, text, icon_path=None, tooltip=None, tooltip_detail=None):
        super().__init__(text)
        self.setFont(QFont(None, 10))
        self.setMinimumHeight(60)
        self.setCursor(Qt.PointingHandCursor)
        if tooltip and tooltip_detail:
            self.setToolTip(f"""
                <div style='background-color: #1E1E1E; padding: 10px; border-radius: 5px;'>
                    <b style='color: #67abdb; font-size: 13px;'>{tooltip}</b>
                    <hr style='border: 1px solid #333333; margin: 5px 0;'/>
                    <p style='color: #E0E0E0; font-size: 12px;'>{tooltip_detail}</p>
                </div>
            """)
        if icon_path:
            self.setIcon(QIcon(icon_path))
            self.setIconSize(QSize(24, 24))
            self.icon_animation = QTimer()
            self.icon_animation.timeout.connect(self.update_icon_size)
            self.icon_size_growing = True
            self.current_icon_size = 24
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setOffset(0, 0)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.setGraphicsEffect(shadow)
        self.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0b5394, stop:1 #67abdb);
                border: none;
                border-radius: 10px;
                padding: 15px 25px;
                color: white;
                font-weight: 500;
                transition: all 0.3s;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #67abdb, stop:1 #0b5394);
                transform: translateY(-2px);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #244d6b, stop:1 #244d6b);
                padding: 16px 24px 14px 26px;
            }
        """)

    def enterEvent(self, event):
        if hasattr(self, 'icon_animation'):
            self.icon_animation.start(50)
        super().enterEvent(event)

    def leaveEvent(self, event):
        if hasattr(self, 'icon_animation'):
            self.icon_animation.stop()
            self.setIconSize(QSize(24, 24))
            self.current_icon_size = 24
        super().leaveEvent(event)

    def update_icon_size(self):
        if self.icon_size_growing:
            self.current_icon_size += 1
            if self.current_icon_size >= 28:
                self.icon_size_growing = False
        else:
            self.current_icon_size -= 1
            if self.current_icon_size <= 24:
                self.icon_size_growing = True
        self.setIconSize(QSize(self.current_icon_size, self.current_icon_size))

class SysCallerOutput(QTextEdit):
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
        if text.strip() == '':
            text = '<br>'
        else:
            text = text.replace('\n', '<br>')
        cursor = self.textCursor()
        cursor.movePosition(cursor.End)
        self.setTextCursor(cursor)
        self.insertHtml(text + '<br>')

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
        self.destroyed.connect(self.cleanup_worker)

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
        logo_image = QLabel()
        logo_pixmap = QIcon("GUI/icons/syscaller.png").pixmap(QSize(64, 64))
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
        dll_header = QLabel("NTDLL PATH")
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
        layout.addSpacing(20)
        validate_btn = SysCallerButton(
            "Validation Check", 
            "GUI/icons/validate.png",
            "Syscall Validation",
            "Analyzes and updates syscall offsets in syscaller.asm by comparing against ntdll.dll. <br><br>"
            "• Disassembles ntdll.dll exports to extract syscall IDs and ensures correct mapping <br>"
            "• Updates or removes syscalls based on their presence in the current systems ntdll.dll"
        )
        validate_btn.clicked.connect(self.run_validation)
        layout.addWidget(validate_btn)
        compatibility_btn = SysCallerButton(
            "Compatibility Check", 
            "GUI/icons/compat.png",
            "Syscall Compatibility",
            "Performs compatibility analysis of syscalls against ntdll.dll: <br><br>"
            "• Detects duplicate syscall names and offsets <br>"
            "• Validates both Nt and Zw syscall variants <br>"
            "• Verifies offset matches between implementation and DLL <br>"
            "• Reports valid, invalid, and duplicate syscalls with detailed status"
        )
        compatibility_btn.clicked.connect(self.run_compatibility)
        layout.addWidget(compatibility_btn)
        verify_btn = SysCallerButton(
            "Verification Check", 
            "GUI/icons/verify.png",
            "Syscall Verification",
            "Performs comprehensive syscall verification: <br><br>"
            "• Validates return types (NTSTATUS, BOOL, HANDLE, etc.) <br>"
            "• Verifies parameter types against system headers <br>"
            "• Checks offset ranges (0x0000-0x0200) <br>"
            "• Traces type definitions in header files"
        )
        verify_btn.clicked.connect(self.run_verification)
        layout.addWidget(verify_btn)
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
        header.setStyleSheet("""
            color: #0077d4;
            font-size: 16px;
            font-weight: bold;
            padding: 10px;
            background: rgba(72, 128, 168, 0.2);
            border-radius: 8px;
        """)
        layout.addWidget(header)
        self.output_text = SysCallerOutput()
        layout.addWidget(self.output_text)
        return right_panel

    def toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def run_validation(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_label.setText("Running validation...")
        self.progress_bar.setMaximum(0)
        self.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Validator', 'validator.py')
        self.worker = WorkerThread(script_path, self.dll_path.text())
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def run_compatibility(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_label.setText("Running compatibility check...")
        self.progress_bar.setMaximum(0)
        self.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Compatibility', 'compatibility.py')
        self.worker = WorkerThread(script_path, self.dll_path.text())
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def run_verification(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_label.setText("Running verification...")
        self.progress_bar.setMaximum(0)
        self.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Verify', 'sysverify.py')
        self.worker = WorkerThread(script_path, self.dll_path.text(), '--from-gui')
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def update_output(self, text):
        self.output_text.append(text)

    def on_worker_finished(self):
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        self.worker = None
        self.status_label.setText("Ready")

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

    def cleanup_worker(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()

    def closeEvent(self, event):
        self.cleanup_worker()
        super().closeEvent(event)

    def update_status(self, text):
        self.status_label.setText(text)
        effect = QGraphicsOpacityEffect(self.status_label)
        self.status_label.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity")
        anim.setDuration(200)
        anim.setStartValue(0)
        anim.setEndValue(1)
        anim.start()

def main():
    os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.qpa.*=false'
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))
    font_id = QFontDatabase.addApplicationFont("GUI/fonts/ibmplexmono.ttf")
    if font_id != -1:
        font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
        app.setFont(QFont(font_family, 10))
    app.setStyleSheet("""
        * {
            font-family: 'IBM Plex Mono';
        }
        QToolTip {
            background-color: #1E1E1E;
            color: white;
            border: 1px solid #2196F3;
            border-radius: 4px;
            padding: 5px;
            font-family: 'IBM Plex Mono';
        }
    """)
    window = SysCallerWindow()
    window.show()
    sys.exit(app.exec_())
if __name__ == '__main__':
    main() 
