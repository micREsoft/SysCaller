import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStyleFactory
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QFontDatabase
from components.title_bar import TitleBar
from components.left_panel import LeftPanel
from components.right_panel import RightPanel
from components.status_bar import StatusBar
from threads.syscaller_thread import SysCallerThread
from settings import SysCallerSettings

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
        title_bar = TitleBar(self)
        main_layout.addWidget(title_bar)
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(20)
        main_layout.addLayout(content_layout)
        self.left_panel = LeftPanel(self)
        content_layout.addWidget(self.left_panel)
        self.right_panel = RightPanel(self)
        content_layout.addWidget(self.right_panel, stretch=2)
        self.status_bar = StatusBar()
        main_layout.addWidget(self.status_bar)
        self.left_panel.validate_btn.clicked.connect(self.run_validation)
        self.left_panel.compatibility_btn.clicked.connect(self.run_compatibility)
        self.left_panel.verify_btn.clicked.connect(self.run_verification)
        self.left_panel.obfuscate_btn.clicked.connect(self.run_obfuscation)
        self.left_panel.settings_btn.clicked.connect(self.show_settings)
        self.worker = None
        self.destroyed.connect(self.cleanup_worker)

    def run_validation(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_bar.update_status("Running validation check...", "working")
        self.left_panel.progress_bar.setMaximum(0)
        self.right_panel.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Validator', 'validator.py')
        self.worker = SysCallerThread(script_path, self.left_panel.dll_path.text())
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def run_compatibility(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_bar.update_status("Running compatibility check...", "working")
        self.left_panel.progress_bar.setMaximum(0)
        self.right_panel.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Compatibility', 'compatibility.py')
        self.worker = SysCallerThread(script_path, self.left_panel.dll_path.text())
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def run_verification(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_bar.update_status("Running verification check...", "working")
        self.left_panel.progress_bar.setMaximum(0)
        self.right_panel.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Verify', 'verify.py')
        self.worker = SysCallerThread(script_path, self.left_panel.dll_path.text(), '--from-gui')
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def run_obfuscation(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_bar.update_status("Running syscaller obfuscation...", "working")
        self.left_panel.progress_bar.setMaximum(0)
        self.right_panel.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Protection', 'protection.py')
        self.worker = SysCallerThread(script_path, self.left_panel.dll_path.text())
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def update_output(self, text):
        self.right_panel.output_text.append(text)
        if "Valid:" in text and "Invalid:" in text:
            try:
                parts = text.split(",")
                valid = int(parts[0].split(":")[1].strip())
                invalid = int(parts[1].split(":")[1].strip())
                duplicates = int(parts[2].split(":")[1].strip())
                self.status_bar.set_result(valid, invalid, duplicates)
            except:
                pass

    def on_worker_finished(self):
        self.left_panel.progress_bar.setRange(0, 1)
        self.left_panel.progress_bar.setValue(1)
        self.worker = None
        if not self.status_bar.result_label.text():
            self.status_bar.update_status("Operation completed", "success")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.drag_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self.drag_pos)
            event.accept()

    def cleanup_worker(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()

    def closeEvent(self, event):
        self.cleanup_worker()
        super().closeEvent(event)

    def show_settings(self):
        settings_dialog = SysCallerSettings(self)
        settings_dialog.exec_()

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
