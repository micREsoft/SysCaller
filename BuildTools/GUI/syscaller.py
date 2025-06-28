import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStyleFactory, QMessageBox, QDialog
from PyQt5.QtCore import Qt, QSettings
from PyQt5.QtGui import QFont, QFontDatabase, QIcon
from components.bars.title_bar import TitleBar
from components.panels.left_panel import LeftPanel
from components.panels.right_panel import RightPanel
from components.bars.status_bar import StatusBar
from threads.syscaller_thread import SysCallerThread
from settings import SysCallerSettings
from features.stub_mapper.stub_mapper_dialog import StubMapperDialog
from settings.utils import get_project_paths, generate_stub_hashes, save_stub_hashes

class SysCallerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SysCaller v1.1.0")
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
        self.left_panel.dll_paths_changed.connect(self.on_dll_paths_changed)
        self.worker = None
        self.dll_paths = self.left_panel.get_dll_paths()
        self.destroyed.connect(self.cleanup_worker)

    def on_dll_paths_changed(self, paths):
        self.dll_paths = paths

    def run_validation(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_bar.update_status("Running Validation Check...", "working")
        self.left_panel.progress_bar.setMaximum(0)
        self.right_panel.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Integrity', 'Validator', 'validator.py')
        self.worker = SysCallerThread(script_path, self.dll_paths)
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def run_compatibility(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_bar.update_status("Running Compatibility Check...", "working")
        self.left_panel.progress_bar.setMaximum(0)
        self.right_panel.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Integrity', 'Compatibility', 'compatibility.py')
        self.worker = SysCallerThread(script_path, self.dll_paths)
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def run_verification(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_bar.update_status("Running Verification Check...", "working")
        self.left_panel.progress_bar.setMaximum(0)
        self.right_panel.output_text.clear()
        script_path = os.path.join(os.path.dirname(__file__), '..', 'Integrity', 'Verify', 'verify.py')
        self.worker = SysCallerThread(script_path, self.dll_paths, '--from-gui')
        self.worker.output.connect(self.update_output)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def run_obfuscation(self):
        if self.worker is not None and self.worker.isRunning():
            return
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("SysCaller - Obfuscation Selector")
        msg_box.setText("Select an obfuscation method:")
        msg_box.setIcon(QMessageBox.Question)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #2A2A2A;
                color: #FFFFFF;
                border-radius: 10px;
            }
            QLabel {
                color: #FFFFFF;
                font-family: 'IBM Plex Mono';
                font-size: 11px;
            }
            QPushButton {
                background-color: #0b5394;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px 15px;
                font-family: 'IBM Plex Mono';
                font-size: 10px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #67abdb;
            }
            QPushButton:pressed {
                background-color: #0A7AD1;
            }
        """)
        normal_button = msg_box.addButton("Obfuscation", QMessageBox.ActionRole)
        stub_mapper_button = msg_box.addButton("Stub Mapper", QMessageBox.ActionRole)
        cancel_button = msg_box.addButton(QMessageBox.Cancel)
        try:
            obfuscate_icon = QIcon("GUI/icons/obfuscate.png")
            msg_box.setWindowIcon(obfuscate_icon)
        except:
            pass
        msg_box.exec_()
        clicked_button = msg_box.clickedButton()
        if clicked_button == normal_button:
            self.status_bar.update_status("Running Normal SysCaller Obfuscation...", "working")
            self.left_panel.progress_bar.setMaximum(0)
            self.right_panel.output_text.clear()
            settings = QSettings('SysCaller', 'BuildTools')
            settings.setValue('obfuscation/force_normal', True)
            settings.setValue('obfuscation/force_stub_mapper', False)
            settings.setValue('obfuscation/last_method', 'normal')
            script_path = os.path.join(os.path.dirname(__file__), '..', 'Protection', 'protection.py')
            self.worker = SysCallerThread(script_path, self.dll_paths)
            self.worker.output.connect(self.update_output)
            self.worker.finished.connect(self.on_worker_finished)
            self.worker.start()
        elif clicked_button == stub_mapper_button:
            self.status_bar.update_status("Opening Stub Mapper...", "info")
            stub_mapper_dialog = StubMapperDialog(self)
            result = stub_mapper_dialog.exec_()
            if result == QDialog.Accepted:
                self.status_bar.update_status("Running Stub Mapper Obfuscation...", "working")
                self.left_panel.progress_bar.setMaximum(0)
                self.right_panel.output_text.clear()
                settings = QSettings('SysCaller', 'BuildTools')
                settings.setValue('obfuscation/force_normal', False)
                settings.setValue('obfuscation/force_stub_mapper', True)
                settings.setValue('obfuscation/last_method', 'stub_mapper')
                script_path = os.path.join(os.path.dirname(__file__), '..', 'Protection', 'protection.py')
                self.worker = SysCallerThread(script_path, self.dll_paths)
                self.worker.output.connect(self.update_output)
                self.worker.finished.connect(self.on_worker_finished)
                self.worker.start()
            else:
                self.status_bar.update_status("Ready", "idle")

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
        settings = QSettings('SysCaller', 'BuildTools')
        last_method = settings.value('obfuscation/last_method', '', str)
        settings.remove('obfuscation/force_normal')
        settings.remove('obfuscation/force_stub_mapper')
        if settings.value('general/hash_stubs', False, bool) and self.worker and hasattr(self.worker, 'script_path'):
            script_path = self.worker.script_path
            if 'protection.py' in script_path:
                obfuscation_type = "Stub Mapper" if last_method == 'stub_mapper' else "Normal"
                self.status_bar.update_status(f"Generating Stub Hashes for {obfuscation_type} Obfuscation...", "working")
                try:
                    paths = get_project_paths()
                    asm_path = paths['asm_path']
                    header_path = paths['header_path']
                    stub_hashes = generate_stub_hashes(asm_path, header_path, last_method)
                    timestamp = None
                    if hasattr(self.worker, 'start_time'):
                        timestamp = self.worker.start_time.strftime("%Y%m%d_%H%M%S")
                    success, result = save_stub_hashes(stub_hashes, timestamp)
                    if success:
                        self.right_panel.output_text.append(f"\n[INFO] Stub Hashes saved to: {os.path.basename(result)}")
                        self.status_bar.update_status("Stub Hashes generated successfully", "success")
                    else:
                        self.right_panel.output_text.append(f"\n[ERROR] Failed to save stub hashes: {result}")
                except Exception as e:
                    self.right_panel.output_text.append(f"\n[ERROR] Error generating stub hashes: {str(e)}")
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
        self.last_settings_dialog = settings_dialog
        settings_dialog.exec_()

def main():
    os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.qpa.*=false'
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))
    font_id = QFontDatabase.addApplicationFont("GUI/res/fonts/ibmplexmono.ttf")
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
