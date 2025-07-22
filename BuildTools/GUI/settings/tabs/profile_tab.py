import os
import sys
import subprocess
import shutil
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QFileDialog, QMessageBox, QApplication
from settings.utils import get_ini_path
from PyQt5.QtCore import QSettings, pyqtSignal

class ProfileTab(QWidget):
    settings_reloaded = pyqtSignal()

    def __init__(self, settings=None):
        super().__init__()
        self.settings = QSettings(get_ini_path(), QSettings.IniFormat)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.export_btn = QPushButton("Export Profile (.ini)")
        self.export_btn.clicked.connect(self.export_profile)
        self.import_btn = QPushButton("Import Profile (.ini)")
        self.import_btn.clicked.connect(self.import_profile)
        layout.addWidget(self.export_btn)
        layout.addWidget(self.import_btn)
        layout.addStretch()

    def export_profile(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Profile", "", "INI Files (*.ini);;All Files (*)")
        if not path:
            return
        if not path.lower().endswith('.ini'):
            path += '.ini'
        try:
            export_settings = QSettings(path, QSettings.IniFormat)
            export_settings.clear()
            self.settings.sync()
            for group in self.settings.childGroups():
                self.settings.beginGroup(group)
                export_settings.beginGroup(group)
                for key in self.settings.childKeys():
                    export_settings.setValue(key, self.settings.value(key))
                export_settings.endGroup()
                self.settings.endGroup()
            export_settings.sync()
            QMessageBox.information(self, "Export Successful", f"Profile exported to:\n{os.path.abspath(path)}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export profile:\n{str(e)}")

    def import_profile(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Profile", "", "INI Files (*.ini);;All Files (*)")
        if not path:
            return
        try:
            ini_path = get_ini_path()
            self.settings.sync()
            del self.settings
            import shutil
            shutil.copy2(path, ini_path)
            QMessageBox.information(self, "Import Successful", f"Profile imported from:\n{os.path.abspath(path)}\n\nSysCaller will now restart to use the imported profile.")
            python = sys.executable
            script = sys.argv[0]
            args = sys.argv[1:]
            subprocess.Popen([python, script] + args, close_fds=True)
            QApplication.quit()
        except Exception as e:
            QMessageBox.critical(self, "Import Failed", f"Failed to import profile:\n{str(e)}")

    def save_settings(self):
        pass
