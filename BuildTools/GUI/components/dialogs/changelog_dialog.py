import os
import markdown2
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QListWidget, QLabel, QTextEdit, QHBoxLayout, QPushButton
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class ChangelogDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SysCaller - History")
        self.setMinimumSize(700, 500)
        self.setStyleSheet("""
            QDialog {
                background: #232323;
                border-radius: 12px;
            }
            QLabel {
                color: #0077d4;
                font-size: 18px;
                font-weight: bold;
                padding: 10px 0 10px 0;
            }
            QListWidget {
                background: #181818;
                color: #fff;
                border-radius: 8px;
                font-size: 14px;
                min-width: 120px;
            }
            QListWidget::item:selected {
                background: #0077d4;
                color: #fff;
            }
            QTextEdit {
                background: #181818;
                color: #fff;
                border-radius: 8px;
                font-family: 'IBM Plex Mono';
                font-size: 13px;
            }
            QPushButton {
                background: #0077d4;
                color: #fff;
                border-radius: 6px;
                padding: 6px 18px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background: #404040;
            }
        """)
        layout = QVBoxLayout(self)
        title = QLabel("Changelog History")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        hbox = QHBoxLayout()
        self.list_widget = QListWidget()
        self.list_widget.setFixedWidth(150)
        hbox.addWidget(self.list_widget)
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        hbox.addWidget(self.text_edit, 1)
        layout.addLayout(hbox)
        btn_box = QHBoxLayout()
        btn_box.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(close_btn)
        layout.addLayout(btn_box)
        self.populate_changelogs()
        self.list_widget.currentItemChanged.connect(self.display_changelog)
        if self.list_widget.count() > 0:
            self.list_widget.setCurrentRow(0)

    def populate_changelogs(self):
        history_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../History'))
        changelogs = []
        for fname in os.listdir(history_dir):
            if fname.startswith('CHANGELOG_') and fname.endswith('.md'):
                version = fname[len('CHANGELOG_'):-3]
                changelogs.append((version, os.path.join(history_dir, fname)))
        changelogs.sort(reverse=True)  # newest log first
        self.changelog_files = {v: p for v, p in changelogs}
        for version, _ in changelogs:
            self.list_widget.addItem(version)

    def display_changelog(self, current, previous):
        if not current:
            self.text_edit.clear()
            return
        version = current.text()
        path = self.changelog_files.get(version)
        if path and os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            html = markdown2.markdown(content)
            custom_css = '''
            <style>
            body { background: #181818; color: #fff; font-family: 'IBM Plex Mono', monospace; }
            h1, h2, h3 { color: #0077d4; }
            code, pre { background: #232323; color: #00ffea; border-radius: 6px; padding: 2px 6px; }
            ul, ol { margin-left: 20px; }
            strong { color: #ffd700; }
            em { color: #ffb347; }
            a { color: #4ec9b0; text-decoration: underline; }
            hr { border: 1px solid #333; }
            </style>
            '''
            self.text_edit.setHtml(custom_css + html)
        else:
            self.text_edit.setHtml("<i>[No Changelog found]</i>")
