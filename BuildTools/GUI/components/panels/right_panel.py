from PyQt5.QtWidgets import QFrame, QVBoxLayout, QLabel
from PyQt5.QtCore import Qt
from components.panels.output import SysCallerOutput

class RightPanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
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