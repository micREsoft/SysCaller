from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel, QToolButton
from PyQt5.QtCore import Qt

class TitleBar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setMaximumHeight(60)
        self.setStyleSheet("""
            QFrame {
                background: #252525;
                border-top-left-radius: 15px;
                border-top-right-radius: 15px;
            }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)
        title = QLabel("1.1.0")
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
        minimize_btn.clicked.connect(self.minimize_window)
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
        close_btn.clicked.connect(self.close_window)
        controls_layout.addWidget(minimize_btn)
        controls_layout.addWidget(maximize_btn)
        controls_layout.addWidget(close_btn)
        layout.addLayout(controls_layout)
        
    def minimize_window(self):
        if self.parent:
            self.parent.showMinimized()
            
    def toggle_maximize(self):
        if self.parent:
            if self.parent.isMaximized():
                self.parent.showNormal()
            else:
                self.parent.showMaximized()
                
    def close_window(self):
        if self.parent:
            self.parent.close() 
