from PyQt5.QtWidgets import QProgressBar

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