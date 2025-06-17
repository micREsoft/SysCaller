from PyQt5.QtWidgets import QPushButton, QGraphicsDropShadowEffect
from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QFont, QColor, QIcon

class SysCallerButton(QPushButton):
    def __init__(self, text, icon_path=None, tooltip=None, tooltip_detail=None):
        super().__init__(text)
        self.setFont(QFont(None, 10))
        self.setMinimumHeight(45)
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
