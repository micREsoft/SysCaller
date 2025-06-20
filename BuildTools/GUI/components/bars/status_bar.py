from PyQt5.QtWidgets import QFrame, QLabel, QHBoxLayout

class StatusBar(QFrame):
    def __init__(self):
        super().__init__()
        self.setMaximumHeight(40)
        self.setStyleSheet("""
            QFrame {
                background: #252525;
                border-bottom-left-radius: 15px;
                border-bottom-right-radius: 15px;
            }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)
        self.status_icon = QLabel("⏺")
        self.status_icon.setStyleSheet("color: #666666; font-size: 16px;")
        layout.addWidget(self.status_icon)
        self.status_msg = QLabel("Ready")
        self.status_msg.setStyleSheet("color: #666666; font-size: 12px;")
        layout.addWidget(self.status_msg)
        layout.addStretch()
        self.result_label = QLabel()
        self.result_label.setStyleSheet("""
            QLabel {
                color: #666666;
                font-size: 12px;
                padding: 5px 10px;
                border-radius: 5px;
                background: rgba(37, 37, 37, 0.5);
            }
        """)
        layout.addWidget(self.result_label)

    def update_status(self, message, status_type="info"):
        color_map = {
            "success": ("#00CA4E", "✓"),
            "error": ("#FF605C", "✕"),
            "info": ("#666666", "⏺"),
            "working": ("#FFB900", "⟳")
        }
        color, icon = color_map.get(status_type, color_map["info"])
        self.status_icon.setStyleSheet(f"color: {color}; font-size: 16px;")
        self.status_icon.setText(icon)
        self.status_msg.setText(message)

    def set_result(self, valid, invalid, duplicates):
        if invalid == 0 and duplicates == 0:
            status = "success"
            result = f"Last Check: Passed ✅ ({valid} valid syscalls)"
        else:
            status = "error"
            result = f"Last Check: Issues Found ❌ ({invalid} invalid, {duplicates} duplicates)"
        self.result_label.setText(result)
        self.update_status("Ready", status) 