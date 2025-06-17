from PyQt5.QtWidgets import QTextEdit

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
