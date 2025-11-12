#include <GUI/Panels.h>

OutputPanel::OutputPanel(QWidget* parent)
    : QTextEdit(parent)
{
    setReadOnly(true);
    setStyleSheet(
        "QTextEdit {"
        " background: #1A1A1A;"
        " color: #FFFFFF;"
        " border: none;"
        " font-family: 'IBM Plex Mono';"
        " font-size: 12px;"
        "}"
    );
}

void OutputPanel::appendText(const QString& text)
{
    append(text);
    QTextCursor cursor = textCursor();
    cursor.movePosition(QTextCursor::End);
    setTextCursor(cursor);
}

void OutputPanel::clearText()
{
    clear();
}