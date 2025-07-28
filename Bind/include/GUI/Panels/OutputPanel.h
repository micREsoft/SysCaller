#pragma once
#include <QTextEdit>

class OutputPanel : public QTextEdit {
    Q_OBJECT
public:
    explicit OutputPanel(QWidget* parent = nullptr);
    void appendText(const QString& text);
    void clearText();
}; 