#pragma once

#include <QFrame>

class QLabel;
class OutputPanel;
class QVBoxLayout;

class RightPanel : public QFrame {
    Q_OBJECT
    
public:
    explicit RightPanel(QWidget* parent = nullptr);
    void appendOutput(const QString& text);
    void clearOutput();
    OutputPanel* getOutputPanel() const { return outputText; }

private:
    QLabel* headerLabel;
    OutputPanel* outputText;
};