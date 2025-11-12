#include <Core/Utils/Common.h>
#include <GUI/Panels.h>

RightPanel::RightPanel(QWidget* parent)
    : QFrame(parent)
{
    setStyleSheet(
        "QFrame {"
        " background: #252525;"
        " border-radius: 15px;"
        "}"
    );

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 20, 20, 20);

    headerLabel = new QLabel("Bind Console", this);
    headerLabel->setStyleSheet(
        "color: #0077d4; font-size: 16px; font-weight: bold; padding: 10px; background: rgba(72, 128, 168, 0.2); border-radius: 8px;"
    );
    layout->addWidget(headerLabel);

    outputText = new OutputPanel(this);
    layout->addWidget(outputText);
}

void RightPanel::appendOutput(const QString& text)
{
    outputText->appendText(text);
}

void RightPanel::clearOutput()
{
    outputText->clearText();
}