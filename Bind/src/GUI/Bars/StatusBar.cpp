#include "include/GUI/Bars/StatusBar.h"
#include <QHBoxLayout>
#include <QLabel>

StatusBar::StatusBar(QWidget* parent)
    : QFrame(parent)
{
    setMaximumHeight(40);
    setStyleSheet("QFrame {"
                  " background: #252525;"
                  " border-bottom-left-radius: 15px;"
                  " border-bottom-right-radius: 15px;"
                  "}");

    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(20, 0, 20, 0);

    statusIcon = new QLabel("⏺", this);
    statusIcon->setStyleSheet("color: #666666; font-size: 16px;");

    layout->addWidget(statusIcon);

    statusMsg = new QLabel("Ready", this);
    statusMsg->setStyleSheet("color: #666666; font-size: 12px;");

    layout->addWidget(statusMsg);
    layout->addStretch();

    resultLabel = new QLabel(this);
    resultLabel->setStyleSheet("QLabel {"
                               " color: #666666;"
                               " font-size: 12px;"
                               " padding: 5px 10px;"
                               " border-radius: 5px;"
                               " background: rgba(37, 37, 37, 0.5);"
                               "}");

    layout->addWidget(resultLabel);
}

void StatusBar::updateStatus(const QString& message, const QString& statusType)
{
    statusMsg->setText(message);

    QString icon, color;

    if (statusType == "working")
    {
        icon = "⏳";
        color = "#FFA500"; // orange
    }
    else if (statusType == "success")
    {
        icon = "✅";
        color = "#00FF00"; // green
    }
    else if (statusType == "error")
    {
        icon = "❌";
        color = "#FF0000"; // red
    }
    else
    {
        icon = "⏺";
        color = "#666666"; // gray
    }

    statusIcon->setText(icon);
    statusIcon->setStyleSheet(QString("color: %1; font-size: 16px;").arg(color));
}