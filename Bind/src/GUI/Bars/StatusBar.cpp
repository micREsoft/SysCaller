#include <Core/Utils/Common.h>
#include <GUI/Bars.h>

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

    statusIcon = new QLabel(this);
    statusIcon->setFixedSize(16, 16);
    statusIcon->setScaledContents(true);
    QPixmap recordPixmap(":/Icons/record.png");
    statusIcon->setPixmap(recordPixmap.scaled(16, 16, Qt::KeepAspectRatio, Qt::SmoothTransformation));

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

    QString iconPath;
    QString color;

    if (statusType == "working")
    {
        iconPath = ":/Icons/hourglass.png";
        color = "#FFA500"; /* orange */
    }
    else if (statusType == "success")
    {
        iconPath = ":/Icons/green.png";
        color = "#00FF00"; /* green */
    }
    else if (statusType == "error")
    {
        iconPath = ":/Icons/xmark.png";
        color = "#FF0000"; /* red */
    }
    else
    {
        iconPath = ":/Icons/record.png";
        color = "#666666"; /* gray */
    }

    QPixmap pixmap(iconPath);
    if (!pixmap.isNull())
    {
        statusIcon->setPixmap(pixmap.scaled(16, 16, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
}