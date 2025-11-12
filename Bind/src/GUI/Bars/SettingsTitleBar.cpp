#include <Core/Utils/Common.h>
#include <GUI/Bars.h>

SettingsTitleBar::SettingsTitleBar(QWidget* parent)
    : QFrame(parent)
{
    initTitleBar("Settings");
}

SettingsTitleBar::SettingsTitleBar(const QString& title, QWidget* parent)
    : QFrame(parent)
{
    initTitleBar(title);
}

void SettingsTitleBar::initTitleBar(const QString& title)
{
    setMaximumHeight(60);
    setStyleSheet("QFrame {"
                  " background: #252525;"
                  " border-top-left-radius: 15px;"
                  " border-top-right-radius: 15px;"
                  "}");

    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(5, 0, 5, 0);

    auto* titleLabel = new QLabel(title, this);
    titleLabel->setStyleSheet("color: white; font-size: 16px; font-weight: bold;");

    layout->addWidget(titleLabel);
    layout->addStretch();

    auto* closeBtn = new QToolButton(this);
    closeBtn->setStyleSheet("QToolButton { background: #FF605C; border-radius: 7px; width: 14px; height: 14px; }"
                            "QToolButton:hover { background: #FF8078; }");

    connect(closeBtn, &QToolButton::clicked, this, &SettingsTitleBar::closeClicked);
    layout->addWidget(closeBtn);
}