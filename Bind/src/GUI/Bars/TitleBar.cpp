#include "include/GUI/Bars/TitleBar.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QToolButton>
#include <QStyle>
#include <QApplication>

TitleBar::TitleBar(QWidget* parent)
    : QFrame(parent)
{
    setMaximumHeight(60);
    setStyleSheet("QFrame {"
                  " background: #252525;"
                  " border-top-left-radius: 15px;"
                  " border-top-right-radius: 15px;"
                  "}");

    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(0, 0, 5, 0);

    auto* title = new QLabel("", this);
    title->setStyleSheet("color: white; font-size: 16px; font-weight: bold;");

    layout->addWidget(title);

    auto* controlsLayout = new QHBoxLayout();
    controlsLayout->setSpacing(15);

    auto* minimizeBtn = new QToolButton(this);
    minimizeBtn->setStyleSheet("QToolButton { background: #FFB900; border-radius: 7px; width: 14px; height: 14px; }"
                               "QToolButton:hover { background: #FFC933; }");

    connect(minimizeBtn, &QToolButton::clicked, this, &TitleBar::minimizeClicked);

    auto* maximizeBtn = new QToolButton(this);
    maximizeBtn->setStyleSheet("QToolButton { background: #00CA4E; border-radius: 7px; width: 14px; height: 14px; }"
                               "QToolButton:hover { background: #00E45B; }");

    connect(maximizeBtn, &QToolButton::clicked, this, &TitleBar::maximizeClicked);

    auto* closeBtn = new QToolButton(this);
    closeBtn->setStyleSheet("QToolButton { background: #FF605C; border-radius: 7px; width: 14px; height: 14px; }"
                            "QToolButton:hover { background: #FF8078; }");

    connect(closeBtn, &QToolButton::clicked, this, &TitleBar::closeClicked);

    controlsLayout->addWidget(minimizeBtn);
    controlsLayout->addWidget(maximizeBtn);
    controlsLayout->addWidget(closeBtn);
    layout->addLayout(controlsLayout);
}
