#include <Core/Utils/Common.h>
#include <GUI/Buttons.h>

BindButton::BindButton(const QString& text,
                       const QString& iconPath,
                       const QString& title,
                       const QString& description,
                       QWidget* parent)
    : QPushButton(text, parent)
    , title(title)
    , description(description)
{
    setIcon(QIcon(iconPath));
    setIconSize(QSize(16, 16));
    setMinimumHeight(40);
    setToolTip(QString("<b>%1</b><br>%2").arg(title, description));
    setupStyle();
}

void BindButton::setupStyle()
{
    setStyleSheet("QPushButton {"
                  " background: #0b5394;"
                  " border: none;"
                  " border-radius: 8px;"
                  " padding: 10px 15px;"
                  " color: white;"
                  " font-family: 'IBM Plex Mono';"
                  " font-size: 11px;"
                  " font-weight: bold;"
                  " text-align: left;"
                  "}"
                  "QPushButton:hover {"
                  " background: #67abdb;"
                  "}"
                  "QPushButton:pressed {"
                  " background: #0A7AD1;"
                  "}"
                  "QPushButton:disabled {"
                  " background: #333333;"
                  " color: #666666;"
                  "}"
                  "QPushButton:disabled:hover {"
                  " background: #333333;"
                  "}");
}