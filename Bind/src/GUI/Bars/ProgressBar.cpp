#include "include/GUI/Bars/ProgressBar.h"

ProgressBar::ProgressBar(QWidget* parent) : QProgressBar(parent) {
    setTextVisible(false);
    setMaximumHeight(4);
    setStyleSheet(
        "QProgressBar {"
        " border: none;"
        " background: rgba(68, 68, 68, 0.5);"
        " border-radius: 2px;"
        "}"
        "QProgressBar::chunk {"
        " background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0b5394, stop:1 #67abdb);"
        " border-radius: 2px;"
        "}"
    );
}