#pragma once
#include <QProgressBar>

class ProgressBar : public QProgressBar {
    Q_OBJECT
public:
    explicit ProgressBar(QWidget* parent = nullptr);
};