#pragma once

#include <QFrame>

class QLabel;

class StatusBar : public QFrame {
    Q_OBJECT

public:
    explicit StatusBar(QWidget* parent = nullptr);
    void updateStatus(const QString& message, const QString& statusType = "info");

private:
    QLabel* statusIcon;
    QLabel* statusMsg;
    QLabel* resultLabel;
};