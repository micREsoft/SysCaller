#pragma once
#include <QFrame>

class TitleBar : public QFrame {
    Q_OBJECT
    
public:
    explicit TitleBar(QWidget* parent = nullptr);

signals:
    void minimizeClicked();
    void maximizeClicked();
    void closeClicked();
};