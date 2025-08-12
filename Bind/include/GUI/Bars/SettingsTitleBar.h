#pragma once
#include <QFrame>

class SettingsTitleBar : public QFrame {
    Q_OBJECT
    
public:
    explicit SettingsTitleBar(QWidget* parent = nullptr);
    explicit SettingsTitleBar(const QString& title, QWidget* parent = nullptr);

signals:
    void closeClicked();

private:
    void initTitleBar(const QString& title);
};
