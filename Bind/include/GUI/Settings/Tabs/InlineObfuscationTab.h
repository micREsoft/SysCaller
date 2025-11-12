#pragma once

#include <QSettings>
#include <QWidget>

class InlineObfuscationTab : public QWidget {
    Q_OBJECT

public:
    explicit InlineObfuscationTab(QSettings* settings, QWidget* parent = nullptr);
    
    void saveSettings();

private:
    void initUI();

    QSettings* settings;
};