#pragma once

#include <QWidget>
#include <QSettings>

class InlineObfuscationTab : public QWidget {
    Q_OBJECT

public:
    explicit InlineObfuscationTab(QSettings* settings, QWidget* parent = nullptr);
    
    void saveSettings();

private:
    void initUI();

    QSettings* settings;
};
