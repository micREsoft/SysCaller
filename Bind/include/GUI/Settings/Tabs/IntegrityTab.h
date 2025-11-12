#pragma once

#include <QCheckBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QSettings>
#include <QVBoxLayout>
#include <QWidget>

class IntegrityTab : public QWidget {
    Q_OBJECT

public:
    explicit IntegrityTab(QSettings* settings, QWidget* parent = nullptr);

    void saveSettings();

private slots:
    void loadSyscalls();
    void selectAllSyscalls();
    void selectNoSyscalls();
    void filterSyscalls(const QString& text);

private:
    void initUI();
    QSettings* settings;
    QListWidget* syscallList;
    QLineEdit* filterEdit;
    QStringList syscalls;
};