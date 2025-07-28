#ifndef INTEGRITYTAB_H
#define INTEGRITYTAB_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QPushButton>
#include <QListWidget>
#include <QLineEdit>
#include <QCheckBox>
#include <QSettings>

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

#endif