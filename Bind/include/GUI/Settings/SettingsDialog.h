#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QPushButton>
#include <QSettings>

class GeneralTab;
class ObfuscationTab;
class IntegrityTab;
class ProfileTab;

class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget* parent = nullptr);

private slots:
    void saveSettings();
    void openStubMapper();

private:
    void initUI();
    void setupStylesheet();
    QSettings* settings;
    QTabWidget* tabs;
    GeneralTab* generalTab;
    ObfuscationTab* obfuscationTab;
    IntegrityTab* integrityTab;
    ProfileTab* profileTab;
};

#endif