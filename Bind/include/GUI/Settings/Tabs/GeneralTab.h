#pragma once

#include <QButtonGroup>
#include <QCheckBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QRadioButton>
#include <QSettings>
#include <QVBoxLayout>
#include <QWidget>

class GeneralTab : public QWidget {
    Q_OBJECT

public:
    explicit GeneralTab(QSettings* settings, QWidget* parent = nullptr);

    void saveSettings();

private slots:
    void showRestoreOptions();
    void restoreDefaultFiles();
    void restoreBackup(const QString& timestamp);
    void openHashCompare();
    void onModeChanged();

private:
    void initUI();
    bool validateSettings();
    QString formatTimestamp(const QString& timestamp);
    QString getIniPath();
    bool isFileLocked(const QString& filePath);
    QStringList getAvailableBackups();
    void createBackupFiles();
    bool restoreFileWithRetry(const QString& sourcePath, const QString& destPath, const QString& fileType);

    QSettings* settings;
    QButtonGroup* modeButtonGroup;
    QRadioButton* ntModeRadio;
    QRadioButton* zwModeRadio;
    QString originalMode;
    QButtonGroup* bindingsButtonGroup;
    QRadioButton* bindingsEnableRadio;
    QRadioButton* bindingsDisableRadio;
    QGroupBox* bindingsGroup;
    QGroupBox* inlineAssemblyGroup;
    QButtonGroup* assemblyModeGroup;
    QRadioButton* directAssemblyRadio;
    QRadioButton* inlineAssemblyRadio;
    QRadioButton* indirectAssemblyRadio;
    QCheckBox* hashStubs;
    QCheckBox* createBackup;
};