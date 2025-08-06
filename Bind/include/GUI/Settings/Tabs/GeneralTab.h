#ifndef GENERALTAB_H
#define GENERALTAB_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QPushButton>
#include <QRadioButton>
#include <QButtonGroup>
#include <QCheckBox>
#include <QMessageBox>
#include <QMenu>
#include <QSettings>

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
    QGroupBox* indirectAssemblyGroup;
    QCheckBox* hashStubs;
    QCheckBox* createBackup;
    QCheckBox* inlineAssembly;
    QCheckBox* indirectAssembly;
};

#endif
