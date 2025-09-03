#include "include/GUI/Settings/Tabs/GeneralTab.h"
#include "include/GUI/Dialogs/HashCompareDialog.h"
#include "include/GUI/Dialogs/ConfirmationDialog.h"
#include "include/Core/Utils/PathUtils.h"
#include <QApplication>
#include <QDir>
#include <QFileInfo>
#include <QFileDialog>
#include <QStandardPaths>
#include <QProcess>
#include <QDateTime>
#include <QThread>
#include <algorithm>

GeneralTab::GeneralTab(QSettings* settings, QWidget* parent) 
    : QWidget(parent), 
      settings(settings),
      modeButtonGroup(nullptr),
      ntModeRadio(nullptr),
      zwModeRadio(nullptr),
      bindingsButtonGroup(nullptr),
      bindingsEnableRadio(nullptr),
      bindingsDisableRadio(nullptr),
      bindingsGroup(nullptr),
      inlineAssemblyGroup(nullptr),
      assemblyModeGroup(nullptr),
      directAssemblyRadio(nullptr),
      inlineAssemblyRadio(nullptr),
      indirectAssemblyRadio(nullptr),
      hashStubs(nullptr),
      createBackup(nullptr) {
    initUI();
}

void GeneralTab::initUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);
    QGroupBox* syscallModeGroup = new QGroupBox("Syscall Mode");
    QVBoxLayout* syscallModeLayout = new QVBoxLayout();
    QLabel* description = new QLabel("Select which syscall mode to use. This affects how syscalls are generated and processed.");
    description->setWordWrap(true);
    syscallModeLayout->addWidget(description);
    modeButtonGroup = new QButtonGroup(this);
    ntModeRadio = new QRadioButton("Nt Mode (User Mode)");
    ntModeRadio->setToolTip("Use Nt prefix for syscalls (default for user-mode applications)");
    zwModeRadio = new QRadioButton("Zw Mode (Kernel Mode)");
    zwModeRadio->setToolTip("Use Zw prefix for syscalls (primarily used in kernel-mode drivers)");
    originalMode = settings->value("general/syscall_mode", "Nt").toString();
    if (originalMode == "Zw") {
        zwModeRadio->setChecked(true);
    } else {
        ntModeRadio->setChecked(true);
    }
    modeButtonGroup->addButton(ntModeRadio);
    modeButtonGroup->addButton(zwModeRadio);
    syscallModeLayout->addWidget(ntModeRadio);
    syscallModeLayout->addWidget(zwModeRadio);
    syscallModeGroup->setLayout(syscallModeLayout);
    layout->addWidget(syscallModeGroup);
    connect(ntModeRadio, &QRadioButton::toggled, this, &GeneralTab::onModeChanged);
    connect(zwModeRadio, &QRadioButton::toggled, this, &GeneralTab::onModeChanged);
    bindingsGroup = new QGroupBox("Bindings");
    QVBoxLayout* bindingsLayout = new QVBoxLayout();
    QLabel* bindingsDesc = new QLabel("Enable or disable automatic generation of SysCaller.def for bindings.");
    bindingsDesc->setWordWrap(true);
    bindingsLayout->addWidget(bindingsDesc);
    bindingsButtonGroup = new QButtonGroup(this);
    bindingsEnableRadio = new QRadioButton("Enable");
    bindingsDisableRadio = new QRadioButton("Disable");
    bindingsButtonGroup->addButton(bindingsEnableRadio);
    bindingsButtonGroup->addButton(bindingsDisableRadio);
    bindingsLayout->addWidget(bindingsEnableRadio);
    bindingsLayout->addWidget(bindingsDisableRadio);
    bindingsGroup->setLayout(bindingsLayout);
    layout->addWidget(bindingsGroup);
    bool bindingsEnabled = settings->value("general/bindings_enabled", false).toBool();
    if (bindingsEnabled) {
        bindingsEnableRadio->setChecked(true);
    } else {
        bindingsDisableRadio->setChecked(true);
    }
    inlineAssemblyGroup = new QGroupBox("Assembly Mode");
    QVBoxLayout* inlineAssemblyLayout = new QVBoxLayout();
    QLabel* inlineDesc = new QLabel("Select the assembly mode for syscall generation.");
    inlineDesc->setWordWrap(true);
    inlineAssemblyLayout->addWidget(inlineDesc);
    QButtonGroup* assemblyModeGroup = new QButtonGroup(this);
    QRadioButton* directAssemblyRadio = new QRadioButton("Direct Assembly Mode (Default)");
    directAssemblyRadio->setToolTip("Use traditional instruction mnemonics for syscall stubs");
    QRadioButton* inlineAssemblyRadio = new QRadioButton("Inline Assembly Mode");
    inlineAssemblyRadio->setToolTip("Generate MASM compatible db-based stubs");
    QRadioButton* indirectAssemblyRadio = new QRadioButton("Indirect Assembly Mode");
    indirectAssemblyRadio->setToolTip("Generate runtime syscall resolution stubs for enhanced stealth");
    assemblyModeGroup->addButton(directAssemblyRadio);
    assemblyModeGroup->addButton(inlineAssemblyRadio);
    assemblyModeGroup->addButton(indirectAssemblyRadio);
    bool inlineEnabled = settings->value("general/inline_assembly", false).toBool();
    bool indirectEnabled = settings->value("general/indirect_assembly", false).toBool();
    
    if (inlineEnabled) {
        inlineAssemblyRadio->setChecked(true);
    } else if (indirectEnabled) {
        indirectAssemblyRadio->setChecked(true);
    } else {
        directAssemblyRadio->setChecked(true);
    }
    inlineAssemblyLayout->addWidget(directAssemblyRadio);
    inlineAssemblyLayout->addWidget(inlineAssemblyRadio);
    inlineAssemblyLayout->addWidget(indirectAssemblyRadio);
    this->directAssemblyRadio = directAssemblyRadio;
    this->inlineAssemblyRadio = inlineAssemblyRadio;
    this->indirectAssemblyRadio = indirectAssemblyRadio;
    this->assemblyModeGroup = assemblyModeGroup;
    connect(directAssemblyRadio, &QRadioButton::toggled, this, &GeneralTab::onAssemblyModeChanged);
    connect(inlineAssemblyRadio, &QRadioButton::toggled, this, &GeneralTab::onAssemblyModeChanged);
    connect(indirectAssemblyRadio, &QRadioButton::toggled, this, &GeneralTab::onAssemblyModeChanged);
    inlineAssemblyGroup->setLayout(inlineAssemblyLayout);
    layout->addWidget(inlineAssemblyGroup);
    QGroupBox* hashStubsGroup = new QGroupBox("Hash Stubs");
    QVBoxLayout* hashStubsLayout = new QVBoxLayout();
    QLabel* hashDesc = new QLabel("Optionally hash each stub/build with unique hash for future lookups.");
    hashDesc->setWordWrap(true);
    hashStubsLayout->addWidget(hashDesc);
    QPushButton* hashCompareBtn = new QPushButton("Hash Compare");
    hashCompareBtn->setToolTip("Compare hash files from different builds to identify changes");
    connect(hashCompareBtn, &QPushButton::clicked, this, &GeneralTab::openHashCompare);
    hashStubsLayout->addWidget(hashCompareBtn);
    hashStubs = new QCheckBox("Enable Hash Stubs");
    hashStubs->setChecked(settings->value("general/hash_stubs", false).toBool());
    hashStubs->setToolTip("If checked, will generate hashes for all stubs after obfuscation and save them to a JSON file in the Backups directory");
    hashStubsLayout->addWidget(hashStubs);
    hashStubsGroup->setLayout(hashStubsLayout);
    layout->addWidget(hashStubsGroup);
    QGroupBox* resetGroup = new QGroupBox("Reset to Default/Backup");
    QVBoxLayout* resetLayout = new QVBoxLayout();
    QLabel* resetDesc = new QLabel("Reset SysCaller to it's default state or restore from a backup. This will revert any changes made by obfuscation or manual editing.");
    resetDesc->setWordWrap(true);
    resetLayout->addWidget(resetDesc);
    QPushButton* restoreBtn = new QPushButton("Restore Files");
    restoreBtn->setMinimumHeight(40);
    connect(restoreBtn, &QPushButton::clicked, this, &GeneralTab::showRestoreOptions);
    resetLayout->addWidget(restoreBtn);
    createBackup = new QCheckBox("Create Backup");
    createBackup->setChecked(settings->value("general/create_backup", true).toBool());
    createBackup->setToolTip("If checked, will create backup files in the Backups directory before restoring defaults");
    resetLayout->addWidget(createBackup);
    resetGroup->setLayout(resetLayout);
    layout->addWidget(resetGroup);
    onModeChanged();
}

void GeneralTab::onModeChanged() {
    bool isKernelMode = zwModeRadio->isChecked();
    bindingsGroup->setVisible(!isKernelMode);
    inlineAssemblyGroup->setVisible(!isKernelMode);
    if (isKernelMode && bindingsEnableRadio->isChecked()) {
        bindingsDisableRadio->setChecked(true);
    }
    if (isKernelMode) {
        if (inlineAssemblyRadio && inlineAssemblyRadio->isChecked()) {
            directAssemblyRadio->setChecked(true);
        }
        if (indirectAssemblyRadio && indirectAssemblyRadio->isChecked()) {
            directAssemblyRadio->setChecked(true);
        }
        if (inlineAssemblyRadio) inlineAssemblyRadio->setEnabled(false);
        if (indirectAssemblyRadio) indirectAssemblyRadio->setEnabled(false);
        if (directAssemblyRadio) directAssemblyRadio->setEnabled(true);
    } else {
        if (inlineAssemblyRadio) inlineAssemblyRadio->setEnabled(true);
        if (indirectAssemblyRadio) indirectAssemblyRadio->setEnabled(true);
        if (directAssemblyRadio) directAssemblyRadio->setEnabled(true);
    }
}

void GeneralTab::onAssemblyModeChanged() {
}

void GeneralTab::saveSettings() {
    settings->setValue("general/create_backup", createBackup->isChecked());
    settings->setValue("general/hash_stubs", hashStubs->isChecked());
    settings->setValue("general/bindings_enabled", bindingsEnableRadio->isChecked());
    if (inlineAssemblyRadio && inlineAssemblyRadio->isChecked()) {
        settings->setValue("general/inline_assembly", true);
        settings->setValue("general/indirect_assembly", false);
    } else if (indirectAssemblyRadio && indirectAssemblyRadio->isChecked()) {
        settings->setValue("general/inline_assembly", false);
        settings->setValue("general/indirect_assembly", true);
    } else {
        settings->setValue("general/inline_assembly", false);
        settings->setValue("general/indirect_assembly", false);
    }
    QString newMode = zwModeRadio->isChecked() ? "Zw" : "Nt";
    bool modeChanged = newMode != originalMode;
    settings->setValue("general/syscall_mode", newMode);
    if (modeChanged) {
        ConfirmationDialog infoDialog("Bind - v1.3.0", this);
        infoDialog.setMessage(QString("The syscall mode has been changed from %1 to %2.\n\n"
                                    "This change affects which files are processed:\n"
                                    "- Nt Mode: User mode files in SysCaller directory\n"
                                    "- Zw Mode: Kernel mode files in SysCallerK directory\n\n"
                                    "Some changes may take full effect after a restart.").arg(originalMode, newMode));
        infoDialog.setButtons(false, false, true, false);
        infoDialog.exec();
    }
}

void GeneralTab::showRestoreOptions() {
    QMenu menu(this);
    menu.setStyleSheet(
        "QMenu {"
        " background-color: #333333;"
        " color: white;"
        " border: 1px solid #444444;"
        " border-radius: 5px;"
        " padding: 5px;"
        "}"
        "QMenu::item {"
        " background-color: transparent;"
        " padding: 8px 20px;"
        " border-radius: 4px;"
        "}"
        "QMenu::item:selected {"
        " background-color: #0b5394;"
        "}"
    );
    QAction* defaultAction = menu.addAction("Restore Default Files");
    connect(defaultAction, &QAction::triggered, this, &GeneralTab::restoreDefaultFiles);
    QStringList completeBackups = getAvailableBackups();
    if (!completeBackups.isEmpty()) {
        if (completeBackups.size() > 1) {
            QString latestTs = completeBackups.first();
            QString latestDate = formatTimestamp(latestTs);
            QAction* latestAction = menu.addAction(
                QString("Restore Latest Backup (%1)").arg(latestDate));
            connect(latestAction, &QAction::triggered, [this, latestTs]() {
                restoreBackup(latestTs);
            });
            QMenu* backupSubmenu = new QMenu("Select Backup", &menu);
            backupSubmenu->setStyleSheet(menu.styleSheet());
            for (const QString& ts : completeBackups) {
                QString dateStr = formatTimestamp(ts);
                QAction* action = backupSubmenu->addAction(QString("Backup from %1").arg(dateStr));
                connect(action, &QAction::triggered, [this, ts]() {
                    restoreBackup(ts);
                });
            }
            menu.addMenu(backupSubmenu);
        } else {
            QString ts = completeBackups.first();
            QString dateStr = formatTimestamp(ts);
            QAction* backupAction = menu.addAction(
                QString("Restore Backup (%1)").arg(dateStr));
            connect(backupAction, &QAction::triggered, [this, ts]() {
                restoreBackup(ts);
            });
        }
    } else {
        QAction* backupAction = menu.addAction("No Backups Available");
        backupAction->setEnabled(false);
    }
    menu.exec(QCursor::pos());
}

void GeneralTab::restoreDefaultFiles() {
    bool isKernelMode = settings->value("general/syscall_mode", "Nt").toString() == "Zw";
    QString modeText = isKernelMode ? "kernel mode" : "user mode";
    QString filePathText = isKernelMode ? "SysCallerK directory" : "SysCaller directory";
    QString headerName = isKernelMode ? "sysFunctions_k.h" : "sysFunctions.h";
    ConfirmationDialog confirmDialog("Bind - v1.3.0", this);
    confirmDialog.setMessage(QString("Are you sure you want to restore default %1 files?\n\n"
                                   "This will overwrite your current syscaller.asm and %2 files in the %3.")
                                   .arg(modeText, headerName, filePathText));

    if (confirmDialog.exec() != QDialog::Accepted || confirmDialog.getResult() != ConfirmationDialog::Yes) {
        return;
    }
    try {
        QString defaultAsmPath = PathUtils::getDefaultSysCallerAsmPath();
        QString defaultHeaderPath = PathUtils::getDefaultSysFunctionsPath(isKernelMode);
        QString asmPath = PathUtils::getSysCallerAsmPath(isKernelMode);
        QString headerPath = PathUtils::getSysFunctionsPath(isKernelMode);
        if (!QFile::exists(defaultAsmPath) || !QFile::exists(defaultHeaderPath)) {
            ConfirmationDialog warningDialog("Bind - v1.3.0", this);
            warningDialog.setMessage("Default files not found in Default directory.");
            warningDialog.setButtons(false, false, true, false);
            warningDialog.exec();
            return;
        }
        if (createBackup->isChecked()) {
            createBackupFiles();
        }
        if (QFile::exists(asmPath)) {
            QFile::remove(asmPath);
        }
        if (QFile::exists(headerPath)) {
            QFile::remove(headerPath);
        }
        bool asmCopied = QFile::copy(defaultAsmPath, asmPath);
        bool headerCopied = QFile::copy(defaultHeaderPath, headerPath);
        if (!asmCopied || !headerCopied) {
            ConfirmationDialog errorDialog("Bind - v1.3.0", this);
            errorDialog.setMessage(QString("Failed to copy files:\nASM: %1\nHeader: %2")
                                 .arg(asmCopied ? "Success" : "Failed")
                                 .arg(headerCopied ? "Success" : "Failed"));
            errorDialog.setButtons(false, false, true, false);
            errorDialog.exec();
            return;
        }
        ConfirmationDialog infoDialog("Bind - v1.3.0", this);
        infoDialog.setMessage(QString("Default %1 files have been restored successfully!").arg(modeText));
        infoDialog.setButtons(false, false, true, false);
        infoDialog.exec();
    } catch (...) {
        ConfirmationDialog errorDialog("Bind - v1.3.0", this);
        errorDialog.setMessage("An error occurred while restoring default files.");
        errorDialog.setButtons(false, true, false);
        errorDialog.exec();
    }
}

void GeneralTab::restoreBackup(const QString& timestamp) {
    try {
        QString backupsDir = PathUtils::getBackupsPath();
        QStringList completeBackups = getAvailableBackups();
        if (!completeBackups.contains(timestamp)) {
            ConfirmationDialog warningDialog("Bind - v1.3.0", this);
            warningDialog.setMessage(QString("Could not find complete backup set for timestamp %1").arg(timestamp));
            warningDialog.setButtons(false, false, true, false);
            warningDialog.exec();
            return;
        }
        QString backupAsmPath = QString("%1/syscaller_%2.asm").arg(backupsDir, timestamp);
        QString backupHeaderPath = QString("%1/sysFunctions_%2.h").arg(backupsDir, timestamp);
        QStringList missingFiles;
        if (!QFile::exists(backupAsmPath)) {
            missingFiles << QString("ASM file: %1").arg(backupAsmPath);
        }
        if (!QFile::exists(backupHeaderPath)) {
            missingFiles << QString("Header file: %1").arg(backupHeaderPath);
        }
        if (!missingFiles.isEmpty()) {
            ConfirmationDialog warningDialog("Bind - v1.3.0", this);
            warningDialog.setMessage(QString("Could not find the following backup files:\n%1").arg(missingFiles.join("\n")));
            warningDialog.setButtons(false, false, true, false);
            warningDialog.exec();
            return;
        }
        ConfirmationDialog confirmDialog("Bind - v1.3.0", this);
        confirmDialog.setMessage(QString("Are you sure you want to restore from backup files dated %1?\n\n"
                                       "This will overwrite your current syscaller.asm and sysFunctions.h files.")
                                       .arg(formatTimestamp(timestamp)));

        if (confirmDialog.exec() != QDialog::Accepted || confirmDialog.getResult() != ConfirmationDialog::Yes) {
            return;
        }
        bool isKernelMode = settings->value("general/syscall_mode", "Nt").toString() == "Zw";
        QString asmPath = PathUtils::getSysCallerAsmPath(isKernelMode);
        QString headerPath = PathUtils::getSysFunctionsPath(isKernelMode);
        QDir().mkpath(QFileInfo(asmPath).absolutePath());
        QDir().mkpath(QFileInfo(headerPath).absolutePath());
        if (QFile::exists(asmPath) && isFileLocked(asmPath)) {
            ConfirmationDialog warningDialog("Bind - v1.3.0", this);
            warningDialog.setMessage("The ASM file appears to be locked by another process. Close any applications that might be using it and try again.");
            warningDialog.setButtons(false, false, true, false);
            warningDialog.exec();
            return;
        }
        if (QFile::exists(headerPath) && isFileLocked(headerPath)) {
            ConfirmationDialog warningDialog("Bind - v1.3.0", this);
            warningDialog.setMessage("The header file appears to be locked by another process. Close any applications that might be using it and try again.");
            warningDialog.setButtons(false, false, true, false);
            warningDialog.exec();
            return;
        }
        if (createBackup->isChecked()) {
            createBackupFiles();
        }
        bool asmRestored = false;
        bool headerRestored = false;
        asmRestored = restoreFileWithRetry(backupAsmPath, asmPath, "ASM");
        if (!asmRestored) {
            if (QFile::exists(asmPath)) {
                QFile::remove(asmPath);
            }
            asmRestored = QFile::copy(backupAsmPath, asmPath);
        }
        headerRestored = restoreFileWithRetry(backupHeaderPath, headerPath, "Header");
        if (!headerRestored) {
            if (QFile::exists(headerPath)) {
                QFile::remove(headerPath);
            }
            headerRestored = QFile::copy(backupHeaderPath, headerPath);
        }
        if (asmRestored && headerRestored) {
            ConfirmationDialog infoDialog("Bind - v1.3.0", this);
            infoDialog.setMessage(QString("Files have been restored from backup successfully!\n\nBackup date: %1")
                                .arg(formatTimestamp(timestamp)));
            infoDialog.setButtons(false, false, true, false);
            infoDialog.exec();
        } else if (!asmRestored && headerRestored) {
            ConfirmationDialog warningDialog("Bind - v1.3.0", this);
            warningDialog.setMessage("Only the header file was restored successfully. The ASM file could not be restored.");
            warningDialog.setButtons(false, false, true, false);
            warningDialog.exec();
        } else if (asmRestored && !headerRestored) {
            ConfirmationDialog warningDialog("Bind - v1.3.0", this);
            warningDialog.setMessage("Only the ASM file was restored successfully. The header file could not be restored.");
            warningDialog.setButtons(false, false, true, false);
            warningDialog.exec();
        } else {
            ConfirmationDialog errorDialog("Bind - v1.3.0", this);
            errorDialog.setMessage("Failed to restore both files from backup.");
            errorDialog.setButtons(false, false, true, false);
            errorDialog.exec();
        }
    } catch (...) {
        ConfirmationDialog errorDialog("Bind - v1.3.0", this);
        errorDialog.setMessage("An error occurred while restoring backup files.");
        errorDialog.setButtons(false, true, false);
        errorDialog.exec();
    }
}

void GeneralTab::openHashCompare() {
    HashCompareDialog dialog(this);
    dialog.exec();
}

QString GeneralTab::formatTimestamp(const QString& timestamp) {
    if (timestamp.contains('_')) {
        QStringList parts = timestamp.split('_');
        if (parts.size() >= 2) {
            QString datePart = parts[0];
            QString timePart = parts[1];
            if (datePart.length() >= 8 && timePart.length() >= 4) {
                QString year = datePart.mid(0, 4);
                QString month = datePart.mid(4, 2);
                QString day = datePart.mid(6, 2);
                QString hour = timePart.mid(0, 2);
                QString minute = timePart.mid(2, 2);
                return QString("%1-%2-%3 %4:%5").arg(year, month, day, hour, minute);
            }
        }
    }
    return timestamp;
}

QString GeneralTab::getIniPath() {
    return PathUtils::getIniPath();
}

bool GeneralTab::isFileLocked(const QString& filePath) {
    if (!QFile::exists(filePath)) {
        return false;
    }
    QFile file(filePath);
    if (!file.open(QIODevice::ReadWrite)) {
        return true;
    }
    file.close();
    return false;
}

QStringList GeneralTab::getAvailableBackups() {
    QStringList completeBackups;
    QString backupsDir = PathUtils::getBackupsPath();
    QDir dir(backupsDir);
    if (!dir.exists()) {
        return completeBackups;
    }
    QStringList filters;
    filters << "syscaller_*.asm";
    QFileInfoList asmFiles = dir.entryInfoList(filters, QDir::Files);
    for (const QFileInfo& asmFile : asmFiles) {
        QString fileName = asmFile.fileName();
        if (fileName.startsWith("syscaller_") && fileName.endsWith(".asm")) {
            QString timestamp = fileName.mid(10, fileName.length() - 14);
            QString headerFile = QString("sysFunctions_%1.h").arg(timestamp);
            QString headerPath = QString("%1/%2").arg(backupsDir, headerFile);
            if (QFile::exists(headerPath)) {
                completeBackups.append(timestamp);
            }
        }
    }
    std::sort(completeBackups.begin(), completeBackups.end(), std::greater<QString>());
    return completeBackups;
}

void GeneralTab::createBackupFiles() {
    try {
        QString backupsDir = PathUtils::getBackupsPath();
        QDir().mkpath(backupsDir);
        QDateTime now = QDateTime::currentDateTime();
        QString timestamp = now.toString("yyyyMMdd_HHmmss");
        bool isKernelMode = settings->value("general/syscall_mode", "Nt").toString() == "Zw";
        QString asmPath = PathUtils::getSysCallerAsmPath(isKernelMode);
        QString headerPath = PathUtils::getSysFunctionsPath(isKernelMode);
        QString backupAsmPath = QString("%1/syscaller_%2.asm").arg(backupsDir, timestamp);
        QString backupHeaderPath = QString("%1/sysFunctions_%2.h").arg(backupsDir, timestamp);
        if (QFile::exists(asmPath)) {
            QFile::copy(asmPath, backupAsmPath);
        }
        if (QFile::exists(headerPath)) {
            QFile::copy(headerPath, backupHeaderPath);
        }
    } catch (...) {
        // backup creation failed but dont stop the operation
    }
}

bool GeneralTab::restoreFileWithRetry(const QString& sourcePath, const QString& destPath, const QString& fileType) {
    const int maxRetries = 3;
    int retryCount = 0;
    while (retryCount < maxRetries) {
        try {
            if (QFile::exists(destPath)) {
                QFile::remove(destPath);
            }
            if (QFile::copy(sourcePath, destPath)) {
                if (QFile::exists(destPath)) {
                    QFileInfo destInfo(destPath);
                    QFileInfo sourceInfo(sourcePath);
                    if (destInfo.size() > 0 && destInfo.size() == sourceInfo.size()) {
                        return true;
                    }
                }
            }
            retryCount++;
            if (retryCount < maxRetries) {
                QThread::msleep(1000);
            }
        } catch (...) {
            retryCount++;
            if (retryCount < maxRetries) {
                QThread::msleep(1000);
            }
        }
    }
    return false;
}
