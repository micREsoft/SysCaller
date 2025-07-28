#include "include/GUI/Dialogs/StubMapperDialog.h"
#include "include/Core/Utils/PathUtils.h"
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QFont>
#include <QPalette>
#include <QApplication>

StubMapperDialog::StubMapperDialog(QWidget* parent)
    : QDialog(parent)
    , settings(new QSettings(PathUtils::getIniPath(), QSettings::IniFormat))
{
    setWindowTitle("Bind - Stub Mapper");
    setMinimumWidth(800);
    setMinimumHeight(600);
    loadSyscallSettings();
    initUI();
}

StubMapperDialog::~StubMapperDialog() {
    delete settings;
}

void StubMapperDialog::initUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);
    QSplitter* splitter = new QSplitter(Qt::Horizontal);
    QWidget* leftPanel = new QWidget();
    QVBoxLayout* leftLayout = new QVBoxLayout(leftPanel);
    QGroupBox* syscallGroup = new QGroupBox("Available Syscalls");
    QVBoxLayout* syscallLayout = new QVBoxLayout();
    QHBoxLayout* filterLayout = new QHBoxLayout();
    QLabel* filterLabel = new QLabel("Filter:");
    filterInput = new QLineEdit();
    filterInput->setPlaceholderText("Filter Syscalls...");
    connect(filterInput, &QLineEdit::textChanged, this, &StubMapperDialog::filterSyscalls);
    filterLayout->addWidget(filterLabel);
    filterLayout->addWidget(filterInput);
    syscallLayout->addLayout(filterLayout);
    syscallList = new QListWidget();
    connect(syscallList, &QListWidget::currentItemChanged, this, &StubMapperDialog::onSyscallSelected);
    loadSyscalls();
    syscallLayout->addWidget(syscallList);
    syscallGroup->setLayout(syscallLayout);
    leftLayout->addWidget(syscallGroup);
    QWidget* rightPanel = new QWidget();
    QVBoxLayout* rightLayout = new QVBoxLayout(rightPanel);
    QGroupBox* settingsGroup = new QGroupBox("Stub Configuration");
    QVBoxLayout* settingsLayout = new QVBoxLayout();
    currentSyscallLabel = new QLabel("Select a Syscall from the list");
    QFont boldFont = currentSyscallLabel->font();
    boldFont.setBold(true);
    currentSyscallLabel->setFont(boldFont);
    settingsLayout->addWidget(currentSyscallLabel);
    settingsTabs = new QTabWidget();
    QWidget* junkTab = new QWidget();
    QFormLayout* junkLayout = new QFormLayout(junkTab);
    enableJunk = new QCheckBox("Enable Junk Instructions");
    connect(enableJunk, &QCheckBox::stateChanged, this, &StubMapperDialog::onSettingChanged);
    junkLayout->addRow(enableJunk);
    minInstructions = new QSpinBox();
    minInstructions->setRange(1, 10);
    minInstructions->setValue(2);
    connect(minInstructions, QOverload<int>::of(&QSpinBox::valueChanged), this, &StubMapperDialog::onSettingChanged);
    junkLayout->addRow("Minimum Instructions:", minInstructions);
    maxInstructions = new QSpinBox();
    maxInstructions->setRange(1, 20);
    maxInstructions->setValue(8);
    connect(maxInstructions, QOverload<int>::of(&QSpinBox::valueChanged), this, &StubMapperDialog::onSettingChanged);
    junkLayout->addRow("Maximum Instructions:", maxInstructions);
    useAdvancedJunk = new QCheckBox("Advanced Junk Instructions");
    connect(useAdvancedJunk, &QCheckBox::stateChanged, this, &StubMapperDialog::onSettingChanged);
    junkLayout->addRow(useAdvancedJunk);
    QWidget* encryptionTab = new QWidget();
    QFormLayout* encryptionLayout = new QFormLayout(encryptionTab);
    enableEncryption = new QCheckBox("Enable Syscall ID Encryption");
    connect(enableEncryption, &QCheckBox::stateChanged, this, &StubMapperDialog::onSettingChanged);
    encryptionLayout->addRow(enableEncryption);
    encryptionMethod = new QComboBox();
    encryptionMethod->addItem("Basic XOR (Simple)", 1);
    encryptionMethod->addItem("Multi-Key XOR (Medium)", 2);
    encryptionMethod->addItem("Add + XOR (Medium)", 3);
    encryptionMethod->addItem("Enhanced XOR (Medium)", 4);
    encryptionMethod->addItem("Offset Shifting (Medium)", 5);
    connect(encryptionMethod, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &StubMapperDialog::onSettingChanged);
    encryptionLayout->addRow("Encryption Method:", encryptionMethod);
    QWidget* structureTab = new QWidget();
    QFormLayout* structureLayout = new QFormLayout(structureTab);
    enableChunking = new QCheckBox("Enable Function Chunking");
    connect(enableChunking, &QCheckBox::stateChanged, this, &StubMapperDialog::onSettingChanged);
    structureLayout->addRow(enableChunking);
    enableInterleaved = new QCheckBox("Enable Interleaved Execution");
    connect(enableInterleaved, &QCheckBox::stateChanged, this, &StubMapperDialog::onSettingChanged);
    structureLayout->addRow(enableInterleaved);
    shuffleSequence = new QCheckBox("Enable Sequence Shuffling");
    connect(shuffleSequence, &QCheckBox::stateChanged, this, &StubMapperDialog::onSettingChanged);
    structureLayout->addRow(shuffleSequence);
    QWidget* nameTab = new QWidget();
    QFormLayout* nameLayout = new QFormLayout(nameTab);
    QHBoxLayout* syscallNameLayout = new QHBoxLayout();
    syscallPrefixLength = new QSpinBox();
    syscallPrefixLength->setRange(4, 16);
    syscallPrefixLength->setValue(8);
    connect(syscallPrefixLength, QOverload<int>::of(&QSpinBox::valueChanged), this, &StubMapperDialog::onSettingChanged);
    syscallNumberLength = new QSpinBox();
    syscallNumberLength->setRange(4, 16);
    syscallNumberLength->setValue(6);
    connect(syscallNumberLength, QOverload<int>::of(&QSpinBox::valueChanged), this, &StubMapperDialog::onSettingChanged);
    syscallNameLayout->addWidget(new QLabel("Chars:"));
    syscallNameLayout->addWidget(syscallPrefixLength);
    syscallNameLayout->addWidget(new QLabel("Numbers:"));
    syscallNameLayout->addWidget(syscallNumberLength);
    nameLayout->addRow("Syscall Name Length:", syscallNameLayout);
    offsetNameLength = new QSpinBox();
    offsetNameLength->setRange(4, 16);
    offsetNameLength->setValue(8);
    connect(offsetNameLength, QOverload<int>::of(&QSpinBox::valueChanged), this, &StubMapperDialog::onSettingChanged);
    nameLayout->addRow("Offset Name Length:", offsetNameLength);
    settingsTabs->addTab(junkTab, "Junk Instructions");
    settingsTabs->addTab(encryptionTab, "Encryption");
    settingsTabs->addTab(structureTab, "Structure");
    settingsTabs->addTab(nameTab, "Name Randomization");
    settingsLayout->addWidget(settingsTabs);
    settingsGroup->setLayout(settingsLayout);
    rightLayout->addWidget(settingsGroup);
    splitter->addWidget(leftPanel);
    splitter->addWidget(rightPanel);
    splitter->setSizes({300, 500});
    layout->addWidget(splitter);
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    useGlobalBtn = new QPushButton("Use Global Settings");
    connect(useGlobalBtn, &QPushButton::clicked, this, &StubMapperDialog::useGlobalSettings);
    resetBtn = new QPushButton("Reset");
    connect(resetBtn, &QPushButton::clicked, this, &StubMapperDialog::resetCurrentSettings);
    QPushButton* validateBtn = new QPushButton("Validate");
    connect(validateBtn, &QPushButton::clicked, this, &StubMapperDialog::validateCurrentSettings);
    QPushButton* saveBtn = new QPushButton("Save");
    connect(saveBtn, &QPushButton::clicked, this, &StubMapperDialog::saveSettings);
    QPushButton* cancelBtn = new QPushButton("Cancel");
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(useGlobalBtn);
    buttonLayout->addWidget(resetBtn);
    buttonLayout->addWidget(validateBtn);
    buttonLayout->addStretch();
    buttonLayout->addWidget(saveBtn);
    buttonLayout->addWidget(cancelBtn);
    layout->addLayout(buttonLayout);
    setStyleSheet(R"(
        QDialog {
            background: #252525;
            color: white;
        }
        QTabWidget::pane {
            border: 1px solid #333333;
            border-radius: 5px;
            background: #1E1E1E;
        }
        QTabBar::tab {
            background: #333333;
            color: white;
            padding: 8px 20px;
            border-top-left-radius: 5px;
            border-top-right-radius: 5px;
        }
        QTabBar::tab:selected {
            background: #0b5394;
        }
        QGroupBox {
            border: 1px solid #333333;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 15px;
            color: white;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
        QSpinBox {
            background: #333333;
            border: none;
            border-radius: 3px;
            padding: 5px;
            color: white;
        }
        QPushButton {
            background: #0b5394;
            border: none;
            border-radius: 5px;
            padding: 8px 15px;
            color: white;
        }
        QPushButton:hover {
            background: #67abdb;
        }
        QCheckBox, QRadioButton {
            color: white;
        }
        QLabel {
            color: white;
        }
        QListWidget {
            background: #333333;
            color: white;
            border-radius: 5px;
            padding: 5px;
        }
        QLineEdit {
            background: #333333;
            border: 1px solid #444444;
            border-radius: 5px;
            padding: 8px;
            color: white;
        }
        QComboBox {
            background: #333333;
            border: 1px solid #444444;
            border-radius: 5px;
            padding: 5px;
            color: white;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox QAbstractItemView {
            background: #333333;
            color: white;
            selection-background-color: #0b5394;
        }
    )");
    enableControls(false);
}

void StubMapperDialog::loadSyscalls() {
    syscallList->clear();
    QStringList selectedSyscalls = settings->value("integrity/selected_syscalls", QStringList()).toStringList();
    if (selectedSyscalls.isEmpty()) {
        QString headerPath = PathUtils::getSysCallerPath() + "/Wrapper/include/Sys/sysFunctions.h";
        QString syscallMode = settings->value("general/syscall_mode", "Nt").toString();
        QString syscallPrefix = (syscallMode == "Nt") ? "Sys" : "SysK";
        QFile headerFile(headerPath);
        if (headerFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&headerFile);
            while (!in.atEnd()) {
                QString line = in.readLine();
                QRegularExpression regex(QString(R"(extern "C" (?:NTSTATUS|ULONG) (%1\w+)\()").arg(syscallPrefix));
                QRegularExpressionMatch match = regex.match(line);
                if (match.hasMatch()) {
                    selectedSyscalls.append(match.captured(1));
                }
                QRegularExpression scRegex(R"(extern "C" (?:NTSTATUS|ULONG) (SC\w+)\()");
                QRegularExpressionMatch scMatch = scRegex.match(line);
                if (scMatch.hasMatch()) {
                    QString syscallName = syscallPrefix + scMatch.captured(1).mid(2);
                    selectedSyscalls.append(syscallName);
                }
            }
            headerFile.close();
        }
        selectedSyscalls.sort();
    }
    for (const QString& syscall : selectedSyscalls) {
        QListWidgetItem* item = new QListWidgetItem(syscall);
        if (syscallSettings.contains(syscall)) {
            item->setForeground(Qt::green);
        }
        syscallList->addItem(item);
    }
}

void StubMapperDialog::filterSyscalls(const QString& text) {
    for (int i = 0; i < syscallList->count(); ++i) {
        QListWidgetItem* item = syscallList->item(i);
        if (item->text().toLower().contains(text.toLower())) {
            item->setHidden(false);
        } else {
            item->setHidden(true);
        }
    }
}

void StubMapperDialog::onSyscallSelected(QListWidgetItem* current, QListWidgetItem* previous) {
    if (current == nullptr) {
        enableControls(false);
        currentSyscallLabel->setText("Select a Syscall from the list");
        return;
    }
    enableControls(true);
    QString syscallName = current->text();
    currentSyscallLabel->setText(QString("Configuring: %1").arg(syscallName));
    loadSyscallSpecificSettings(syscallName);
}

void StubMapperDialog::loadSyscallSpecificSettings(const QString& syscallName) {
    if (syscallSettings.contains(syscallName)) {
        QMap<QString, QVariant> settings = syscallSettings[syscallName].toMap();
        // junk instructions
        enableJunk->setChecked(settings.value("enable_junk", false).toBool());
        minInstructions->setValue(settings.value("min_instructions", 2).toInt());
        maxInstructions->setValue(settings.value("max_instructions", 8).toInt());
        useAdvancedJunk->setChecked(settings.value("use_advanced_junk", false).toBool());
        // encryption
        enableEncryption->setChecked(settings.value("enable_encryption", false).toBool());
        int encryptionMethodValue = settings.value("encryption_method", 1).toInt();
        int index = encryptionMethod->findData(encryptionMethodValue);
        if (index >= 0) {
            encryptionMethod->setCurrentIndex(index);
        }
        // structure
        enableChunking->setChecked(settings.value("enable_chunking", false).toBool());
        enableInterleaved->setChecked(settings.value("enable_interleaved", false).toBool());
        shuffleSequence->setChecked(settings.value("shuffle_sequence", false).toBool());
        // name randomization
        syscallPrefixLength->setValue(settings.value("syscall_prefix_length", 8).toInt());
        syscallNumberLength->setValue(settings.value("syscall_number_length", 6).toInt());
        offsetNameLength->setValue(settings.value("offset_name_length", 8).toInt());
    } else {
        loadGlobalSettings();
    }
}

void StubMapperDialog::loadGlobalSettings() {
    // junk instructions
    enableJunk->setChecked(true);
    minInstructions->setValue(settings->value("obfuscation/min_instructions", 2).toInt());
    maxInstructions->setValue(settings->value("obfuscation/max_instructions", 8).toInt());
    useAdvancedJunk->setChecked(settings->value("obfuscation/use_advanced_junk", false).toBool());
    // encryption
    enableEncryption->setChecked(settings->value("obfuscation/enable_encryption", true).toBool());
    int encryptionMethodValue = settings->value("obfuscation/encryption_method", 1).toInt();
    int index = encryptionMethod->findData(encryptionMethodValue);
    if (index >= 0) {
        encryptionMethod->setCurrentIndex(index);
    }
    // structure
    enableChunking->setChecked(settings->value("obfuscation/enable_chunking", true).toBool());
    enableInterleaved->setChecked(settings->value("obfuscation/enable_interleaved", true).toBool());
    shuffleSequence->setChecked(settings->value("obfuscation/shuffle_sequence", true).toBool());
    // name randomization
    syscallPrefixLength->setValue(settings->value("obfuscation/syscall_prefix_length", 8).toInt());
    syscallNumberLength->setValue(settings->value("obfuscation/syscall_number_length", 6).toInt());
    offsetNameLength->setValue(settings->value("obfuscation/offset_name_length", 8).toInt());
}

void StubMapperDialog::useGlobalSettings() {
    QListWidgetItem* currentItem = syscallList->currentItem();
    if (currentItem) {
        QString syscallName = currentItem->text();
        if (syscallSettings.contains(syscallName)) {
            syscallSettings.remove(syscallName);
            currentItem->setForeground(Qt::white);
        }
        loadGlobalSettings();
    }
}

void StubMapperDialog::resetCurrentSettings() {
    QListWidgetItem* currentItem = syscallList->currentItem();
    if (currentItem) {
        QString syscallName = currentItem->text();
        if (syscallSettings.contains(syscallName)) {
            syscallSettings.remove(syscallName);
            currentItem->setForeground(Qt::white);
        }
        enableJunk->setChecked(true);
        minInstructions->setValue(2);
        maxInstructions->setValue(8);
        useAdvancedJunk->setChecked(false);
        enableEncryption->setChecked(true);
        encryptionMethod->setCurrentIndex(0);
        enableChunking->setChecked(true);
        enableInterleaved->setChecked(true);
        shuffleSequence->setChecked(true);
        syscallPrefixLength->setValue(8);
        syscallNumberLength->setValue(6);
        offsetNameLength->setValue(8);
    }
}

void StubMapperDialog::onSettingChanged() {
    QListWidgetItem* currentItem = syscallList->currentItem();
    if (currentItem) {
        QString syscallName = currentItem->text();
        saveCurrentSyscallSettings(syscallName);
        currentItem->setForeground(Qt::green);
    }
}

void StubMapperDialog::saveCurrentSyscallSettings(const QString& syscallName) {
    QMap<QString, QVariant> settings;
    // junk instructions
    settings["enable_junk"] = enableJunk->isChecked();
    settings["min_instructions"] = minInstructions->value();
    settings["max_instructions"] = maxInstructions->value();
    settings["use_advanced_junk"] = useAdvancedJunk->isChecked();
    // encryption
    settings["enable_encryption"] = enableEncryption->isChecked();
    settings["encryption_method"] = encryptionMethod->currentData();
    // structure
    settings["enable_chunking"] = enableChunking->isChecked();
    settings["enable_interleaved"] = enableInterleaved->isChecked();
    settings["shuffle_sequence"] = shuffleSequence->isChecked();
    // name randomization
    settings["syscall_prefix_length"] = syscallPrefixLength->value();
    settings["syscall_number_length"] = syscallNumberLength->value();
    settings["offset_name_length"] = offsetNameLength->value();
    syscallSettings[syscallName] = QVariant::fromValue(settings);
}

void StubMapperDialog::validateCurrentSettings() {
    QListWidgetItem* currentItem = syscallList->currentItem();
    if (currentItem) {
        QString syscallName = currentItem->text();
        if (syscallSettings.contains(syscallName)) {
            QMap<QString, QVariant> settings = syscallSettings[syscallName].toMap();
            QString errorMessage;
            bool isValid = validateStubSettings(settings, errorMessage);
            if (isValid) {
                showValidationSuccess(QString("Settings for %1 are Valid!").arg(syscallName));
            } else {
                showValidationError(QString("Settings for %1 are Invalid: %2").arg(syscallName, errorMessage));
            }
        } else {
            showValidationSuccess(QString("Using Global Settings for %1.").arg(syscallName));
        }
    } else {
        QMessageBox::warning(this, "Bind - v1.2.0", "Please select a Syscall first.");
    }
}

void StubMapperDialog::enableControls(bool enabled) {
    settingsTabs->setEnabled(enabled);
    useGlobalBtn->setEnabled(enabled);
    resetBtn->setEnabled(enabled);
}

void StubMapperDialog::loadSyscallSettings() {
    syscallSettings = settings->value("stub_mapper/syscall_settings", QMap<QString, QVariant>()).toMap();
}

void StubMapperDialog::saveSettings() {
    QStringList invalidSyscalls;
    for (auto it = syscallSettings.begin(); it != syscallSettings.end(); ++it) {
        QString syscallName = it.key();
        QMap<QString, QVariant> settings = it.value().toMap();
        QString errorMessage;
        bool isValid = validateStubSettings(settings, errorMessage);
        if (!isValid) {
            invalidSyscalls.append(QString("%1: %2").arg(syscallName, errorMessage));
        }
    }
    if (!invalidSyscalls.isEmpty()) {
        QString errorMessage = "The following Syscalls have Invalid Settings:\n\n" + invalidSyscalls.join("\n");
        showValidationError(errorMessage);
        return;
    }
    settings->setValue("stub_mapper/syscall_settings", QVariant::fromValue(syscallSettings));
    QMessageBox::information(this, "Bind - v1.2.0", "Custom Syscall Settings have been saved successfully.");
    accept();
}

bool StubMapperDialog::validateStubSettings(const QMap<QString, QVariant>& settings, QString& errorMessage) {
    QStringList requiredKeys = {
        "enable_junk", "min_instructions", "max_instructions", "use_advanced_junk",
        "enable_encryption", "encryption_method",
        "enable_chunking", "enable_interleaved", "shuffle_sequence",
        "syscall_prefix_length", "syscall_number_length", "offset_name_length"
    };
    for (const QString& key : requiredKeys) {
        if (!settings.contains(key)) {
            errorMessage = QString("Missing Required Setting: %1").arg(key);
            return false;
        }
    }
    if (settings["min_instructions"].toInt() < 1 || settings["min_instructions"].toInt() > 10) {
        errorMessage = "Minimum Instructions Must Be Between 1 And 10";
        return false;
    }
    if (settings["max_instructions"].toInt() < 1 || settings["max_instructions"].toInt() > 20) {
        errorMessage = "Maximum Instructions Must Be Between 1 And 20";
        return false;
    }
    if (settings["min_instructions"].toInt() > settings["max_instructions"].toInt()) {
        errorMessage = "Minimum Instructions Cannot Be Greater Than Maximum Instructions";
        return false;
    }
    if (settings["syscall_prefix_length"].toInt() < 4 || settings["syscall_prefix_length"].toInt() > 16) {
        errorMessage = "Syscall Prefix Length Must Be Between 4 And 16";
        return false;
    }
    if (settings["syscall_number_length"].toInt() < 4 || settings["syscall_number_length"].toInt() > 16) {
        errorMessage = "Syscall Number Length Must Be Between 4 And 16";
        return false;
    }
    if (settings["offset_name_length"].toInt() < 4 || settings["offset_name_length"].toInt() > 16) {
        errorMessage = "Offset Name Length Must Be Between 4 And 16";
        return false;
    }
    QList<int> validEncryptionMethods = {1, 2, 3, 4, 5};
    if (!validEncryptionMethods.contains(settings["encryption_method"].toInt())) {
        errorMessage = QString("Invalid Encryption Method: %1").arg(settings["encryption_method"].toInt());
        return false;
    }
    return true;
}

void StubMapperDialog::showValidationError(const QString& message) {
    QMessageBox::critical(this, "Bind - v1.2.0", message);
}

void StubMapperDialog::showValidationSuccess(const QString& message) {
    QMessageBox::information(this, "Bind - v1.2.0", message);
}
