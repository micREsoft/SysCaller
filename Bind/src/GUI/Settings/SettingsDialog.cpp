#include "include/GUI/Settings/SettingsDialog.h"
#include "include/GUI/Settings/Tabs/GeneralTab.h"
#include "include/GUI/Settings/Tabs/ObfuscationTab.h"
#include "include/GUI/Settings/Tabs/IntegrityTab.h"
#include "include/GUI/Settings/Tabs/ProfileTab.h"
#include "include/GUI/Dialogs/StubMapperDialog.h"
#include "include/Core/Utils/PathUtils.h"
#include <QApplication>
#include <QDir>
#include <QMessageBox>
#include <QIcon>

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Bind - Settings");
    setMinimumWidth(500);
    setMinimumHeight(600);
    setWindowIcon(QIcon(":/src/Res/Icons/logo.ico"));
    QString iniPath = PathUtils::getIniPath();
    settings = new QSettings(iniPath, QSettings::IniFormat, this);
    setupStylesheet();
    initUI();
}

void SettingsDialog::initUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);
    tabs = new QTabWidget();
    generalTab = new GeneralTab(settings);
    obfuscationTab = new ObfuscationTab(settings);
    integrityTab = new IntegrityTab(settings);
    profileTab = new ProfileTab(settings);
    tabs->addTab(generalTab, "General");
    tabs->addTab(integrityTab, "Integrity");
    tabs->addTab(obfuscationTab, "Obfuscation");
    tabs->addTab(profileTab, "Profile");
    layout->addWidget(tabs);
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    QPushButton* stubMapperBtn = new QPushButton("Stub Mapper");
    stubMapperBtn->setToolTip("Customize Obfuscation Settings for Individual Syscalls");
    connect(stubMapperBtn, &QPushButton::clicked, this, &SettingsDialog::openStubMapper);
    QPushButton* saveBtn = new QPushButton("Save");
    connect(saveBtn, &QPushButton::clicked, this, &SettingsDialog::saveSettings);
    QPushButton* cancelBtn = new QPushButton("Cancel");
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(stubMapperBtn);
    buttonLayout->addStretch();
    buttonLayout->addWidget(saveBtn);
    buttonLayout->addWidget(cancelBtn);
    layout->addLayout(buttonLayout);
}

void SettingsDialog::setupStylesheet() {
    setStyleSheet(
        "QDialog {"
        " background: #252525;"
        " color: white;"
        "}"
        "QTabWidget::pane {"
        " border: 1px solid #333333;"
        " border-radius: 5px;"
        " background: #1E1E1E;"
        "}"
        "QTabBar::tab {"
        " background: #333333;"
        " color: white;"
        " padding: 8px 20px;"
        " border-top-left-radius: 5px;"
        " border-top-right-radius: 5px;"
        "}"
        "QTabBar::tab:selected {"
        " background: #0b5394;"
        "}"
        "QGroupBox {"
        " border: 1px solid #333333;"
        " border-radius: 5px;"
        " margin-top: 10px;"
        " padding-top: 15px;"
        " color: white;"
        "}"
        "QGroupBox::title {"
        " subcontrol-origin: margin;"
        " left: 10px;"
        " padding: 0 5px;"
        "}"
        "QSpinBox {"
        " background: #333333;"
        " border: none;"
        " border-radius: 3px;"
        " padding: 5px;"
        " color: white;"
        "}"
        "QPushButton {"
        " background: #0b5394;"
        " border: none;"
        " border-radius: 5px;"
        " padding: 8px 15px;"
        " color: white;"
        "}"
        "QPushButton:hover {"
        " background: #67abdb;"
        "}"
        "QCheckBox, QRadioButton {"
        " color: white;"
        "}"
        "QLabel {"
        " color: white;"
        "}"
        "QListWidget {"
        " background: #333333;"
        " color: white;"
        " border-radius: 5px;"
        " padding: 5px;"
        "}"
        "QLineEdit {"
        " background: #333333;"
        " border: 1px solid #444444;"
        " border-radius: 5px;"
        " padding: 8px;"
        " color: white;"
        "}"
        "QScrollArea {"
        " border: none;"
        " background: transparent;"
        "}"
    );
}

void SettingsDialog::saveSettings() {
    generalTab->saveSettings();
    obfuscationTab->saveSettings();
    integrityTab->saveSettings();
    profileTab->saveSettings();
    accept();
}

void SettingsDialog::openStubMapper() {
    StubMapperDialog dialog(this);
    dialog.exec();
} 