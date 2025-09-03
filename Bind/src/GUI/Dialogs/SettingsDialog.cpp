#include "include/GUI/Dialogs/SettingsDialog.h"
#include "include/GUI/Settings/Tabs/GeneralTab.h"
#include "include/GUI/Settings/Tabs/ObfuscationTab.h"
#include "include/GUI/Settings/Tabs/IndirectObfuscationTab.h"
#include "include/GUI/Settings/Tabs/InlineObfuscationTab.h"
#include "include/GUI/Settings/Tabs/IntegrityTab.h"
#include "include/GUI/Settings/Tabs/ProfileTab.h"
#include "include/GUI/Dialogs/StubMapperDialog.h"
#include "include/GUI/Bars/SettingsTitleBar.h"
#include "include/Core/Utils/PathUtils.h"
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QMessageBox>
#include <QMouseEvent>
#include <QIcon>
#include <QScrollArea>
#include <QTextStream>

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setMinimumSize(500, 600);
    titleBar = new SettingsTitleBar(this);
    QString iniPath = PathUtils::getIniPath();
    settings = new QSettings(iniPath, QSettings::IniFormat, this);
    setupStylesheet();
    initUI();
}

void SettingsDialog::initUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(titleBar);
    tabs = new QTabWidget();
    QScrollArea* generalScrollArea = new QScrollArea();
    generalScrollArea->setWidgetResizable(true);
    generalScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    generalScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    generalTab = new GeneralTab(settings);
    generalTab->setStyleSheet("QWidget { background: #1E1E1E; color: white; }");
    generalScrollArea->setWidget(generalTab);
    QScrollArea* integrityScrollArea = new QScrollArea();
    integrityScrollArea->setWidgetResizable(true);
    integrityScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    integrityScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    integrityTab = new IntegrityTab(settings);
    integrityTab->setStyleSheet("QWidget { background: #1E1E1E; color: white; }");
    integrityScrollArea->setWidget(integrityTab);
    QScrollArea* profileScrollArea = new QScrollArea();
    profileScrollArea->setWidgetResizable(true);
    profileScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    profileScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    profileTab = new ProfileTab(settings);
    profileTab->setStyleSheet("QWidget { background: #1E1E1E; color: white; }");
    profileScrollArea->setWidget(profileTab);
    tabs->addTab(generalScrollArea, "General");
    tabs->addTab(integrityScrollArea, "Integrity");
    bool inlineAssemblyEnabled = settings->value("general/inline_assembly", false).toBool();
    bool indirectAssemblyEnabled = settings->value("general/indirect_assembly", false).toBool();
    if (inlineAssemblyEnabled) {
        QScrollArea* inlineObfuscationScrollArea = new QScrollArea();
        inlineObfuscationScrollArea->setWidgetResizable(true);
        inlineObfuscationScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        inlineObfuscationScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        inlineObfuscationTab = new InlineObfuscationTab(settings);
        inlineObfuscationTab->setStyleSheet("QWidget { background: #1E1E1E; color: white; }");
        inlineObfuscationScrollArea->setWidget(inlineObfuscationTab);
        tabs->addTab(inlineObfuscationScrollArea, "Obfuscation");
    } else if (indirectAssemblyEnabled) {
        QScrollArea* indirectObfuscationScrollArea = new QScrollArea();
        indirectObfuscationScrollArea->setWidgetResizable(true);
        indirectObfuscationScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        indirectObfuscationScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        indirectObfuscationTab = new IndirectObfuscationTab(settings);
        indirectObfuscationTab->setStyleSheet("QWidget { background: #1E1E1E; color: white; }");
        indirectObfuscationScrollArea->setWidget(indirectObfuscationTab);
        tabs->addTab(indirectObfuscationScrollArea, "Obfuscation");
    } else {
        QScrollArea* obfuscationScrollArea = new QScrollArea();
        obfuscationScrollArea->setWidgetResizable(true);
        obfuscationScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        obfuscationScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        obfuscationTab = new ObfuscationTab(settings);
        obfuscationTab->setStyleSheet("QWidget { background: #1E1E1E; color: white; }");
        obfuscationScrollArea->setWidget(obfuscationTab);
        tabs->addTab(obfuscationScrollArea, "Obfuscation");
    }
    tabs->addTab(profileScrollArea, "Profile");
    layout->addWidget(tabs);
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(10);
    buttonLayout->setContentsMargins(20, 10, 20, 10);
    if (!inlineAssemblyEnabled && !indirectAssemblyEnabled) {
        QPushButton* stubMapperBtn = new QPushButton("Stub Mapper");
        stubMapperBtn->setToolTip("Customize Obfuscation Settings for Individual Syscalls");
        connect(stubMapperBtn, &QPushButton::clicked, this, &SettingsDialog::openStubMapper);
        buttonLayout->addWidget(stubMapperBtn);
    }
    QPushButton* saveBtn = new QPushButton("Save");
    connect(saveBtn, &QPushButton::clicked, this, &SettingsDialog::saveSettings);
    QPushButton* cancelBtn = new QPushButton("Cancel");
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addStretch();
    buttonLayout->addWidget(saveBtn);
    buttonLayout->addWidget(cancelBtn);
    layout->addLayout(buttonLayout);
    connect(titleBar, &SettingsTitleBar::closeClicked, this, &SettingsDialog::reject);
}

void SettingsDialog::setupStylesheet() {
    QFile stylesheetFile(":/src/GUI/Stylesheets/SettingsDialog.qss");
    if (stylesheetFile.open(QFile::ReadOnly | QFile::Text)) {
        QTextStream in(&stylesheetFile);
        QString stylesheet = in.readAll();
        setStyleSheet(stylesheet);
        stylesheetFile.close();
    }
}

void SettingsDialog::saveSettings() {
    generalTab->saveSettings();
    bool inlineAssemblyEnabled = settings->value("general/inline_assembly", false).toBool();
    bool indirectAssemblyEnabled = settings->value("general/indirect_assembly", false).toBool();
    if (inlineAssemblyEnabled) {
        if (inlineObfuscationTab) {
            inlineObfuscationTab->saveSettings();
        }
    } else if (indirectAssemblyEnabled) {
        if (indirectObfuscationTab) {
            indirectObfuscationTab->saveSettings();
        }
    } else {
        if (obfuscationTab) {
            obfuscationTab->saveSettings();
        }
    }
    integrityTab->saveSettings();
    profileTab->saveSettings();
    accept();
}

void SettingsDialog::openStubMapper() {
    StubMapperDialog dialog(this);
    dialog.exec();
}

void SettingsDialog::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        m_dragging = true;
        m_dragPosition = event->globalPos() - frameGeometry().topLeft();
        event->accept();
    }
}

void SettingsDialog::mouseMoveEvent(QMouseEvent* event) {
    if (event->buttons() & Qt::LeftButton && m_dragging) {
        move(event->globalPos() - m_dragPosition);
        event->accept();
    }
}

void SettingsDialog::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        m_dragging = false;
        event->accept();
    }
}
