#include "include/GUI/Dialogs/SettingsDialog.h"
#include "include/GUI/Settings/Tabs/GeneralTab.h"
#include "include/GUI/Settings/Tabs/ObfuscationTab.h"
#include "include/GUI/Settings/Tabs/IntegrityTab.h"
#include "include/GUI/Settings/Tabs/ProfileTab.h"
#include "include/GUI/Dialogs/StubMapperDialog.h"
#include "include/GUI/Bars/SettingsTitleBar.h"
#include "include/Core/Utils/PathUtils.h"
#include <QApplication>
#include <QDir>
#include <QMessageBox>
#include <QMouseEvent>
#include <QIcon>
#include <QScrollArea>

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
    QScrollArea* obfuscationScrollArea = new QScrollArea();
    obfuscationScrollArea->setWidgetResizable(true);
    obfuscationScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    obfuscationScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    obfuscationTab = new ObfuscationTab(settings);
    obfuscationTab->setStyleSheet("QWidget { background: #1E1E1E; color: white; }");
    obfuscationScrollArea->setWidget(obfuscationTab);    
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
    tabs->addTab(obfuscationScrollArea, "Obfuscation");
    tabs->addTab(profileScrollArea, "Profile");    
    layout->addWidget(tabs);
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(10);
    buttonLayout->setContentsMargins(20, 10, 20, 10);
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
    connect(titleBar, &SettingsTitleBar::closeClicked, this, &SettingsDialog::reject);
}

void SettingsDialog::setupStylesheet() {
    setStyleSheet(
        "QDialog {"
        " background: #252525;"
        " color: white;"
        " border-radius: 15px;"
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
        " padding-bottom: 10px;"
        " padding-left: 10px;"
        " padding-right: 10px;"
        " color: white;"
        " background: rgba(255, 255, 255, 0.05);"
        "}"
        "QGroupBox::title {"
        " subcontrol-origin: margin;"
        " left: 10px;"
        " padding: 0 5px;"
        "}"
        "QSpinBox {"
        " background: rgba(255, 255, 255, 0.1);"
        " border: 1px solid rgba(255, 255, 255, 0.2);"
        " border-radius: 3px;"
        " padding: 5px;"
        " color: white;"
        "}"
        "QSpinBox:hover {"
        " background: rgba(255, 255, 255, 0.15);"
        " border: 1px solid rgba(255, 255, 255, 0.3);"
        "}"
        "QSpinBox:focus {"
        " background: rgba(11, 83, 148, 0.2);"
        " border: 1px solid #0b5394;"
        "}"
        "QSpinBox::up-button, QSpinBox::down-button {"
        " background: #0b5394;"
        " border: none;"
        " border-radius: 2px;"
        " width: 16px;"
        "}"
        "QSpinBox::up-button:hover, QSpinBox::down-button:hover {"
        " background: #67abdb;"
        "}"
        "QSpinBox::up-arrow {"
        " image: none;"
        " border-left: 4px solid transparent;"
        " border-right: 4px solid transparent;"
        " border-bottom: 6px solid white;"
        " margin-top: 2px;"
        "}"
        "QSpinBox::down-arrow {"
        " image: none;"
        " border-left: 4px solid transparent;"
        " border-right: 4px solid transparent;"
        " border-top: 6px solid white;"
        " margin-bottom: 2px;"
        "}"
        "QPushButton {"
        " background: #0b5394;"
        " border: none;"
        " border-radius: 5px;"
        " padding: 8px 15px;"
        " color: white;"
        " font-weight: bold;"
        "}"
        "QPushButton:hover {"
        " background: #67abdb;"
        " border: 1px solid #8bc4e6;"
        " transform: translateY(-1px);"
        "}"
        "QPushButton:pressed {"
        " background: #094a7a;"
        " transform: translateY(0px);"
        "}"
        "QCheckBox {"
        " color: white;"
        " background: rgba(255, 255, 255, 0.1);"
        " border: 1px solid rgba(255, 255, 255, 0.2);"
        " border-radius: 3px;"
        " padding: 4px;"
        "}"
        "QCheckBox:hover {"
        " background: rgba(255, 255, 255, 0.15);"
        " border: 1px solid rgba(255, 255, 255, 0.3);"
        "}"
        "QCheckBox:checked {"
        " background: rgba(11, 83, 148, 0.3);"
        " border: 1px solid #0b5394;"
        "}"
        "QRadioButton {"
        " color: white;"
        " background: rgba(255, 255, 255, 0.1);"
        " border: 1px solid rgba(255, 255, 255, 0.2);"
        " border-radius: 3px;"
        " padding: 4px;"
        "}"
        "QRadioButton:hover {"
        " background: rgba(255, 255, 255, 0.15);"
        " border: 1px solid rgba(255, 255, 255, 0.3);"
        "}"
        "QRadioButton:checked {"
        " background: rgba(11, 83, 148, 0.3);"
        " border: 1px solid #0b5394;"
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
        "QListWidget::item {"
        " background: rgba(255, 255, 255, 0.1);"
        " border: 1px solid rgba(255, 255, 255, 0.2);"
        " border-radius: 2px;"
        " padding: 3px;"
        " margin: 1px;"
        "}"
        "QListWidget::item:hover {"
        " background: rgba(255, 255, 255, 0.15);"
        " border: 1px solid rgba(255, 255, 255, 0.3);"
        "}"
        "QListWidget::item:selected {"
        " background: rgba(11, 83, 148, 0.3);"
        " border: 1px solid #0b5394;"
        "}"
        "QLineEdit {"
        " background: rgba(255, 255, 255, 0.1);"
        " border: 1px solid rgba(255, 255, 255, 0.2);"
        " border-radius: 5px;"
        " padding: 8px;"
        " color: white;"
        "}"
        "QLineEdit:hover {"
        " background: rgba(255, 255, 255, 0.15);"
        " border: 1px solid rgba(255, 255, 255, 0.3);"
        "}"
        "QLineEdit:focus {"
        " background: rgba(11, 83, 148, 0.2);"
        " border: 1px solid #0b5394;"
        "}"
        "QComboBox {"
        " background: rgba(255, 255, 255, 0.1);"
        " border: 1px solid rgba(255, 255, 255, 0.2);"
        " border-radius: 5px;"
        " padding: 8px;"
        " color: white;"
        "}"
        "QComboBox:hover {"
        " background: rgba(255, 255, 255, 0.15);"
        " border: 1px solid rgba(255, 255, 255, 0.3);"
        "}"
        "QComboBox:focus {"
        " background: rgba(11, 83, 148, 0.2);"
        " border: 1px solid #0b5394;"
        "}"
        "QComboBox::drop-down {"
        " border: none;"
        " width: 20px;"
        "}"
        "QComboBox::down-arrow {"
        " image: none;"
        " border-left: 5px solid transparent;"
        " border-right: 5px solid transparent;"
        " border-top: 5px solid white;"
        "}"
        "QComboBox QAbstractItemView {"
        " background: #333333;"
        " color: white;"
        " selection-background-color: #0b5394;"
        " border: 1px solid #0b5394;"
        "}"
        "QScrollArea {"
        " border: none;"
        " background: #1E1E1E;"
        "}"
        "QScrollArea > QWidget > QWidget {"
        " background: #1E1E1E;"
        "}"
        "QScrollBar:vertical {"
        " background: #333333;"
        " width: 12px;"
        " border-radius: 6px;"
        "}"
        "QScrollBar::handle:vertical {"
        " background: #555555;"
        " border-radius: 6px;"
        " min-height: 20px;"
        "}"
        "QScrollBar::handle:vertical:hover {"
        " background: #777777;"
        "}"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
        " height: 0px;"
        "}"
        "QScrollBar:horizontal {"
        " background: #333333;"
        " height: 12px;"
        " border-radius: 6px;"
        "}"
        "QScrollBar::handle:horizontal {"
        " background: #555555;"
        " border-radius: 6px;"
        " min-width: 20px;"
        "}"
        "QScrollBar::handle:horizontal:hover {"
        " background: #777777;"
        "}"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {"
        " width: 0px;"
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
