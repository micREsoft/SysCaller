#include "include/GUI/Dialogs/ObfuscationSelectionDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QIcon>
#include <QFont>
#include <QApplication>

ObfuscationSelectionDialog::ObfuscationSelectionDialog(QWidget* parent)
    : QDialog(parent)
    , selection(Cancelled)
{
    setWindowTitle("Bind - v1.3.0");
    setFixedSize(450, 300);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    
    setupStylesheet();
    initUI();
}

void ObfuscationSelectionDialog::setupStylesheet() {
    setStyleSheet(
        "ObfuscationSelectionDialog {"
        " background: #252525;"
        " border: 2px solid #333333;"
        " border-radius: 15px;"
        "}"
        "QLabel {"
        " color: white;"
        "}"
        "QLabel#title {"
        " font-size: 18px;"
        " font-weight: bold;"
        " color: #0077d4;"
        " padding: 10px;"
        "}"
        "QLabel#description {"
        " font-size: 14px;"
        " color: #cccccc;"
        " padding: 10px;"
        "}"
        "QPushButton {"
        " background: #0b5394;"
        " border: none;"
        " border-radius: 8px;"
        " padding: 12px 20px;"
        " color: white;"
        " font-weight: bold;"
        " font-size: 14px;"
        " min-width: 120px;"
        "}"
        "QPushButton:hover {"
        " background: #67abdb;"
        "}"
        "QPushButton:pressed {"
        " background: #004578;"
        "}"
        "QPushButton#cancel {"
        " background: #555555;"
        "}"
        "QPushButton#cancel:hover {"
        " background: #777777;"
        "}"
    );
}

void ObfuscationSelectionDialog::initUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(30, 30, 30, 30);
    mainLayout->setSpacing(20);
    titleLabel = new QLabel("Obfuscation Selection");
    titleLabel->setObjectName("title");
    titleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(titleLabel);
    descriptionLabel = new QLabel("Choose the Obfuscation Method you want to use for Syscall Generation:");
    descriptionLabel->setObjectName("description");
    descriptionLabel->setAlignment(Qt::AlignCenter);
    descriptionLabel->setWordWrap(true);
    mainLayout->addWidget(descriptionLabel);
    QVBoxLayout* buttonLayout = new QVBoxLayout();
    buttonLayout->setSpacing(15);
    normalObfuscationButton = new QPushButton("Normal Obfuscation");
    normalObfuscationButton->setToolTip("Runs w/ Obfuscation configured from the Obfuscation Settings for all Syscalls.");
    connect(normalObfuscationButton, &QPushButton::clicked, this, &ObfuscationSelectionDialog::onNormalObfuscationClicked);
    buttonLayout->addWidget(normalObfuscationButton);
    stubMapperButton = new QPushButton("Stub Mapper");
    stubMapperButton->setToolTip("Runs w/ Obfuscation configured from Stub Mapper for specially configured Syscalls.");
    connect(stubMapperButton, &QPushButton::clicked, this, &ObfuscationSelectionDialog::onStubMapperClicked);
    buttonLayout->addWidget(stubMapperButton);
    mainLayout->addLayout(buttonLayout);
    QHBoxLayout* cancelLayout = new QHBoxLayout();
    cancelLayout->addStretch();
    cancelButton = new QPushButton("Cancel");
    cancelButton->setObjectName("cancel");
    cancelButton->setFixedWidth(100);
    connect(cancelButton, &QPushButton::clicked, this, &ObfuscationSelectionDialog::onCancelClicked);
    cancelLayout->addWidget(cancelButton);
    mainLayout->addLayout(cancelLayout);
}

void ObfuscationSelectionDialog::onNormalObfuscationClicked() {
    selection = NormalObfuscation;
    accept();
}

void ObfuscationSelectionDialog::onStubMapperClicked() {
    selection = StubMapper;
    accept();
}

void ObfuscationSelectionDialog::onCancelClicked() {
    selection = Cancelled;
    reject();
} 