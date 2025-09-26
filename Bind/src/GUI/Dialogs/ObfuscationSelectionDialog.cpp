#include "include/GUI/Dialogs/ObfuscationSelectionDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QIcon>
#include <QFont>
#include <QApplication>
#include <QFile>
#include <QTextStream>

ObfuscationSelectionDialog::ObfuscationSelectionDialog(QWidget* parent)
    : QDialog(parent)
    , selection(Cancelled)
{
    setWindowTitle("Bind - v1.3.1");
    setFixedSize(450, 300);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setupStylesheet();
    initUI();
}

void ObfuscationSelectionDialog::setupStylesheet()
{
    QFile stylesheetFile(":/src/GUI/Stylesheets/ObfuscationSelectionDialog.qss");

    if (stylesheetFile.open(QFile::ReadOnly | QFile::Text))
    {
        QTextStream in(&stylesheetFile);
        QString stylesheet = in.readAll();
        setStyleSheet(stylesheet);
        stylesheetFile.close();
    }
}

void ObfuscationSelectionDialog::initUI()
{
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

void ObfuscationSelectionDialog::onNormalObfuscationClicked()
{
    selection = NormalObfuscation;
    accept();
}

void ObfuscationSelectionDialog::onStubMapperClicked()
{
    selection = StubMapper;
    accept();
}

void ObfuscationSelectionDialog::onCancelClicked()
{
    selection = Cancelled;
    reject();
}
