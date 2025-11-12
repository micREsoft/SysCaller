#include <Core/Utils/Common.h>
#include <GUI/Dialogs.h>
#include <GUI/Bars.h>

ObfuscationSelectionDialog::ObfuscationSelectionDialog(QWidget* parent)
    : QDialog(parent)
    , selection(Cancelled)
{
    setWindowTitle(SYSCALLER_WINDOW_TITLE);
    setFixedSize(450, 300);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setupStylesheet();
    initUI();
}

void ObfuscationSelectionDialog::setupStylesheet()
{
    QFile stylesheetFile(":/GUI/Stylesheets/ObfuscationSelectionDialog.qss");

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
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    SettingsTitleBar* titleBar = new SettingsTitleBar("Obfuscation Selection", this);
    connect(titleBar, &SettingsTitleBar::closeClicked, this, &ObfuscationSelectionDialog::onCancelClicked);
    mainLayout->addWidget(titleBar);

    QWidget* contentWidget = new QWidget();
    contentWidget->setObjectName("contentWidget");
    QVBoxLayout* contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setContentsMargins(30, 30, 30, 30);
    contentLayout->setSpacing(25);

    descriptionLabel = new QLabel("Choose the Obfuscation Method you want to use for Syscall Generation:");
    descriptionLabel->setObjectName("description");
    descriptionLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    descriptionLabel->setWordWrap(true);
    contentLayout->addWidget(descriptionLabel);

    QVBoxLayout* buttonLayout = new QVBoxLayout();
    buttonLayout->setSpacing(12);

    normalObfuscationButton = new QPushButton("Normal Obfuscation");
    normalObfuscationButton->setToolTip("Runs w/ Obfuscation configured from the Obfuscation Settings for all Syscalls.");
    normalObfuscationButton->setMinimumHeight(45);
    connect(normalObfuscationButton, &QPushButton::clicked, this, &ObfuscationSelectionDialog::onNormalObfuscationClicked);
    buttonLayout->addWidget(normalObfuscationButton);

    stubMapperButton = new QPushButton("Stub Mapper");
    stubMapperButton->setToolTip("Runs w/ Obfuscation configured from Stub Mapper for specially configured Syscalls.");
    stubMapperButton->setMinimumHeight(45);
    connect(stubMapperButton, &QPushButton::clicked, this, &ObfuscationSelectionDialog::onStubMapperClicked);
    buttonLayout->addWidget(stubMapperButton);
    contentLayout->addLayout(buttonLayout);

    contentLayout->addStretch();

    QHBoxLayout* cancelLayout = new QHBoxLayout();
    cancelLayout->addStretch();

    cancelButton = new QPushButton("Cancel");
    cancelButton->setObjectName("cancel");
    cancelButton->setMinimumWidth(100);
    connect(cancelButton, &QPushButton::clicked, this, &ObfuscationSelectionDialog::onCancelClicked);
    cancelLayout->addWidget(cancelButton);
    contentLayout->addLayout(cancelLayout);

    mainLayout->addWidget(contentWidget);
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