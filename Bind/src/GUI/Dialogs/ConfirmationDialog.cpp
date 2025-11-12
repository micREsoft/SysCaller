#include <Core/Utils/Common.h>
#include <GUI/Bars.h>
#include <GUI/Dialogs.h>

ConfirmationDialog::ConfirmationDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setMinimumSize(405, 205);
    initUI("Confirmation");
    setupStylesheet();
}

ConfirmationDialog::ConfirmationDialog(const QString& title, QWidget* parent)
    : QDialog(parent)
{
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setMinimumSize(405, 205);
    initUI(title);
    setupStylesheet();
}

ConfirmationDialog::~ConfirmationDialog() = default;

void ConfirmationDialog::setTitle(const QString& title)
{
    Q_UNUSED(title)
}

void ConfirmationDialog::setMessage(const QString& message)
{
    if (messageLabel)
    {
        messageLabel->setText(message);
    }
}

void ConfirmationDialog::setButtons(bool showYes, bool showNo, bool showOK, bool showCancel)
{
    if (yesButton)
        yesButton->setVisible(showYes);

    if (noButton)
        noButton->setVisible(showNo);

    if (okButton)
        okButton->setVisible(showOK);

    if (cancelButton)
        cancelButton->setVisible(showCancel);
}

void ConfirmationDialog::initUI(const QString& title)
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    titleBar = new SettingsTitleBar(title, this);
    layout->addWidget(titleBar);

    QWidget* contentWidget = new QWidget();
    contentWidget->setObjectName("contentWidget");
    QVBoxLayout* contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setContentsMargins(30, 30, 30, 30);
    contentLayout->setSpacing(25);

    messageLabel = new QLabel();
    messageLabel->setWordWrap(true);
    messageLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    messageLabel->setTextFormat(Qt::RichText);
    contentLayout->addWidget(messageLabel);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(12);
    buttonLayout->addStretch();

    yesButton = new QPushButton("Yes");
    yesButton->setObjectName("yesButton");
    yesButton->setMinimumWidth(100);
    connect(yesButton, &QPushButton::clicked, this, &ConfirmationDialog::onYesClicked);
    buttonLayout->addWidget(yesButton);

    noButton = new QPushButton("No");
    noButton->setObjectName("noButton");
    noButton->setMinimumWidth(100);
    connect(noButton, &QPushButton::clicked, this, &ConfirmationDialog::onNoClicked);
    buttonLayout->addWidget(noButton);

    okButton = new QPushButton("OK");
    okButton->setObjectName("yesButton");
    okButton->setMinimumWidth(100);
    okButton->setVisible(false);
    connect(okButton, &QPushButton::clicked, this, &ConfirmationDialog::onOKClicked);
    buttonLayout->addWidget(okButton);

    cancelButton = new QPushButton("Cancel");
    cancelButton->setObjectName("cancelButton");
    cancelButton->setMinimumWidth(100);
    cancelButton->setVisible(false);
    connect(cancelButton, &QPushButton::clicked, this, &ConfirmationDialog::onCancelClicked);
    buttonLayout->addWidget(cancelButton);

    contentLayout->addLayout(buttonLayout);
    layout->addWidget(contentWidget);
}

void ConfirmationDialog::setupStylesheet()
{
    QFile stylesheetFile(":/GUI/Stylesheets/ConfirmationDialog.qss");

    if (stylesheetFile.open(QFile::ReadOnly | QFile::Text))
    {
        QTextStream in(&stylesheetFile);
        QString stylesheet = in.readAll();
        setStyleSheet(stylesheet);
        stylesheetFile.close();
    }
    else
    {
        setStyleSheet(
            "QDialog { background: #252525; color: white; border-radius: 15px; }"
            "QPushButton { background: #0b5394; border: none; border-radius: 5px; padding: 8px 15px; color: white; font-weight: bold; }"
            "QPushButton:hover { background: #67abdb; }"
            "QPushButton:pressed { background: #094a7a; }"
            "QLabel { color: white; }"
        );
    }
}

void ConfirmationDialog::onYesClicked()
{
    result = Yes;
    accept();
}

void ConfirmationDialog::onNoClicked()
{
    result = No;
    reject();
}

void ConfirmationDialog::onOKClicked()
{
    result = OK;
    accept();
}

void ConfirmationDialog::onCancelClicked()
{
    result = Cancel;
    reject();
}

void ConfirmationDialog::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton)
    {
        m_dragging = true;
        m_dragPosition = event->globalPos() - frameGeometry().topLeft();
        event->accept();
    }
}

void ConfirmationDialog::mouseMoveEvent(QMouseEvent* event)
{
    if (event->buttons() & Qt::LeftButton && m_dragging)
    {
        move(event->globalPos() - m_dragPosition);
        event->accept();
    }
}

void ConfirmationDialog::mouseReleaseEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton)
    {
        m_dragging = false;
        event->accept();
    }
}