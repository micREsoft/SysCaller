#include <Core/Utils/Common.h>
#include <GUI/Bars.h>
#include <GUI/Dialogs.h>

ChangelogDialog::ChangelogDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle("History");
    setMinimumSize(1150, 600);
    resize(1150, 600);
    setWindowIcon(QIcon(":/Icons/logo.ico"));
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    /* setAttribute(Qt::WA_TranslucentBackground); */
    setupStylesheet();
    setupUI();
    populateChangelogs();

    connect(listWidget, &QListWidget::currentItemChanged,
            this, &ChangelogDialog::displayChangelog);

    if (listWidget->count() > 0)
    {
        listWidget->setCurrentRow(0);
    }
}

void ChangelogDialog::setupStylesheet()
{
    QFile stylesheetFile(":/GUI/Stylesheets/ChangelogDialog.qss");

    if (stylesheetFile.open(QFile::ReadOnly | QFile::Text))
    {
        QTextStream in(&stylesheetFile);
        QString stylesheet = in.readAll();
        setStyleSheet(stylesheet);
        stylesheetFile.close();
    }
}

void ChangelogDialog::setupUI()
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    titleBar = new SettingsTitleBar("Changelog History", this);
    titleBar->setStyleSheet("QFrame {"
                           " background: #252525;"
                           " border-top-left-radius: 0px;"
                           " border-top-right-radius: 0px;"
                           "}");
    layout->addWidget(titleBar);

    auto* contentLayout = new QVBoxLayout();
    contentLayout->setContentsMargins(25, 25, 25, 25);
    contentLayout->setSpacing(25);

    auto* hbox = new QHBoxLayout();
    hbox->setSpacing(20);
    
    listWidget = new QListWidget();
    listWidget->setFixedWidth(220);
    listWidget->setSpacing(4);
    hbox->addWidget(listWidget);

    textEdit = new QTextEdit();
    textEdit->setReadOnly(true);
    textEdit->setFrameShape(QFrame::NoFrame);
    hbox->addWidget(textEdit, 1);
    contentLayout->addLayout(hbox);

    auto* btnBox = new QHBoxLayout();
    btnBox->addStretch();

    auto* closeBtn = new QPushButton("Close");
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnBox->addWidget(closeBtn);
    contentLayout->addLayout(btnBox);
    layout->addLayout(contentLayout);

    connect(titleBar, &SettingsTitleBar::closeClicked, this, &QDialog::accept);
}

void ChangelogDialog::populateChangelogs()
{
    QString historyDir = PathUtils::getProjectRoot() + "/History";
    QDir dir(historyDir);
    QStringList changelogs;
    QStringList filters;
    filters << "CHANGELOG_*.md";

    QFileInfoList files = dir.entryInfoList(filters, QDir::Files);

    for (const QFileInfo& fileInfo : files)
    {
        QString fileName = fileInfo.fileName();

        if (fileName.startsWith("CHANGELOG_") && fileName.endsWith(".md"))
        {
            QString version = fileName.mid(10, fileName.length() - 13);
            changelogFiles[version] = fileInfo.absoluteFilePath();
            changelogs.append(version);
        }
    }

    std::sort(changelogs.begin(), changelogs.end(), std::greater<QString>());

    for (const QString& version : changelogs)
    {
        listWidget->addItem(version);
    }
}

void ChangelogDialog::displayChangelog(QListWidgetItem* current, QListWidgetItem* previous)
{
    Q_UNUSED(previous)

    if (!current)
    {
        textEdit->clear();
        return;
    }

    QString version = current->text();
    QString filePath = changelogFiles.value(version);

    if (!filePath.isEmpty() && QFile::exists(filePath))
    {
        QFile file(filePath);

        if (file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            QTextStream stream(&file);
            stream.setCodec("UTF-8");
            QString content = stream.readAll();
            file.close();
            QString html = markdownToHtml(content);
            textEdit->setHtml(html);
        }
        else
        {
            textEdit->setHtml("<i>[Error Reading Changelog File]</i>");
        }
    }
    else
    {
        textEdit->setHtml("<i>[No Changelog Found]</i>");
    }
}

QString ChangelogDialog::markdownToHtml(const QString& markdown)
{
    QByteArray utf8 = markdown.toUtf8();
    char* html = cmark_markdown_to_html(utf8.constData(), utf8.size(), CMARK_OPT_DEFAULT);
    QString result = QString::fromUtf8(html);
    free(html);

    QString customCss =
        "<style>"
        "body { "
        "  background: #1E1E1E; "
        "  color: #E8E8E8; "
        "  font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif; "
        "  margin: 0; "
        "  padding: 20px 25px; "
        "  line-height: 1.7; "
        "}"
        "h1 { "
        "  color: #0077d4; "
        "  font-size: 32px; "
        "  font-weight: 700; "
        "  margin-top: 0; "
        "  margin-bottom: 16px; "
        "  padding-bottom: 12px; "
        "  border-bottom: 2px solid #2A2A2A; "
        "}"
        "h2 { "
        "  color: #0b5394; "
        "  font-size: 24px; "
        "  font-weight: 600; "
        "  margin-top: 32px; "
        "  margin-bottom: 16px; "
        "  padding-bottom: 8px; "
        "  border-bottom: 1px solid #2A2A2A; "
        "}"
        "h3 { "
        "  color: #67abdb; "
        "  font-size: 18px; "
        "  font-weight: 600; "
        "  margin-top: 24px; "
        "  margin-bottom: 12px; "
        "}"
        "h4 { "
        "  color: #8BB8E8; "
        "  font-size: 16px; "
        "  font-weight: 600; "
        "  margin-top: 20px; "
        "  margin-bottom: 10px; "
        "}"
        "p { "
        "  margin-bottom: 14px; "
        "  line-height: 1.7; "
        "  color: #D0D0D0; "
        "}"
        "code { "
        "  background: #252525; "
        "  color: #67abdb; "
        "  border-radius: 4px; "
        "  padding: 3px 8px; "
        "  font-family: 'Consolas', 'Courier New', monospace; "
        "  font-size: 13px; "
        "  border: 1px solid #2A2A2A; "
        "}"
        "pre { "
        "  background: #252525; "
        "  color: #E8E8E8; "
        "  border-radius: 8px; "
        "  padding: 16px; "
        "  margin: 16px 0; "
        "  overflow-x: auto; "
        "  border: 1px solid #2A2A2A; "
        "  font-family: 'Consolas', 'Courier New', monospace; "
        "  font-size: 13px; "
        "  line-height: 1.5; "
        "}"
        "pre code { "
        "  background: transparent; "
        "  border: none; "
        "  padding: 0; "
        "  color: inherit; "
        "}"
        "ul, ol { "
        "  margin-left: 24px; "
        "  margin-bottom: 16px; "
        "  padding-left: 8px; "
        "}"
        "li { "
        "  margin-bottom: 10px; "
        "  line-height: 1.6; "
        "  color: #D0D0D0; "
        "}"
        "ul li::marker { "
        "  color: #0077d4; "
        "}"
        "ol li::marker { "
        "  color: #0077d4; "
        "  font-weight: 600; "
        "}"
        "strong { "
        "  color: #FFFFFF; "
        "  font-weight: 600; "
        "}"
        "em { "
        "  color: #B8B8B8; "
        "  font-style: italic; "
        "}"
        "a { "
        "  color: #67abdb; "
        "  text-decoration: none; "
        "  border-bottom: 1px solid #67abdb; "
        "  transition: color 0.2s; "
        "}"
        "a:hover { "
        "  color: #8BB8E8; "
        "  border-bottom-color: #8BB8E8; "
        "}"
        "hr { "
        "  border: none; "
        "  border-top: 2px solid #2A2A2A; "
        "  margin: 32px 0; "
        "}"
        "blockquote { "
        "  border-left: 4px solid #0077d4; "
        "  background: #252525; "
        "  margin: 16px 0; "
        "  padding: 12px 20px; "
        "  border-radius: 4px; "
        "  color: #C8C8C8; "
        "  font-style: italic; "
        "}"
        "table { "
        "  border-collapse: collapse; "
        "  width: 100%; "
        "  margin: 16px 0; "
        "}"
        "th, td { "
        "  border: 1px solid #2A2A2A; "
        "  padding: 10px 14px; "
        "  text-align: left; "
        "}"
        "th { "
        "  background: #252525; "
        "  color: #0077d4; "
        "  font-weight: 600; "
        "}"
        "td { "
        "  background: #1E1E1E; "
        "  color: #D0D0D0; "
        "}"
        "</style>";

    return customCss + result;
}

void ChangelogDialog::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton)
    {
        m_dragging = true;
        m_dragPosition = event->globalPos() - frameGeometry().topLeft();
        event->accept();
    }
}

void ChangelogDialog::mouseMoveEvent(QMouseEvent* event)
{
    if (event->buttons() & Qt::LeftButton && m_dragging)
    {
        move(event->globalPos() - m_dragPosition);
        event->accept();
    }
}

void ChangelogDialog::mouseReleaseEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton)
    {
        m_dragging = false;
        event->accept();
    }
}