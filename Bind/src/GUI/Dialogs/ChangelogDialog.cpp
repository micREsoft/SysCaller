#include "include/GUI/Dialogs/ChangelogDialog.h"
#include "include/GUI/Bars/SettingsTitleBar.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QTextEdit>
#include <QLabel>
#include <QPushButton>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QRegExp>
#include <QRegularExpression>
#include <QApplication>
#include <QIcon>
#include <QMouseEvent>
#include "include/Core/Utils/PathUtils.h"

ChangelogDialog::ChangelogDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle("Bind - History");
    setMinimumSize(1150, 600);
    resize(1150, 600);
    setWindowIcon(QIcon(":/src/Res/Icons/logo.ico"));
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    // setAttribute(Qt::WA_TranslucentBackground);
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
    QFile stylesheetFile(":/src/GUI/Stylesheets/ChangelogDialog.qss");

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

    titleBar = new SettingsTitleBar("Bind - Changelog History", this);
    layout->addWidget(titleBar);

    auto* contentLayout = new QVBoxLayout();
    contentLayout->setContentsMargins(20, 20, 20, 20);
    contentLayout->setSpacing(20);

    auto* hbox = new QHBoxLayout();
    listWidget = new QListWidget();
    listWidget->setFixedWidth(200);
    hbox->addWidget(listWidget);

    textEdit = new QTextEdit();
    textEdit->setReadOnly(true);
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
        "body { background: #181818; color: #fff; font-family: 'IBM Plex Mono', monospace; margin: 0; padding: 10px; }"
        "h1, h2, h3 { color: #0077d4; margin-top: 20px; margin-bottom: 10px; }"
        "h1 { font-size: 24px; }"
        "h2 { font-size: 20px; }"
        "h3 { font-size: 16px; }"
        "code, pre { background: #232323; color: #00ffea; border-radius: 6px; padding: 2px 6px; font-family: 'IBM Plex Mono', monospace; }"
        "pre { padding: 10px; margin: 10px 0; overflow-x: auto; }"
        "ul, ol { margin-left: 20px; margin-bottom: 10px; }"
        "li { margin-bottom: 5px; }"
        "strong { color: #ffd700; font-weight: bold; }"
        "em { color: #ffb347; font-style: italic; }"
        "a { color: #4ec9b0; text-decoration: underline; }"
        "hr { border: 1px solid #333; margin: 20px 0; }"
        "p { margin-bottom: 10px; line-height: 1.4; }"
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
