#pragma once

#include <QDialog>
#include <QMap>
#include <QString>
#include <cmark.h>

class QListWidget;
class QTextEdit;
class QLabel;
class QListWidgetItem;

class ChangelogDialog : public QDialog {
    Q_OBJECT

public:
    explicit ChangelogDialog(QWidget* parent = nullptr);

private slots:
    void displayChangelog(QListWidgetItem* current, QListWidgetItem* previous);

private:
    void populateChangelogs();
    void setupUI();
    QString markdownToHtml(const QString& markdown);
    QListWidget* listWidget;
    QTextEdit* textEdit;
    QMap<QString, QString> changelogFiles; // version -> filepath
};