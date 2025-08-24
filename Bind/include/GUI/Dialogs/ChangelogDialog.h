#pragma once

#include <QDialog>
#include <QMap>
#include <QString>
#include <cmark.h>

class QListWidget;
class QTextEdit;
class QLabel;
class QListWidgetItem;
class SettingsTitleBar;

class ChangelogDialog : public QDialog {
    Q_OBJECT

public:
    explicit ChangelogDialog(QWidget* parent = nullptr);

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;

private slots:
    void displayChangelog(QListWidgetItem* current, QListWidgetItem* previous);

private:
    void populateChangelogs();
    void setupUI();
    QString markdownToHtml(const QString& markdown);
    QListWidget* listWidget;
    QTextEdit* textEdit;
    QMap<QString, QString> changelogFiles; // version -> filepath
    SettingsTitleBar* titleBar;
    bool m_dragging = false;
    QPoint m_dragPosition;
};
