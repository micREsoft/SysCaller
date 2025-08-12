#pragma once

#include <QDialog>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVariant>
#include <QMouseEvent>

class SettingsTitleBar;

class QListWidget;
class QTableWidget;
class QPushButton;
class QComboBox;
class QCheckBox;
class QGroupBox;
class QSplitter;

class HashCompareDialog : public QDialog {
    Q_OBJECT

public:
    explicit HashCompareDialog(QWidget* parent = nullptr);

private slots:
    void loadHashFiles();
    void selectionChanged();
    void onHashTypeChanged(const QString& hashType);
    void compareSelected();
    void exportComparison();

private:
    void initUI();

    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;

    void updateHashTable();
    void displayComparison(const QStringList& files);
    QString extractHash(const QString& hashValue, const QString& hashType);
    void exportAsCsv(const QString& exportPath, const QStringList& selectedFiles);
    void exportAsHtml(const QString& exportPath, const QStringList& selectedFiles);
    QString getProjectPaths();

    QListWidget* hashFileList;
    QTableWidget* hashTable;
    QPushButton* refreshBtn;
    QPushButton* compareBtn;
    QPushButton* exportBtn;
    QComboBox* hashTypeCombo;
    QCheckBox* showOnlyDifferences;
    QSplitter* splitter;
    SettingsTitleBar* titleBar;

    QStringList hashFiles;
    bool m_dragging = false;
    QPoint m_dragPosition;
    QMap<QString, QVariantMap> hashData;
    QString hashType;
};