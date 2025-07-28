#ifndef HASHCOMPAREDIALOG_H
#define HASHCOMPAREDIALOG_H

#include <QDialog>
#include <QMap>
#include <QString>
#include <QVariant>

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
    QStringList hashFiles;
    QMap<QString, QVariantMap> hashData;
    QString hashType;
};

#endif