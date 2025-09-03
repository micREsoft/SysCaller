#include "include/GUI/Dialogs/HashCompareDialog.h"
#include "include/Core/Utils/PathUtils.h"
#include "include/GUI/Bars/SettingsTitleBar.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QComboBox>
#include <QCheckBox>
#include <QGroupBox>
#include <QSplitter>
#include <QLabel>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QApplication>
#include <QIcon>
#include <QColor>
#include <algorithm>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegExp>
#include <QSet>
#include <QFile>
#include <QTextStream>

HashCompareDialog::HashCompareDialog(QWidget* parent) : QDialog(parent), hashType("MD5") {
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setMinimumSize(950, 400);
    titleBar = new SettingsTitleBar("Hash Compare", this);
    setupStylesheet();
    initUI();
    loadHashFiles();
}

void HashCompareDialog::initUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(titleBar);
    auto* topLayout = new QHBoxLayout();
    topLayout->setContentsMargins(20, 10, 20, 10);
    refreshBtn = new QPushButton("Refresh");
    refreshBtn->setIcon(QIcon(":/src/Res/Icons/refresh.svg"));
    connect(refreshBtn, &QPushButton::clicked, this, &HashCompareDialog::loadHashFiles);
    topLayout->addWidget(refreshBtn);
    topLayout->addSpacing(20);
    auto* hashTypeLayout = new QHBoxLayout();
    auto* hashTypeLabel = new QLabel("Hash Type:");
    hashTypeLabel->setStyleSheet("color: white; background: transparent;");
    hashTypeLayout->addWidget(hashTypeLabel);
    hashTypeCombo = new QComboBox();
    hashTypeCombo->addItems({"MD5", "SHA-256"});
    hashTypeCombo->setCurrentText(hashType);
    connect(hashTypeCombo, QOverload<const QString&>::of(&QComboBox::currentTextChanged),
            this, &HashCompareDialog::onHashTypeChanged);
    hashTypeLayout->addWidget(hashTypeCombo);
    topLayout->addLayout(hashTypeLayout);
    topLayout->addStretch();
    exportBtn = new QPushButton("Export Comparison");
    exportBtn->setIcon(QIcon(":/src/Res/Icons/export.svg"));
    connect(exportBtn, &QPushButton::clicked, this, &HashCompareDialog::exportComparison);
    exportBtn->setEnabled(false);
    topLayout->addWidget(exportBtn);
    layout->addLayout(topLayout);
    splitter = new QSplitter(Qt::Horizontal);
    // left side, hash file list
    auto* leftPanel = new QGroupBox("Hash Files");
    auto* leftLayout = new QVBoxLayout(leftPanel);
    showOnlyDifferences = new QCheckBox("Highlight Duplicates");
    showOnlyDifferences->setChecked(true);
    connect(showOnlyDifferences, &QCheckBox::stateChanged, this, &HashCompareDialog::updateHashTable);
    leftLayout->addWidget(showOnlyDifferences);
    hashFileList = new QListWidget();
    hashFileList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    connect(hashFileList, &QListWidget::itemSelectionChanged, 
            this, &HashCompareDialog::selectionChanged);
    leftLayout->addWidget(hashFileList);
    compareBtn = new QPushButton("Compare Selected");
    connect(compareBtn, &QPushButton::clicked, this, &HashCompareDialog::compareSelected);
    leftLayout->addWidget(compareBtn);
    splitter->addWidget(leftPanel);
    // right side, hash table
    auto* rightPanel = new QGroupBox("Hash Comparison");
    auto* rightLayout = new QVBoxLayout(rightPanel);
    hashTable = new QTableWidget(0, 3);
    hashTable->setHorizontalHeaderLabels({"Syscall", "Hash File 1", "Hash File 2"});
    hashTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    hashTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    hashTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    hashTable->verticalHeader()->setVisible(false);
    hashTable->setAlternatingRowColors(true);
    hashTable->setSortingEnabled(true);
    rightLayout->addWidget(hashTable);
    splitter->addWidget(rightPanel);
    layout->addWidget(splitter);
    splitter->setSizes({300, 600});
    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    auto* closeBtn = new QPushButton("Close");
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(closeBtn);
    layout->addLayout(buttonLayout);
    connect(titleBar, &SettingsTitleBar::closeClicked, this, &QDialog::reject);
}

void HashCompareDialog::setupStylesheet() {
    QFile stylesheetFile(":/src/GUI/Stylesheets/HashCompareDialog.qss");
    if (stylesheetFile.open(QFile::ReadOnly | QFile::Text)) {
        QTextStream in(&stylesheetFile);
        QString stylesheet = in.readAll();
        setStyleSheet(stylesheet);
        stylesheetFile.close();
    }
}

void HashCompareDialog::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        m_dragging = true;
        m_dragPosition = event->globalPos() - frameGeometry().topLeft();
        event->accept();
    }
}

void HashCompareDialog::mouseMoveEvent(QMouseEvent* event) {
    if (event->buttons() & Qt::LeftButton && m_dragging) {
        move(event->globalPos() - m_dragPosition);
        event->accept();
    }
}

void HashCompareDialog::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        m_dragging = false;
        event->accept();
    }
}

void HashCompareDialog::loadHashFiles() {
    try {
        QString hashBackupsDir = PathUtils::getHashBackupsPath();
        QDir dir(hashBackupsDir);
        if (!dir.exists()) {
            hashFileList->clear();
            hashFileList->addItem("No Hash Directory Found");
            return;
        }
        hashFileList->clear();
        hashFiles.clear();
        hashData.clear();
        QStringList filters;
        filters << "stub_hashes_*.json";
        QFileInfoList files = dir.entryInfoList(filters, QDir::Files);
        // sort files in reverse order (newest first)
        std::sort(files.begin(), files.end(), [](const QFileInfo& a, const QFileInfo& b) {
            return a.fileName() > b.fileName();
        });
        for (const QFileInfo& fileInfo : files) {
            try {
                QString filePath = fileInfo.absoluteFilePath();
                QFile file(filePath);
                if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                    QTextStream stream(&file);
                    stream.setCodec("UTF-8");
                    QString content = stream.readAll();
                    file.close();
                    QJsonDocument doc = QJsonDocument::fromJson(content.toUtf8());
                    if (doc.isObject()) {
                        QJsonObject jsonObj = doc.object();
                        QVariantMap data;
                        data["filepath"] = filePath;
                        data["content"] = content;
                        data["json"] = jsonObj.toVariantMap();
                        QString timestamp = jsonObj["timestamp"].toString();
                        if (timestamp.isEmpty()) timestamp = "Unknown";
                        QString obfMethod = "Normal";
                        QJsonObject config = jsonObj["config"].toObject();
                        if (!config.isEmpty()) {
                            if (config.contains("obfuscation_method")) {
                                obfMethod = config["obfuscation_method"].toString();
                            } else if (config.contains("global_settings")) {
                                obfMethod = "Stub Mapper";
                            }
                        }
                        QString displayName = QString("%1 (%2)").arg(timestamp, obfMethod);
                        hashFileList->addItem(displayName);
                        hashFiles.append(filePath);
                        hashData[filePath] = data;
                    }
                }
            } catch (...) {
                continue;
            }
        }
        if (hashFiles.isEmpty()) {
            hashFileList->addItem("No Hash Files Found");
        }
    } catch (...) {
        hashFileList->clear();
        hashFileList->addItem("Error Loading Hash Files");
    }
}

void HashCompareDialog::selectionChanged() {
    QList<QListWidgetItem*> selectedItems = hashFileList->selectedItems();
    exportBtn->setEnabled(selectedItems.size() >= 1);
}

void HashCompareDialog::onHashTypeChanged(const QString& hashType) {
    this->hashType = hashType;
    updateHashTable();
}

void HashCompareDialog::updateHashTable() {
    QList<QListWidgetItem*> selectedItems = hashFileList->selectedItems();
    if (selectedItems.isEmpty()) {
        return;
    }
    QStringList selectedFiles;
    for (QListWidgetItem* item : selectedItems) {
        int index = hashFileList->row(item);
        if (index >= 0 && index < hashFiles.size()) {
            selectedFiles.append(hashFiles[index]);
        }
    }
    if (!selectedFiles.isEmpty()) {
        displayComparison(selectedFiles);
    }
}

void HashCompareDialog::compareSelected() {
    QList<QListWidgetItem*> selectedItems = hashFileList->selectedItems();
    if (selectedItems.size() < 1) {
        QMessageBox::warning(this, "Bind - v1.3.0", "Please select at least one Hash File to view.");
        return;
    }
    if (selectedItems.size() > 5) {
        QMessageBox::warning(this, "Bind - v1.3.0", "Please select at most 5 Hash Files to compare.");
        return;
    }
    QStringList selectedFiles;
    for (QListWidgetItem* item : selectedItems) {
        int index = hashFileList->row(item);
        if (index >= 0 && index < hashFiles.size()) {
            selectedFiles.append(hashFiles[index]);
        }
    }
    displayComparison(selectedFiles);
}

void HashCompareDialog::displayComparison(const QStringList& files) {
    if (files.isEmpty()) {
        return;
    }
    hashTable->clear();
    hashTable->setSortingEnabled(false);
    hashTable->setColumnCount(files.size() + 1);
    QStringList headers;
    headers << "Syscall";
    QSet<QString> allSyscalls;
    QMap<QString, QVariantMap> fileData;
    for (const QString& filePath : files) {
        QVariantMap data = hashData.value(filePath);
        QVariantMap jsonData = data["json"].toMap();
        QString timestamp = jsonData["timestamp"].toString();
        if (timestamp.isEmpty()) timestamp = "Unknown";
        QString obfMethod = "Normal";
        QVariantMap config = jsonData["config"].toMap();
        if (!config.isEmpty()) {
            if (config.contains("obfuscation_method")) {
                obfMethod = config["obfuscation_method"].toString();
            } else if (config.contains("global_settings")) {
                obfMethod = "Stub Mapper";
            }
        }
        headers << QString("%1\n(%2)").arg(timestamp, obfMethod);
        fileData[filePath] = jsonData;
        QVariantMap stubs = jsonData["stubs"].toMap();
        for (auto it = stubs.begin(); it != stubs.end(); ++it) {
            allSyscalls.insert(it.key());
        }
    }
    hashTable->setHorizontalHeaderLabels(headers);
    // create hash mapping for duplicate detection
    QMap<QString, QList<QPair<QString, int>>> hashMapping;
    QStringList sortedSyscalls = allSyscalls.values();
    std::sort(sortedSyscalls.begin(), sortedSyscalls.end());
    hashTable->setRowCount(sortedSyscalls.size());
    for (int row = 0; row < sortedSyscalls.size(); ++row) {
        QString syscall = sortedSyscalls[row];
        hashTable->setItem(row, 0, new QTableWidgetItem(syscall));
        for (int col = 0; col < files.size(); ++col) {
            QString filePath = files[col];
            QVariantMap jsonData = fileData[filePath];
            QVariantMap stubs = jsonData["stubs"].toMap();
            QString hashValue = stubs.value(syscall).toString();
            QString displayValue = "N/A";
            if (!hashValue.isEmpty()) {
                QString extractedHash = extractHash(hashValue, hashType);
                if (extractedHash != "N/A") {
                    displayValue = extractedHash;
                    if (!hashMapping.contains(extractedHash)) {
                        hashMapping[extractedHash] = QList<QPair<QString, int>>();
                    }
                    hashMapping[extractedHash].append(qMakePair(syscall, col + 1));
                }
            }
            QTableWidgetItem* item = new QTableWidgetItem(displayValue);
            if (hashValue.isEmpty()) {
                item->setBackground(QColor(80, 80, 80));
            }
            hashTable->setItem(row, col + 1, item);
        }
    }
    if (showOnlyDifferences->isChecked()) {
        QList<QColor> duplicateColors = {
            QColor(255, 150, 150),  // red
            QColor(150, 255, 150),  // green
            QColor(150, 150, 255),  // blue
            QColor(255, 255, 150),  // yellow
            QColor(255, 150, 255),  // purple
            QColor(150, 255, 255),  // cyan
            QColor(255, 200, 150),  // orange
        };
        int colorIndex = 0;
        for (auto it = hashMapping.begin(); it != hashMapping.end(); ++it) {
            if (it.value().size() > 1) {
                QColor color = duplicateColors[colorIndex % duplicateColors.size()];
                colorIndex++;
                for (const auto& pos : it.value()) {
                    int row = sortedSyscalls.indexOf(pos.first);
                    if (row >= 0) {
                        QTableWidgetItem* item = hashTable->item(row, pos.second);
                        if (item && row % 2 == 1) {
                            item->setBackground(color);
                        }
                    }
                }
            }
        }
    }
    for (int i = 0; i < hashTable->columnCount(); ++i) {
        hashTable->horizontalHeader()->setSectionResizeMode(i, QHeaderView::Stretch);
    }
    hashTable->setSortingEnabled(true);
    exportBtn->setEnabled(true);
}

QString HashCompareDialog::extractHash(const QString& hashValue, const QString& hashType) {
    if (hashType == "MD5") {
        QRegExp md5Regex("MD5:\\s*([a-fA-F0-9]{32})");
        if (md5Regex.indexIn(hashValue) != -1) {
            return md5Regex.cap(1);
        }
    } else if (hashType == "SHA-256") {
        QRegExp sha256Regex("SHA-256:\\s*([a-fA-F0-9]{64})");
        if (sha256Regex.indexIn(hashValue) != -1) {
            return sha256Regex.cap(1);
        }
    }
    return hashValue;
}

void HashCompareDialog::exportComparison() {
    QList<QListWidgetItem*> selectedItems = hashFileList->selectedItems();
    if (selectedItems.isEmpty()) {
        QMessageBox::warning(this, "Bind - v1.3.0", "Please select at least one Hash File to export.");
        return;
    }
    QStringList selectedFiles;
    for (QListWidgetItem* item : selectedItems) {
        int index = hashFileList->row(item);
        if (index >= 0 && index < hashFiles.size()) {
            selectedFiles.append(hashFiles[index]);
        }
    }
    QString exportPath = QFileDialog::getSaveFileName(
        this,
        "Bind - v1.3.0",
        "",
        "CSV Files (*.csv);;HTML Files (*.html);;All Files (*.*)"
    );
    if (exportPath.isEmpty()) {
        return;
    }
    try {
        if (exportPath.toLower().endsWith(".csv")) {
            exportAsCsv(exportPath, selectedFiles);
        } else if (exportPath.toLower().endsWith(".html")) {
            exportAsHtml(exportPath, selectedFiles);
        } else {
            if (!exportPath.toLower().endsWith(".csv")) {
                exportPath += ".csv";
            }
            exportAsCsv(exportPath, selectedFiles);
        }
        QMessageBox::information(this, "Bind - v1.3.0", 
                               QString("Hash Comparison exported successfully to:\n%1").arg(exportPath));
    } catch (...) {
        QMessageBox::critical(this, "Bind - v1.3.0", "Failed to Export Comparison.");
    }
}

void HashCompareDialog::exportAsCsv(const QString& exportPath, const QStringList& selectedFiles) {
    if (selectedFiles.isEmpty()) {
        return;
    }
    QSet<QString> allSyscalls;
    QMap<QString, QVariantMap> fileData;
    for (const QString& filePath : selectedFiles) {
        QVariantMap data = hashData.value(filePath);
        QVariantMap jsonData = data["json"].toMap();
        fileData[filePath] = jsonData;
        QVariantMap stubs = jsonData["stubs"].toMap();
        for (auto it = stubs.begin(); it != stubs.end(); ++it) {
            allSyscalls.insert(it.key());
        }
    }
    QFile file(exportPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Bind - v1.3.0", "Could not create Export File.");
        return;
    }
    QTextStream stream(&file);
    stream.setCodec("UTF-8");
    stream << "Syscall";
    for (const QString& filePath : selectedFiles) {
        QVariantMap jsonData = fileData[filePath];
        QString timestamp = jsonData["timestamp"].toString();
        if (timestamp.isEmpty()) timestamp = "Unknown";
        QString obfMethod = "Normal";
        QVariantMap config = jsonData["config"].toMap();
        if (!config.isEmpty()) {
            if (config.contains("obfuscation_method")) {
                obfMethod = config["obfuscation_method"].toString();
            } else if (config.contains("global_settings")) {
                obfMethod = "Stub Mapper";
            }
        }
        stream << ",\"" << timestamp << " (" << obfMethod << ")\"";
    }
    stream << "\n";
    QStringList sortedSyscalls = allSyscalls.values();
    std::sort(sortedSyscalls.begin(), sortedSyscalls.end());
    for (const QString& syscall : sortedSyscalls) {
        stream << "\"" << syscall << "\"";
        for (const QString& filePath : selectedFiles) {
            QVariantMap jsonData = fileData[filePath];
            QVariantMap stubs = jsonData["stubs"].toMap();
            QString hashValue = stubs.value(syscall).toString();
            QString displayValue = "N/A";
            if (!hashValue.isEmpty()) {
                QString extractedHash = extractHash(hashValue, hashType);
                if (extractedHash != "N/A") {
                    displayValue = extractedHash;
                }
            }
            stream << ",\"" << displayValue << "\"";
        }
        stream << "\n";
    }
    file.close();
}

void HashCompareDialog::exportAsHtml(const QString& exportPath, const QStringList& selectedFiles) {
    if (selectedFiles.isEmpty()) {
        return;
    }
    QSet<QString> allSyscalls;
    QMap<QString, QVariantMap> fileData;
    for (const QString& filePath : selectedFiles) {
        QVariantMap data = hashData.value(filePath);
        QVariantMap jsonData = data["json"].toMap();
        fileData[filePath] = jsonData;
        QVariantMap stubs = jsonData["stubs"].toMap();
        for (auto it = stubs.begin(); it != stubs.end(); ++it) {
            allSyscalls.insert(it.key());
        }
    }
    QFile file(exportPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Bind - v1.3.0", "Could not create Export File.");
        return;
    }
    QTextStream stream(&file);
    stream.setCodec("UTF-8");
    stream << "<!DOCTYPE html>\n";
    stream << "<html>\n<head>\n";
    stream << "<meta charset=\"UTF-8\">\n";
    stream << "<title>Bind - Hash Comparison</title>\n";
    stream << "<style>\n";
    stream << "body { font-family: Arial, sans-serif; margin: 20px; background-color: #f8f8f8; }\n";
    stream << "h1 { color: #0b5394; }\n";
    stream << "table { border-collapse: collapse; width: 100%; margin-top: 20px; }\n";
    stream << "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n";
    stream << "th { background-color: #0b5394; color: white; }\n";
    stream << "tr:nth-child(even) { background-color: #f2f2f2; }\n";
    stream << "tr:nth-child(odd) { background-color: #ffffff; }\n";
    stream << "tr:hover { background-color: #ddd; }\n";
    stream << ".duplicate { background-color: #ffe0e0; }\n";
    stream << ".timestamp { font-weight: bold; }\n";
    stream << ".method { font-style: italic; color: #666; }\n";
    stream << ".hash-type { font-weight: bold; color: #0b5394; }\n";
    stream << "</style>\n</head>\n<body>\n";
    stream << "<h1>Bind - Hash Comparison</h1>\n";
    QString firstTimestamp = fileData.value(selectedFiles.first())["timestamp"].toString();
    if (firstTimestamp.isEmpty()) firstTimestamp = "Unknown";
    stream << "<p>Generated on: " << firstTimestamp << "</p>\n";
    stream << "<p><span class=\"hash-type\">Hash Type: " << hashType << "</span></p>\n";
    stream << "<table>\n<tr><th>Syscall</th>";
    for (const QString& filePath : selectedFiles) {
        QVariantMap jsonData = fileData[filePath];
        QString timestamp = jsonData["timestamp"].toString();
        if (timestamp.isEmpty()) timestamp = "Unknown";
        QString obfMethod = "Normal";
        QVariantMap config = jsonData["config"].toMap();
        if (!config.isEmpty()) {
            if (config.contains("obfuscation_method")) {
                obfMethod = config["obfuscation_method"].toString();
            } else if (config.contains("global_settings")) {
                obfMethod = "Stub Mapper";
            }
        }
        stream << "<th><span class=\"timestamp\">" << timestamp << "</span><br><span class=\"method\">(" << obfMethod << ")</span></th>";
    }
    stream << "</tr>\n";
    QMap<QString, QList<QPair<QString, QString>>> hashMapping;
    for (const QString& syscall : allSyscalls) {
        for (const QString& filePath : selectedFiles) {
            QVariantMap jsonData = fileData[filePath];
            QVariantMap stubs = jsonData["stubs"].toMap();
            QString hashValue = stubs.value(syscall).toString();
            if (!hashValue.isEmpty()) {
                QString extractedHash = extractHash(hashValue, hashType);
                if (extractedHash != "N/A") {
                    if (!hashMapping.contains(extractedHash)) {
                        hashMapping[extractedHash] = QList<QPair<QString, QString>>();
                    }
                    hashMapping[extractedHash].append(qMakePair(syscall, filePath));
                }
            }
        }
    }
    QStringList sortedSyscalls = allSyscalls.values();
    std::sort(sortedSyscalls.begin(), sortedSyscalls.end());
    for (const QString& syscall : sortedSyscalls) {
        stream << "<tr><td>" << syscall << "</td>";
        for (const QString& filePath : selectedFiles) {
            QVariantMap jsonData = fileData[filePath];
            QVariantMap stubs = jsonData["stubs"].toMap();
            QString hashValue = stubs.value(syscall).toString();
            QString displayValue = "N/A";
            if (!hashValue.isEmpty()) {
                QString extractedHash = extractHash(hashValue, hashType);
                if (extractedHash != "N/A") {
                    displayValue = extractedHash;
                }
            }
            QString duplicateClass = "";
            if (displayValue != "N/A") {
                if (hashMapping.contains(displayValue) && hashMapping[displayValue].size() > 1) {
                    duplicateClass = " class=\"duplicate\"";
                }
            }
            stream << "<td" << duplicateClass << ">" << displayValue << "</td>";
        }
        stream << "</tr>\n";
    }
    stream << "</table>\n</body>\n</html>";
    file.close();
}

QString HashCompareDialog::getProjectPaths() {
    return PathUtils::getProjectRoot();
}
