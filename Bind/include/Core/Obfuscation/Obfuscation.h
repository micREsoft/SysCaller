#pragma once

#include <QString>
#include <QStringList>
#include <QMap>
#include <QSet>
#include <functional>
#include <QSettings>
#include "include/GUI/Themes/Colors.h"

class Obfuscation {
public:
    explicit Obfuscation();
    int run(const QStringList& dllPaths = QStringList());
    void setOutputCallback(std::function<void(const QString&)> callback);
    static int extractSyscallOffset(const QString& line);
    bool generateExports();

private:
    std::function<void(const QString&)> outputCallback;
    QSettings* settings;
    void logMessage(const QString& message);
    QString getAsmFilePath(bool isKernelMode);
    QString getHeaderFilePath(bool isKernelMode);
    QString getDefFilePath(bool isKernelMode);
    bool isKernelMode();
    QString getSyscallPrefix();
    bool processAssemblyFile(const QString& asmPath, const QString& headerPath);
    bool updateHeaderFile(const QString& headerPath, const QMap<QString, QString>& syscallMap, const QMap<QString, QString>& functionSuffixes);
    bool updateDefFile(const QString& defPath, const QStringList& obfuscatedNames);
};
