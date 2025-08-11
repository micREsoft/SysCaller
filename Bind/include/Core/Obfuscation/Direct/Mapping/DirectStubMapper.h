#ifndef STUBMAPPER_H
#define STUBMAPPER_H

#include <QSettings>
#include <QMap>
#include <QString>
#include <QVariant>
#include <QSet>
#include <QPair>
#include <QStringList>
#include "include/GUI/Themes/Colors.h"

namespace DirectObfuscation {
class StubMapper {
public:
    StubMapper(QSettings* settings);
    void setSettings(QSettings* settings);
    bool generateCustomExports();
    QPair<int, QString> applyCustomSyscallSettings(const QString& syscallName, int realOffset, const QMap<QString, QVariant>& customSettings = QMap<QString, QVariant>());
    
private:
    QSettings* settings;
    int extractSyscallOffset(const QString& line);
    QString getAsmFilePath(bool isKernelMode);
    QString getHeaderFilePath(bool isKernelMode);
    QString getDefFilePath(bool isKernelMode);
    bool isKernelMode();
    QString getSyscallPrefix();
    bool processAssemblyFile(const QString& asmPath, const QString& headerPath);
    bool updateHeaderFile(const QString& headerPath, const QMap<QString, QString>& syscallMap, const QMap<QString, QString>& functionSuffixes);
    bool updateDefFile(const QString& defPath, const QStringList& obfuscatedNames);
    int getRandomInt(int min, int max);
    void logMessage(const QString& message);
    std::function<void(const QString&)> outputCallback;
    
public:
    void setOutputCallback(std::function<void(const QString&)> callback);
};
}

#endif
