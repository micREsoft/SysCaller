#pragma once

#include <QSettings>
#include <QString>
#include <QStringList>
#include <functional>

class IndirectObfuscationManager {
private:
    QSettings* settings;
    std::function<void(const QString&)> outputCallback;

public:
    IndirectObfuscationManager(QSettings* settings);
    void setOutputCallback(std::function<void(const QString&)> callback);
    bool generateIndirectObfuscation();
    bool processIndirectAssemblyFile(const QString& asmPath, const QString& headerPath);
    
private:
    void logMessage(const QString& message);
    QString getIndirectPrefix();
    bool isIndirectMode();
    bool updateIndirectHeaderFile(const QString& headerPath,
                                  const QMap<QString, QString>& syscallMap);
    bool updateDefFile(const QString& defPath, const QStringList& obfuscatedNames);
}; 
