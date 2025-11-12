#pragma once

#include <QMap>
#include <QSettings>
#include <QString>
#include <QStringList>
#include <Core/Utils/Dependencies.h>

class IndirectObfuscationManager {
private:
    QSettings* settings;
    std::function<void(const QString&)> outputCallback;

    void logMessage(const QString& message);
    QString getIndirectPrefix();
    bool isIndirectMode();
    bool updateIndirectHeaderFile(const QString& headerPath,
                                  const QMap<QString, QString>& syscallMap);
    bool updateDefFile(const QString& defPath, const QStringList& obfuscatedNames);

public:
    explicit IndirectObfuscationManager(QSettings* settings);

    void setOutputCallback(std::function<void(const QString&)> callback);
    bool generateIndirectObfuscation();
    bool processIndirectAssemblyFile(const QString& asmPath, const QString& headerPath);
};