#pragma once

#include <QSettings>
#include <QString>
#include <QStringList>
#include <functional>

class IndirectObfuscation {
private:
    QSettings* settings;
    std::function<void(const QString&)> outputCallback;

public:
    IndirectObfuscation(QSettings* settings);
    void setOutputCallback(std::function<void(const QString&)> callback);
    bool generateIndirectObfuscation();
    bool processIndirectAssemblyFile(const QString& asmPath, const QString& headerPath);
    QString generateObfuscatedResolver();
    QString generateObfuscatedHashTable();
    QString generateObfuscatedFunctionPointers();
    QString generateJunkCodeForIndirect();
    QString generateEncryptedSyscallNumbers();
    QString obfuscateResolverCall(const QString& originalCall);
    QString obfuscateHashComputation(const QString& functionName);
    QString obfuscateFunctionPointerLookup(const QString& functionName);
    
private:
    void logMessage(const QString& message);
    QString getIndirectPrefix();
    bool isIndirectMode();
};
