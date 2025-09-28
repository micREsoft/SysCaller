#pragma once

#include <QString>
#include <QStringList>
#include <QMap>
#include <QSettings>
#include <QObject>
#include <QList>
#include <QPair>
#include <vector>
#include <cstdint>
#include <pe-parse/parse.h>
#include <functional>
#include <optional>
#include "include/GUI/Themes/Colors.h"
#include "include/Core/Utils/Utils.h"

class Verification : public QObject {
    Q_OBJECT

public:
    explicit Verification();

    int run(int argc, char* argv[]);
    int runWithDllPaths(const QStringList& dllPaths);
    void setOutputCallback(std::function<void(const QString&)> callback);

signals:
    void progressMessage(const QString& message);

private:
    struct Parameter {
        QString type;
        QString name;
        bool optional;
    };

    struct SyscallDefinition {
        QString name;
        QString returnType;
        QList<Parameter> parameters;
        QString offset;
        QString description;
    };

    struct TypeDefinition {
        QString file;
        QString definition;
    };

    struct TestResult {
        QString name;
        QString status;
        QString offset;
        QString returnType;
        int parameterCount;
        QStringList errors;
        QList<QPair<QString, QString>> typeDefinitions;  /* type, source_file */
    };

    class TypeDefinitionTracker {
    public:
        TypeDefinitionTracker();

        void parseHeaderFiles();
        std::optional<TypeDefinition> checkType(const QString& typeName, bool isKernelMode);

    private:
        QMap<QString, TypeDefinition> typeDefinitions;
        QStringList externalTypes;
        bool isKernelMode;
    };

    void parseSyscallDefinitions();
    QMap<QString, QString> parseSyscallOffsets(const QString& asmPath);
    std::optional<int> getOffsetFromDll(const QString& syscallName, const QString& dllPath = QString());
    TestResult testSyscall(const SyscallDefinition& syscall);
    bool validateParameterType(const QString& paramType);
    void runTests(const QString& outputFormat = "console");
    void printResult(const TestResult& result);
    void outputProgress(const QString& message);
    QString getIniPath();
    QString getAsmFilePath(bool isKernelMode);
    QString getHeaderFilePath(bool isKernelMode);

    QMap<QString, SyscallDefinition> syscalls;
    QList<TestResult> testResults;
    QStringList dllPaths;
    QString dllPath;
    TypeDefinitionTracker typeTracker;
    peparse::parsed_pe* pe;
    uint64_t imageBase;
    QMap<QString, int> syscallNumbers;
    std::function<void(const QString&)> outputCallback;
};