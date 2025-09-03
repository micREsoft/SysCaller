#pragma once

#include <QString>
#include <QStringList>
#include <QMap>
#include <QSet>
#include <QVector>
#include <QSettings>
#include <QObject>
#include <vector>
#include <cstdint>
#include <pe-parse/parse.h>
#include <functional>
#include "include/GUI/Themes/Colors.h"
#include "include/Core/Utils/Utils.h"

class Validator : public QObject {
    Q_OBJECT

public:
    explicit Validator();

    int run(int argc, char* argv[]);
    int runWithDllPaths(const QStringList& dllPaths);
    void setOutputCallback(std::function<void(const QString&)> callback);

signals:
    void progressMessage(const QString& message);

private:
    struct SyscallInfo {
        int start;
        int end;
        QStringList content;
    };

    QMap<QString, SyscallInfo> parseAsmFile(const QString& asmFile);
    void updateSyscalls(const QString& asmFile, const QMap<int, QMap<QString, int>>& syscallTables);
    void updateHeaderFile(const QMap<int, QMap<QString, int>>& syscallTables,
                          const QStringList& selectedSyscalls,
                          bool useAllSyscalls);
    void updateDefFile(const QStringList& syscallNames, const QString& defPath);
    QString generateIndirectStub(const QString& stubName, int syscallId);
    QString getIniPath();
    QString getHeaderFilePath(bool isKernelMode);
    QString getAsmFilePath(bool isKernelMode);
    QString getDefFilePath();
    void outputProgress(const QString& message);

    std::function<void(const QString&)> outputCallback;
};