#pragma once

#include <QObject>
#include <QList>
#include <QSettings>
#include <QString>
#include <QStringList>
#include <Core/Utils/Dependencies.h>
#include <Core/Utils/Utils.h>
#include <GUI/Themes/Colors.h>
#include <pe-parse/parse.h>

class Compatibility : public QObject {
    Q_OBJECT

public:
    explicit Compatibility();

    int run(int argc, char* argv[]);
    int runWithDllPaths(const QStringList& dllPaths);
    void setOutputCallback(std::function<void(const QString&)> callback);

signals:
    void progressMessage(const QString& message);

private:
    struct SyscallInfo {
        QString name;
        QString baseName;
        int version;
        int offset;
        bool duplicateName;
        QString duplicateNameWith;
        bool duplicateOffset;
        QString duplicateOffsetWith;

        bool operator==(const SyscallInfo& other) const {
            return name == other.name &&
                   baseName == other.baseName &&
                   version == other.version &&
                   offset == other.offset;
        }
    };

    QList<SyscallInfo> readSyscalls(const QString& asmFile);
    void validateSyscalls(const QString& asmFile, const QStringList& dllPaths);
    void printLegend();
    QString getIniPath();
    QString getAsmFilePath(bool isKernelMode);
    void outputProgress(const QString& message);

    std::function<void(const QString&)> outputCallback;
};