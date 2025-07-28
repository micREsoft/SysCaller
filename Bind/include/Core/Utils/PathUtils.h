#ifndef PATHUTILS_H
#define PATHUTILS_H

#include <QString>
#include <QDir>
#include <QFileInfo>
#include <QVariantMap>
#include <QPair>

class PathUtils {
public:
    static QString getProjectRoot();
    static QString getBuildToolsPath();
    static QString getBackupsPath();
    static QString getDefaultPath();
    static QString getSysCallerPath();
    static QString getSysCallerKPath();
    static QString getSysFunctionsPath(bool isKernelMode = false);
    static QString getSysCallerAsmPath(bool isKernelMode = false);
    static QString getDefaultSysFunctionsPath(bool isKernelMode = false);
    static QString getDefaultSysCallerAsmPath();
    static QString getIniPath();
    static void debugPathDetection();
    static QString getHashBackupsPath();

private:
    static QString findProjectRoot();
    static bool isProjectRoot(const QString& path);
};

#endif