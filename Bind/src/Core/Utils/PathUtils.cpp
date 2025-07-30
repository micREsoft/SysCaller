#include "include/Core/Utils/PathUtils.h"
#include <QApplication>
#include <QStandardPaths>
#include <QDebug>
#include <QFile>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QDateTime>
#include <QDir>
#include <QSettings>

static QString s_projectRoot;

QString PathUtils::getProjectRoot() {
    if (s_projectRoot.isEmpty()) {
        s_projectRoot = findProjectRoot();
    }
    return s_projectRoot;
}

QString PathUtils::getBackupsPath() {
    return getProjectRoot() + "/Backups";
}

QString PathUtils::getHashBackupsPath() {
    return getBackupsPath() + "/Hashes";
}

QString PathUtils::getDefaultPath() {
    return getProjectRoot() + "/Default";
}

QString PathUtils::getSysCallerPath() {
    return getProjectRoot() + "/SysCaller";
}

QString PathUtils::getSysCallerKPath() {
    return getProjectRoot() + "/SysCallerK";
}

QString PathUtils::getSysFunctionsPath(bool isKernelMode) {
    if (isKernelMode) {
        return getSysCallerKPath() + "/Wrapper/include/SysK/sysFunctions_k.h";
    } else {
        return getSysCallerPath() + "/Wrapper/include/Sys/sysFunctions.h";
    }
}

QString PathUtils::getSysCallerAsmPath(bool isKernelMode) {
    if (isKernelMode) {
        return getSysCallerKPath() + "/Wrapper/src/syscaller.asm";
    } else {
        return getSysCallerPath() + "/Wrapper/src/syscaller.asm";
    }
}

QString PathUtils::getDefaultSysFunctionsPath(bool isKernelMode) {
    if (isKernelMode) {
        return getDefaultPath() + "/sysFunctions_k.h";
    } else {
        return getDefaultPath() + "/sysFunctions.h";
    }
}

QString PathUtils::getDefaultSysCallerAsmPath() {
    return getDefaultPath() + "/syscaller.asm";
}

QString PathUtils::getIniPath() {
    return getProjectRoot() + "/SysCaller.ini";
}

QString PathUtils::findProjectRoot() {
    QDir dir(QApplication::applicationDirPath());
    qDebug() << "Starting Path Resolution from:" << dir.absolutePath();
    while (!dir.isRoot()) {
        QString currentPath = QDir::cleanPath(dir.absolutePath());
        QFileInfo info(currentPath);
        qDebug() << "Checking Directory:" << currentPath << "Name:" << info.fileName();
        if (info.fileName() == "SysCaller") {
            qDebug() << "Found SysCaller Directory:" << currentPath;
            if (isProjectRoot(currentPath)) {
                qDebug() << "Found Project Root (validated):" << currentPath;
                return currentPath;
            } else {
                qDebug() << "SysCaller Directory found but Validation failed";
            }
        }
        QDir parentDir = dir;
        parentDir.cdUp();
        QString parentPath = QDir::cleanPath(parentDir.absolutePath());
        QFileInfo parentInfo(parentPath);
        if (parentInfo.fileName() == "SysCaller") {
            qDebug() << "Found SysCaller Parent Directory:" << parentPath;
            if (isProjectRoot(parentPath)) {
                qDebug() << "Found Project Root (Validated):" << parentPath;
                return parentPath;
            }
        }
        dir.cdUp();
    }
    QDir dir2(QApplication::applicationDirPath());
    while (!dir2.isRoot()) {
        QString currentPath = QDir::cleanPath(dir2.absolutePath());
        QFileInfo info(currentPath);
        if (info.fileName() == "Bind") {
            qDebug() << "Found Bind Directory:" << currentPath;
            QDir projectRootDir = dir2;
            projectRootDir.cdUp();
            QString projectRootPath = QDir::cleanPath(projectRootDir.absolutePath());
            qDebug() << "Checking Potential Project Root:" << projectRootPath;
            if (isProjectRoot(projectRootPath)) {
                qDebug() << "Found Project Root via Bind:" << projectRootPath;
                return projectRootPath;
            }
        }
        dir2.cdUp();
    }
    QString hardcodedPath = "C:/Users/devil/source/repos/SysCaller";
    if (QDir(hardcodedPath).exists() && isProjectRoot(hardcodedPath)) {
        qDebug() << "Using Hardcoded Project Root:" << hardcodedPath;
        return hardcodedPath;
    }
    qWarning() << "Project Root not found, falling back to executable directory";
    return QApplication::applicationDirPath();
}

bool PathUtils::isProjectRoot(const QString& path) {
    QDir dir(path);
    QStringList requiredItems = {
        "SysCaller",
        "SysCallerK",
        "Backups",
        "Bindings"
    };
    int foundItems = 0;
    for (const QString& item : requiredItems) {
        if (dir.exists(item)) {
            foundItems++;
            qDebug() << "Found Project Root Item:" << item;
        } else {
            qDebug() << "Missing Project Root Item:" << item;
        }
    }
    bool isValid = (foundItems >= 3);
    qDebug() << "Project Root Validation Result:" << isValid << "(" << foundItems << "/" << requiredItems.size() << " Items Found)";
    return isValid;
}

void PathUtils::debugPathDetection() {
    qDebug() << "=== PathUtils Debug Information ===";
    qDebug() << "Application Directory:" << QApplication::applicationDirPath();
    qDebug() << "Project Root:" << getProjectRoot();
    qDebug() << "Backups Path:" << getBackupsPath();
    qDebug() << "Hash Backups Path:" << getHashBackupsPath();
    qDebug() << "Default Path:" << getDefaultPath();
    qDebug() << "SysCaller Path:" << getSysCallerPath();
    qDebug() << "SysCallerK Path:" << getSysCallerKPath();
    qDebug() << "SysFunctions Path (Nt):" << getSysFunctionsPath(false);
    qDebug() << "SysFunctions Path (Zw):" << getSysFunctionsPath(true);
    qDebug() << "INI Path:" << getIniPath();
    qDebug() << "SysCaller.ini Exists:" << QFile::exists(getIniPath());
    qDebug() << "sysFunctions.h Exists:" << QFile::exists(getSysFunctionsPath(false));
    qDebug() << "sysFunctions_k.h Exists:" << QFile::exists(getSysFunctionsPath(true));
    qDebug() << "=== End PathUtils Debug ===";
} 
