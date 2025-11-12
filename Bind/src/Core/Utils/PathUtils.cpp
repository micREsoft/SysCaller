#include <Core/Utils/Common.h>

static QString s_projectRoot;

QString PathUtils::getProjectRoot()
{
    if (s_projectRoot.isEmpty())
    {
        s_projectRoot = findProjectRoot();
    }

    return s_projectRoot;
}

QString PathUtils::getBackupsPath()
{
    return QDir(getProjectRoot()).filePath("Backups");
}

QString PathUtils::getHashBackupsPath()
{
    return QDir(getBackupsPath()).filePath("Hashes");
}

QString PathUtils::getDefaultPath()
{
    return QDir(getProjectRoot()).filePath("Default");
}

QString PathUtils::getSysCallerPath()
{
    return QDir(getProjectRoot()).filePath("SysCaller");
}

QString PathUtils::getSysCallerKPath()
{
    return QDir(getProjectRoot()).filePath("SysCallerK");
}

QString PathUtils::getSysFunctionsPath(bool isKernelMode)
{
    if (isKernelMode)
    {
        return QDir(getSysCallerKPath()).filePath("Wrapper/include/SysK/SysKFunctions.h");
    }
    else
    {
        return QDir(getSysCallerPath()).filePath("Wrapper/include/Sys/SysFunctions.h");
    }
}

QString PathUtils::getSysCallerAsmPath(bool isKernelMode)
{
    if (isKernelMode)
    {
        return QDir(getSysCallerKPath()).filePath("Wrapper/src/SysCaller.asm");
    }
    else
    {
        return QDir(getSysCallerPath()).filePath("Wrapper/src/SysCaller.asm");
    }
}

QString PathUtils::getDefaultSysFunctionsPath(bool isKernelMode)
{
    if (isKernelMode)
    {
        return QDir(getDefaultPath()).filePath("SysKFunctions.h");
    }
    else
    {
        return QDir(getDefaultPath()).filePath("SysFunctions.h");
    }
}

QString PathUtils::getDefaultSysCallerAsmPath()
{
    return QDir(getDefaultPath()).filePath("SysCaller.asm");
}

QString PathUtils::getIniPath()
{
    return QDir(getProjectRoot()).filePath("SysCaller.ini");
}

QString PathUtils::findProjectRoot()
{
    QDir dir(QApplication::applicationDirPath());
    qDebug() << "Starting Path Resolution from:" << dir.absolutePath();

    while (!dir.isRoot())
    {
        QString currentPath = QDir::cleanPath(dir.absolutePath());
        QFileInfo info(currentPath);
        qDebug() << "Checking Directory:" << currentPath << "Name:" << info.fileName();

        if (info.fileName() == "SysCaller")
        {
            qDebug() << "Found SysCaller Directory:" << currentPath;

            if (isProjectRoot(currentPath))
            {
                qDebug() << "Found Project Root (validated):" << currentPath;
                return currentPath;
            }
            else
            {
                qDebug() << "SysCaller Directory found but Validation failed";
            }
        }

        QDir parentDir = dir;
        parentDir.cdUp();
        QString parentPath = QDir::cleanPath(parentDir.absolutePath());
        QFileInfo parentInfo(parentPath);

        if (parentInfo.fileName() == "SysCaller")
        {
            qDebug() << "Found SysCaller Parent Directory:" << parentPath;

            if (isProjectRoot(parentPath))
            {
                qDebug() << "Found Project Root (Validated):" << parentPath;
                return parentPath;
            }
        }

        dir.cdUp();
    }
    QDir dir2(QApplication::applicationDirPath());

    while (!dir2.isRoot())
    {
        QString currentPath = QDir::cleanPath(dir2.absolutePath());
        QFileInfo info(currentPath);

        if (info.fileName() == "Bind")
        {
            qDebug() << "Found Bind Directory:" << currentPath;

            QDir projectRootDir = dir2;
            projectRootDir.cdUp();
            QString projectRootPath = QDir::cleanPath(projectRootDir.absolutePath());
            qDebug() << "Checking Potential Project Root:" << projectRootPath;

            if (isProjectRoot(projectRootPath))
            {
                qDebug() << "Found Project Root via Bind:" << projectRootPath;
                return projectRootPath;
            }
        }

        dir2.cdUp();
    }

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    QString envPath = env.value("SYSCALLER_ROOT", "");
    
    if (!envPath.isEmpty())
    {
        QString cleanPath = QDir::cleanPath(envPath);
        if (QDir(cleanPath).exists() && isProjectRoot(cleanPath))
        {
            qDebug() << "Using SYSCALLER_ROOT environment variable:" << cleanPath;
            return cleanPath;
        }
        else
        {
            qWarning() << "SYSCALLER_ROOT environment variable set but path is invalid:" << cleanPath;
        }
    }

    qWarning() << "Project Root not found, falling back to executable directory";
    return QApplication::applicationDirPath();
}

bool PathUtils::isProjectRoot(const QString& path)
{
    QDir dir(path);
    QStringList requiredItems =
    {
        "SysCaller",
        "SysCallerK",
        "Backups",
        "Bindings"
    };

    int foundItems = 0;

    for (const QString& item : requiredItems)
    {
        if (dir.exists(item))
        {
            foundItems++;
            qDebug() << "Found Project Root Item:" << item;
        }
        else
        {
            qDebug() << "Missing Project Root Item:" << item;
        }
    }

    bool isValid = (foundItems >= 3);
    qDebug() << "Project Root Validation Result:" << isValid << "(" << foundItems << "/" << requiredItems.size() << " Items Found)";
    return isValid;
}

void PathUtils::debugPathDetection()
{
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
    qDebug() << "SysFunctions.h Exists:" << QFile::exists(getSysFunctionsPath(false));
    qDebug() << "SysKFunctions.h Exists:" << QFile::exists(getSysFunctionsPath(true));
    qDebug() << "=== End PathUtils Debug ===";
}