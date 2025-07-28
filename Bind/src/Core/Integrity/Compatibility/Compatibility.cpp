#include "include/Core/Integrity/Compatibility/Compatibility.h"
#include "include/Core/Utils/PathUtils.h"
#include <QFile>
#include <QDir>
#include <QTextStream>
#include <QRegularExpression>
#include <QDebug>
#include <QProcessEnvironment>
#include <pe-parse/parse.h>
#include <cstring>

Compatibility::Compatibility() : QObject(nullptr) {}

void Compatibility::setOutputCallback(std::function<void(const QString&)> callback) {
    outputCallback = callback;
}

void Compatibility::outputProgress(const QString& message) {
    if (outputCallback) {
        outputCallback(message);
    }
}

int Compatibility::run(int argc, char* argv[]) {
    return runWithDllPaths(QStringList() << "C:\\Windows\\System32\\ntdll.dll");
}

int Compatibility::runWithDllPaths(const QStringList& dllPaths) {
    qDebug() << QString("Compatibility::runWithDllPaths() called with paths: %1").arg(dllPaths.join(", "));
    QSettings settings(getIniPath(), QSettings::IniFormat);
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    bool isKernelMode = (syscallMode == "Zw");
    qDebug() << QString("Syscall Mode: %1, Kernel Mode: %2").arg(syscallMode).arg(isKernelMode);
    QString asmFile = getAsmFilePath(isKernelMode);
    qDebug() << QString("ASM File Path: %1").arg(asmFile);
    QStringList dllPathsToUse = dllPaths;
    if (dllPathsToUse.isEmpty()) {
        dllPathsToUse << "C:\\Windows\\System32\\ntdll.dll";
    }
    qDebug() << QString("Using DLL Paths: %1").arg(dllPathsToUse.join(", "));
    validateSyscalls(asmFile, dllPathsToUse);
    return 0;
}

QList<Compatibility::SyscallInfo> Compatibility::readSyscalls(const QString& asmFile) {
    QList<SyscallInfo> syscalls;
    QMap<QString, QString> uniqueOffsets;
    QMap<QString, QString> uniqueNames;
    QFile file(asmFile);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "Failed to open ASM File:" << asmFile;
        return syscalls;
    }
    QTextStream stream(&file);
    SyscallInfo currentSyscall;
    bool hasCurrentSyscall = false;
    qDebug() << "Debug: Reading ASM File:" << asmFile;
    int lineCount = 0;
    while (!stream.atEnd()) {
        QString line = stream.readLine();
        lineCount++;
        if (lineCount <= 10) {
            qDebug() << "Debug: Line" << lineCount << ":" << line.trimmed();
        }
        QRegularExpression procMatch("((Sys|SysK)\\w+)\\s+PROC");
        QRegularExpressionMatch match = procMatch.match(line.trimmed());
        if (line.trimmed().contains("PROC") && (line.trimmed().startsWith("Sys") || line.trimmed().startsWith("SysK"))) {
            qDebug() << "Debug: Line contains PROC and starts with Sys/SysK:" << line.trimmed();
            if (!match.hasMatch()) {
                qDebug() << "Debug: But Regex didn't match!";
            }
        }
        if (match.hasMatch()) {
            qDebug() << "Debug: Found Syscall Line:" << line.trimmed() << "Captured:" << match.captured(1);
        }
        if (match.hasMatch()) {
            if (hasCurrentSyscall && !syscalls.contains(currentSyscall)) {
                syscalls.append(currentSyscall);
            }
            QString syscallName = match.captured(1);
            QString baseName;
            int version = 1;
            QRegularExpression versionMatch(R"((Sys|SysK)(\w+?)([A-Z])?$)");
            QRegularExpressionMatch vMatch = versionMatch.match(syscallName);
            if (vMatch.hasMatch()) {
                QString prefix = vMatch.captured(1); // "Sys" or "SysK"
                QString namePart = vMatch.captured(2); // the actual function name
                QString versionPart = vMatch.captured(3); // the version letter
                baseName = prefix + namePart;
                if (!versionPart.isEmpty()) {
                    // convert letter to version number A=2, B=3, C=4, etc
                    version = versionPart.at(0).toLatin1() - 'A' + 2;
                } else {
                    version = 1;
                }
            } else {
                baseName = syscallName;
                version = 1;
            }
            qDebug() << QString("Debug: Parsed Syscall '%1' -> BaseName='%2', Version=%3").arg(syscallName).arg(baseName).arg(version);
            currentSyscall = SyscallInfo{
                syscallName,
                baseName,
                version,
                0,
                false,
                "",
                false,
                ""
            };
            hasCurrentSyscall = true;
            QString nameKey = QString("%1_%2").arg(baseName).arg(version);
            if (uniqueNames.contains(nameKey)) {
                currentSyscall.duplicateName = true;
                currentSyscall.duplicateNameWith = uniqueNames[nameKey];
            } else {
                currentSyscall.duplicateName = false;
                uniqueNames[nameKey] = syscallName;
            }
        }
        QRegularExpression offsetMatch(R"(mov\s+(eax|rax),\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)h?)");
        QRegularExpressionMatch oMatch = offsetMatch.match(line);
        if (hasCurrentSyscall && oMatch.hasMatch() && !line.trimmed().startsWith(";")) {
            QString offsetValue = oMatch.captured(2);
            bool ok;
            int offset;
            if (offsetValue.startsWith("0x")) {
                offset = offsetValue.toInt(&ok, 16);
            } else {
                offset = offsetValue.remove("h").toInt(&ok, 16);
            }
            
            if (ok) {
                currentSyscall.offset = offset;
                QString offsetKey = QString("%1_%2").arg(offset).arg(currentSyscall.version);
                
                if (uniqueOffsets.contains(offsetKey)) {
                    currentSyscall.duplicateOffset = true;
                    currentSyscall.duplicateOffsetWith = uniqueOffsets[offsetKey];
                } else {
                    currentSyscall.duplicateOffset = false;
                    uniqueOffsets[offsetKey] = currentSyscall.name;
                }
            }
        }
        if (hasCurrentSyscall && line.contains("ENDP") && !syscalls.contains(currentSyscall)) {
            syscalls.append(currentSyscall);
        }
    }
    if (hasCurrentSyscall && !syscalls.contains(currentSyscall)) {
        syscalls.append(currentSyscall);
    }
    file.close();
    return syscalls;
}

void Compatibility::printLegend() {
    outputProgress("");
    outputProgress(Colors::BOLD() + "Bind Legend:" + Colors::ENDC());
    outputProgress(Colors::BOLD() + "Nt/Zw = Indicates type of syscall stub found" + Colors::ENDC());
    outputProgress(Colors::BOLD() + "DUP = Duplicate Offset or Name (conflicts with another syscall)" + Colors::ENDC());
    outputProgress(Colors::BOLD() + "Found = Found Syscall Name (resolved in DLL)" + Colors::ENDC());
    outputProgress(Colors::BOLD() + "Not Found = Syscall not Found in DLL" + Colors::ENDC());
    outputProgress(Colors::BOLD() + "MATCH = Syscall Name and Offset Match ntdll Version" + Colors::ENDC());
    outputProgress(Colors::BOLD() + "MISMATCH = Syscall Name or Offset Mismatch with ntdll Version" + Colors::ENDC());
    outputProgress(Colors::BOLD() + "f = Found Offset (resolved in DLL)" + Colors::ENDC());
    outputProgress(Colors::BOLD() + "i = Invalid Offset (could not be resolved or malformed)" + Colors::ENDC());
    outputProgress(Colors::BOLD() + "v = Valid Offset (resolved in DLL)" + Colors::ENDC());
    outputProgress("");
}

void Compatibility::validateSyscalls(const QString& asmFile, const QStringList& dllPaths) {
    QSettings settings(getIniPath(), QSettings::IniFormat);
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    bool isZwMode = (syscallMode == "Zw");
    QString modeDisplay = isZwMode ? "Zw" : "Nt";
    QList<SyscallInfo> syscalls = readSyscalls(asmFile);
    outputProgress(Colors::BOLD() + QString("Found %1 Syscalls in syscaller.asm").arg(syscalls.size()) + Colors::ENDC());
    for (int i = 0; i < qMin(3, syscalls.size()); ++i) {
        qDebug() << QString("Debug: Found Syscall %1 with Offset %2").arg(syscalls[i].name).arg(syscalls[i].offset);
    }
    QMap<int, QMap<QString, int>> syscallTables;
    QStringList dllPathsToUse = dllPaths;
    if (dllPathsToUse.isEmpty()) {
        dllPathsToUse << "C:\\Windows\\System32\\ntdll.dll";
    }
    QString mainDllPath = dllPathsToUse.first();
    outputProgress(Colors::OKBLUE() + QString("Processing Primary NTDLL: %1").arg(mainDllPath) + Colors::ENDC());
    syscallTables[0] = SyscallExtractor::getSyscallsFromDll(mainDllPath);
    qDebug() << QString("Found %1 Syscalls in Primary NTDLL").arg(syscallTables[0].size());
    for (int i = 1; i < dllPathsToUse.size(); ++i) {
        QString additionalDllPath = dllPathsToUse[i];
        if (!additionalDllPath.isEmpty() && QFile::exists(additionalDllPath)) {
            outputProgress(Colors::OKBLUE() + QString("Processing Additional NTDLL %1: %2").arg(i).arg(additionalDllPath) + Colors::ENDC());
            syscallTables[i] = SyscallExtractor::getSyscallsFromDll(additionalDllPath);
            qDebug() << QString("Found %1 Syscalls in Additional NTDLL %2").arg(syscallTables[i].size()).arg(i);
        } else {
            qWarning() << "Additional DLL path does not exist or is empty:" << additionalDllPath;
        }
    }
    printLegend();
    int valid = 0, invalid = 0, duplicates = 0;
    for (const SyscallInfo& syscall : syscalls) {
        int version = syscall.version;
        int dllIndex = (version == 1) ? 0 : (version - 1); // version 1 = table 0, version 2 = table 1, etc.
        qDebug() << QString("Debug: Checking Syscall '%1' (version %2) against Table %3").arg(syscall.name).arg(version).arg(dllIndex);
        if (!syscallTables.contains(dllIndex)) {
            outputProgress(Colors::WARNING() + QString("Warning: No Syscall Table found for version %1 (Table %2)").arg(version).arg(dllIndex) + Colors::ENDC());
            continue;
        }
        QMap<QString, int> syscallNumbers = syscallTables[dllIndex];
        // remove version suffix for DLL lookup
        QString baseName = syscall.baseName;
        QString expectedName;
        if (baseName.startsWith("SysK")) {
            expectedName = "Nt" + baseName.mid(4);
        } else if (baseName.startsWith("Sys")) {
            expectedName = "Nt" + baseName.mid(3);
        } else {
            expectedName = baseName;
        }
        int actualOffset = syscallNumbers.value(expectedName, 0);
        // check for duplicates only within same table
        bool isDuplicate = false;
        QString dupType, dupWith;
        if (syscall.duplicateOffset || syscall.duplicateName) {
            if (syscall.duplicateOffset && syscall.duplicateName) {
                dupType = "Duplicate Offset & Name";
                if (syscall.duplicateOffsetWith == syscall.duplicateNameWith) {
                    dupWith = QString("Offset & Name with %1").arg(syscall.duplicateOffsetWith);
                } else {
                    dupWith = QString("Offset with %1 | Name with %2").arg(syscall.duplicateOffsetWith).arg(syscall.duplicateNameWith);
                }
            } else if (syscall.duplicateOffset) {
                dupType = "Duplicate Offset";
                dupWith = QString("with %1").arg(syscall.duplicateOffsetWith);
            } else {
                dupType = "Duplicate Name";
                dupWith = QString("with %1").arg(syscall.duplicateNameWith);
            }
            isDuplicate = true;
        }
        if (isDuplicate) {
            duplicates++;
            QString prefix = (syscall.offset == actualOffset) ? "v" : "i";
            outputProgress(Colors::WARNING() + QString("%1: %2 (%3) %40x%5 f0x%6 (DUP) %7").arg(syscall.name)
                         .arg(dupType)
                         .arg(modeDisplay)
                         .arg(prefix)
                         .arg(syscall.offset, 0, 16)
                         .arg(actualOffset, 0, 16)
                         .arg(dupWith) + Colors::ENDC());
            continue;
        }
        if (syscallNumbers.contains(expectedName)) {
            if (syscall.offset == syscallNumbers[expectedName]) {
                valid++;
                outputProgress(Colors::OKGREEN() + QString("%1: Found (%2) v0x%3 f0x%4 (MATCH)")
                             .arg(syscall.name)
                             .arg(modeDisplay)
                             .arg(syscall.offset, 0, 16)
                             .arg(syscallNumbers[expectedName], 0, 16) + Colors::ENDC());
            } else {
                invalid++;
                outputProgress(Colors::FAIL() + QString("%1: Found (%2) i0x%3 f0x%4 (MISMATCH)")
                             .arg(syscall.name)
                             .arg(modeDisplay)
                             .arg(syscall.offset, 0, 16)
                             .arg(syscallNumbers[expectedName], 0, 16) + Colors::ENDC());
            }
        } else {
            invalid++;
            outputProgress(Colors::FAIL() + QString("%1: Not Found (%2) i0x%3 f0x%4 (MISMATCH)")
                         .arg(syscall.name)
                         .arg(modeDisplay)
                         .arg(syscall.offset, 0, 16)
                         .arg(actualOffset, 0, 16) + Colors::ENDC());
        }
    }
    outputProgress(Colors::BOLD() + QString("Valid: ") + Colors::OKGREEN() + QString::number(valid) + Colors::ENDC() + 
                   Colors::BOLD() + QString(", Invalid: ") + Colors::FAIL() + QString::number(invalid) + Colors::ENDC() + 
                   Colors::BOLD() + QString(", Duplicates: ") + Colors::WARNING() + QString::number(duplicates) + Colors::ENDC());
}

QString Compatibility::getIniPath() {
    return PathUtils::getIniPath();
}

QString Compatibility::getAsmFilePath(bool isKernelMode) {
    return PathUtils::getSysCallerAsmPath(isKernelMode);
}