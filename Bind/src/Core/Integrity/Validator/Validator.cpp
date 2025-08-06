#include "include/Core/Integrity/Validator/Validator.h"
#include "include/Core/Utils/PathUtils.h"
#include "include/Core/Utils/Utils.h"
#include <QFile>
#include <QDir>
#include <QTextStream>
#include <QRegularExpression>
#include <QDebug>
#include <QProcessEnvironment>
#include <pe-parse/parse.h>
#include <cstring>

Validator::Validator() : QObject(nullptr) {}

void Validator::setOutputCallback(std::function<void(const QString&)> callback) {
    outputCallback = callback;
}

void Validator::outputProgress(const QString& message) {
    if (outputCallback) {
        outputCallback(message);
    }
}

int Validator::run(int argc, char* argv[]) {
    return runWithDllPaths(QStringList() << "C:\\Windows\\System32\\ntdll.dll");
}

int Validator::runWithDllPaths(const QStringList& dllPaths) {
    qDebug() << QString("Validator::runWithDllPaths() called with paths: %1").arg(dllPaths.join(", "));
    QSettings settings(getIniPath(), QSettings::IniFormat);
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    bool isKernelMode = (syscallMode == "Zw");
    qDebug() << QString("Syscall Mode: %1, Kernel Mode: %2").arg(syscallMode).arg(isKernelMode);
    QString baseDir = PathUtils::getProjectRoot();
    QString asmFile = getAsmFilePath(isKernelMode);
    qDebug() << QString("Base Dir: %1").arg(baseDir);
    qDebug() << QString("ASM File Path: %1").arg(asmFile);
    QStringList dllPathsToUse = dllPaths;
    if (dllPathsToUse.isEmpty()) {
        dllPathsToUse << "C:\\Windows\\System32\\ntdll.dll";
    }
    qDebug() << QString("Using DLL Paths: %1").arg(dllPathsToUse.join(", "));
    QMap<int, QMap<QString, int>> syscallTables;
    QString mainDllPath = dllPathsToUse.first();
    outputProgress(Colors::OKBLUE() + QString("Processing Primary NTDLL: %1").arg(mainDllPath) + Colors::ENDC());
    qDebug() << QString("Processing Primary NTDLL: %1").arg(mainDllPath);
    qDebug() << "DLL Path Exists:" << QFile::exists(mainDllPath);
    if (!QFile::exists(mainDllPath)) {
        qWarning() << "Primary DLL path does not exist:" << mainDllPath;
        qWarning() << "Using default path: C:\\Windows\\System32\\ntdll.dll";
        mainDllPath = "C:\\Windows\\System32\\ntdll.dll";
        if (!QFile::exists(mainDllPath)) {
            qCritical() << "Default DLL path also does not exist! Cannot proceed.";
            return -1;
        }
    }
    syscallTables[0] = SyscallExtractor::getSyscallsFromDll(mainDllPath);
    qDebug() << QString("Found %1 Syscalls in Primary NTDLL").arg(syscallTables[0].size());
    if (syscallTables[0].size() > 0) {
        qDebug() << "Sample Syscalls from Primary NTDLL:";
        int count = 0;
        for (auto it = syscallTables[0].begin(); it != syscallTables[0].end() && count < 5; ++it, ++count) {
            qDebug() << "  " << it.key() << "->" << it.value();
        }
    }
    for (int i = 1; i < dllPathsToUse.size(); ++i) {
        QString additionalDllPath = dllPathsToUse[i];
        if (!additionalDllPath.isEmpty() && QFile::exists(additionalDllPath)) {
            outputProgress(Colors::OKBLUE() + QString("Processing Additional NTDLL %1: %2").arg(i).arg(additionalDllPath) + Colors::ENDC());
            qDebug() << "Processing Additional NTDLL" << i << ":" << additionalDllPath;
            syscallTables[i] = SyscallExtractor::getSyscallsFromDll(additionalDllPath);
        } else {
            qWarning() << "Additional DLL path does not exist or is empty:" << additionalDllPath;
        }
    }
    qDebug() << QString("About to call updateSyscalls...");
    updateSyscalls(asmFile, syscallTables);
    qDebug() << QString("updateSyscalls completed");
    bool bindingsEnabled = settings.value("general/bindings_enabled", false).toBool();
    bool indirectAssemblyMode = settings.value("general/indirect_assembly", false).toBool();
    if (bindingsEnabled && !isKernelMode) {
        qDebug() << QString("Bindings enabled, parsing updated ASM file for Sys* PROC patterns...");
        QStringList syscallNames;
        QFile file(asmFile);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream stream(&file);
            QRegularExpression procRegex(R"(^\s*(Sys\w+)\s+PROC)");
            while (!stream.atEnd()) {
                QString line = stream.readLine();
                QRegularExpressionMatch match = procRegex.match(line);
                if (match.hasMatch()) {
                    QString syscallName = match.captured(1);
                    syscallNames.append(syscallName);
                    qDebug() << "Found Syscall for DEF File:" << syscallName;
                }
            }
            file.close();
        }
        if (indirectAssemblyMode && syscallMode == "Nt") {
            syscallNames.append("GetSyscallNumber");
            syscallNames.append("InitializeResolver");
            syscallNames.append("CleanupResolver");
            qDebug() << "Added resolver functions to DEF file";
        }
        qDebug() << QString("Found %1 Syscalls for DEF File").arg(syscallNames.size());
        QString defPath = getDefFilePath();
        updateDefFile(syscallNames, defPath);
        qDebug() << QString("Updated DEF File: %1").arg(defPath);
    }
    return 0;
}

QMap<QString, Validator::SyscallInfo> Validator::parseAsmFile(const QString& asmFile) {
    QMap<QString, SyscallInfo> syscalls;
    QFile file(asmFile);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return syscalls;
    }
    QTextStream stream(&file);
    QStringList lines;
    while (!stream.atEnd()) {
        lines.append(stream.readLine());
    }
    file.close();
    QString currentSyscall;
    int startIndex = -1;
    for (int i = 0; i < lines.size(); ++i) {
        QString line = lines[i];
        QRegularExpression procMatch(R"((Sys\w+|SC\w+)\s+PROC)");
        QRegularExpressionMatch match = procMatch.match(line);
        if (match.hasMatch()) {
            if (!currentSyscall.isEmpty()) {
                syscalls[currentSyscall].end = i - 1;
            }
            currentSyscall = match.captured(1);
            syscalls[currentSyscall].start = i;
            syscalls[currentSyscall].end = -1;
        } else if (!currentSyscall.isEmpty() && line.contains("ENDP")) {
            syscalls[currentSyscall].end = i;
            currentSyscall.clear();
        }
    }
    if (!currentSyscall.isEmpty()) {
        syscalls[currentSyscall].end = lines.size() - 1;
    }
    for (auto it = syscalls.begin(); it != syscalls.end(); ++it) {
        int start = it.value().start;
        int end = it.value().end;
        if (start >= 0 && end >= start && end < lines.size()) {
            for (int i = start; i <= end; ++i) {
                it.value().content.append(lines[i]);
            }
        }
    }
    return syscalls;
}

void Validator::updateSyscalls(const QString& asmFile, const QMap<int, QMap<QString, int>>& syscallTables) {
    QFile file(asmFile);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << "Failed to open ASM File for reading:" << asmFile;
        return;
    }
    QStringList lines;
    QTextStream stream(&file);
    while (!stream.atEnd()) {
        lines.append(stream.readLine());
    }
    file.close();
    int numTables = syscallTables.size();
    if (numTables == 0) {
        qDebug() << "No Syscall Tables provided. Aborting.";
        return;
    }
    outputProgress(Colors::OKBLUE() + QString("Processing %1 Syscall Table(s)...").arg(numTables) + Colors::ENDC());
    QSettings settings(getIniPath(), QSettings::IniFormat);
    QStringList selectedSyscalls = settings.value("integrity/selected_syscalls", QStringList()).toStringList();
    qDebug() << "Selected Syscalls from Settings:" << selectedSyscalls;
    bool useAllSyscalls = selectedSyscalls.isEmpty();
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    QString syscallPrefix = (syscallMode == "Nt") ? "Sys" : "SysK";
    bool inlineAssemblyMode = settings.value("general/inline_assembly", false).toBool();
    bool indirectAssemblyMode = settings.value("general/indirect_assembly", false).toBool();
    if (inlineAssemblyMode && syscallMode == "Nt") {
        syscallPrefix = "SysInline";
        outputProgress(Colors::OKBLUE() + "Using SysInline prefix" + Colors::ENDC());
    } else if (indirectAssemblyMode && syscallMode == "Nt") {
        syscallPrefix = "SysIndirect";
        outputProgress(Colors::OKBLUE() + "Using SysIndirect prefix" + Colors::ENDC());
    }
    QMap<QString, SyscallInfo> scStubs;
    QString currentStub;
    int startIndex = -1;
    for (int i = 0; i < lines.size(); ++i) {
        QString line = lines[i];
        QRegularExpression procMatch(R"(SC(\w+)\s+PROC)");
        QRegularExpressionMatch match = procMatch.match(line);
        if (match.hasMatch()) {
            if (!currentStub.isEmpty()) {
                scStubs[currentStub].end = i - 1;
            }
            QString baseName = match.captured(1);
            currentStub = "SC" + baseName;
            scStubs[currentStub].start = i;
            scStubs[currentStub].end = -1;
        } else if (!currentStub.isEmpty() && line.contains("ENDP")) {
            scStubs[currentStub].end = i;
            currentStub.clear();
        }
    }
    if (!currentStub.isEmpty()) {
        scStubs[currentStub].end = lines.size() - 1;
    }
    // extract content for each SC stub
    for (auto it = scStubs.begin(); it != scStubs.end(); ++it) {
        int start = it.value().start;
        int end = it.value().end;
        if (start >= 0 && end >= start && end < lines.size()) {
            for (int i = start; i <= end; ++i) {
                it.value().content.append(lines[i]);
            }
        }
    }
    qDebug() << "Found" << scStubs.size() << "SC Stubs in ASM File";
    if (scStubs.size() > 0) {
        qDebug() << "SC Stubs Found:";
        int count = 0;
        for (auto it = scStubs.begin(); it != scStubs.end() && count < 3; ++it, ++count) {
            qDebug() << "  " << it.key() << "(" << it.value().content.size() << " lines)";
        }
    }
    if (inlineAssemblyMode && syscallMode == "Zw") {
        outputProgress(Colors::WARNING() + "Inline assembly mode is not supported in kernel mode, disabling." + Colors::ENDC());
        inlineAssemblyMode = false;
    }
    QStringList newLines;
    int skipUntil = -1;
    for (int i = 0; i < lines.size(); ++i) {
        if (i <= skipUntil) {
            continue;
        }
        QString line = lines[i];
        QRegularExpression procMatch(R"(SC(\w+)\s+PROC)");
        QRegularExpressionMatch match = procMatch.match(line);
        if (match.hasMatch()) {
            QString originalName = match.captured(0);
            QString baseName = match.captured(1);
            QString originalFuncName = "SC" + baseName;
            QString syscallName = syscallPrefix + baseName;
            QString checkName = syscallName;
            if (inlineAssemblyMode && syscallName.startsWith("SysInline")) {
            // convert back to Sys prefix for checking against selectedSyscalls
                checkName = "Sys" + syscallName.mid(9);
            } else if (indirectAssemblyMode && syscallName.startsWith("SysIndirect")) {
            // convert back to Sys prefix for checking against selectedSyscalls
                checkName = "Sys" + syscallName.mid(11);
            }
            if (!useAllSyscalls && !selectedSyscalls.contains(checkName)) {
                outputProgress(Colors::WARNING() + QString("Skipping %1 (not selected in Settings)").arg(syscallName) + Colors::ENDC());
                if (scStubs.contains(originalFuncName)) {
                    skipUntil = scStubs[originalFuncName].end;
                }
                continue;
            }
            bool foundInAny = false;
            for (auto tableIt = syscallTables.begin(); tableIt != syscallTables.end(); ++tableIt) {
                int tableIdx = tableIt.key();
                const QMap<QString, int>& syscallNumbers = tableIt.value();
                QString expectedDllName, expectedAltName;
                if (syscallMode == "Nt") {
                    expectedDllName = "Nt" + baseName;
                    expectedAltName = "Zw" + baseName;
                } else {
                    expectedDllName = "Zw" + baseName;
                    expectedAltName = "Nt" + baseName;
                }
                int syscallId = -1;
                if (syscallNumbers.contains(expectedDllName)) {
                    syscallId = syscallNumbers[expectedDllName];
                } else if (syscallNumbers.contains(expectedAltName)) {
                    syscallId = syscallNumbers[expectedAltName];
                }
                if (syscallId != -1) {
                    foundInAny = true;
                    QString versionSuffix = (tableIdx == 0) ? "" : QString(QChar('A' + tableIdx - 1));
                    QString versionedSyscallName = syscallPrefix + baseName + versionSuffix;
                    if (inlineAssemblyMode) {
                        QString inlineStub = InlineAssemblyConverter::convertStubToInline(versionedSyscallName, syscallId);
                        newLines.append(inlineStub);
                        newLines.append("");
                    } else if (indirectAssemblyMode) {
                        QString indirectStub = generateIndirectStub(versionedSyscallName, syscallId);
                        newLines.append(indirectStub);
                        newLines.append("");
                    } else {
                        QString procLine = QString("%1 PROC").arg(versionedSyscallName);
                        newLines.append(procLine);
                        if (scStubs.contains(originalFuncName)) {
                            QStringList content = scStubs[originalFuncName].content;
                            for (int j = 1; j < content.size() - 1; ++j) {
                                QString contentLine = content[j];
                                if (contentLine.contains("<syscall_id>")) {
                                    contentLine = contentLine.replace("<syscall_id>", QString("0%1").arg(syscallId, 0, 16).toUpper());
                                }
                                QRegularExpression scRegex(R"(\bSC(\w+)\b)");
                                contentLine.replace(scRegex, syscallPrefix + "\\1" + versionSuffix);
                                newLines.append(contentLine);
                            }
                            QString endpLine = content.last().replace(originalFuncName, versionedSyscallName);
                            newLines.append(endpLine);
                            newLines.append("");
                        }
                    }
                }
            }
            if (!foundInAny) {
                outputProgress(Colors::FAIL() + QString("Removing %1 (not found in any ntdll.dll)").arg(syscallName) + Colors::ENDC());
            }
            if (scStubs.contains(originalFuncName)) {
                skipUntil = scStubs[originalFuncName].end;
            }
        } else {
            newLines.append(line);
        }
    }
    QStringList cleanedLines;
    bool prevEmpty = false;
    for (const QString& line : newLines) {
        if (line.trimmed().isEmpty()) {
            if (!prevEmpty) {
                cleanedLines.append(line);
                prevEmpty = true;
            }
        } else {
            cleanedLines.append(line);
            prevEmpty = false;
        }
    }
    if (!cleanedLines.isEmpty() && !cleanedLines.first().contains(".code")) {
        cleanedLines.insert(0, ".code");
        cleanedLines.insert(1, "");
    }
    if (indirectAssemblyMode && syscallMode == "Nt") {
        cleanedLines.insert(0, "extern GetSyscallNumber:PROC");
        cleanedLines.insert(1, "");
    }
    if (!cleanedLines.isEmpty() && !cleanedLines.last().contains("end", Qt::CaseInsensitive)) {
        cleanedLines.append("");
        cleanedLines.append("end");
    }
    QFile outFile(asmFile);
    if (outFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream outStream(&outFile);
        for (const QString& line : cleanedLines) {
            outStream << line << "\n";
        }
        outFile.close();
        qDebug() << "Successfully wrote ASM File with updated Stubs";
    } else {
        qDebug() << "Failed to open ASM File for writing:" << asmFile;
    }
    updateHeaderFile(syscallTables, selectedSyscalls, useAllSyscalls);
    outputProgress(Colors::OKGREEN() + QString("Updated Syscalls Written to %1").arg(asmFile) + Colors::ENDC());
}

void Validator::updateHeaderFile(const QMap<int, QMap<QString, int>>& syscallTables, const QStringList& selectedSyscalls, bool useAllSyscalls) {
    QSettings settings(getIniPath(), QSettings::IniFormat);
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    bool isKernelMode = (syscallMode == "Zw");
    QString headerFilePath = getHeaderFilePath(isKernelMode);
    
    QFile file(headerFilePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return;
    }
    QStringList lines;
    QTextStream stream(&file);
    while (!stream.atEnd()) {
        lines.append(stream.readLine());
    }
    file.close();
    QStringList updatedLines;
    bool headerPartEnded = false;
    QStringList endingLines;
    QString syscallPrefix = (syscallMode == "Nt") ? "Sys" : "SysK";
    bool inlineAssemblyMode = settings.value("general/inline_assembly", false).toBool();
    bool indirectAssemblyMode = settings.value("general/indirect_assembly", false).toBool();
    if (inlineAssemblyMode && syscallMode == "Zw") {
        inlineAssemblyMode = false;
    }
    if (inlineAssemblyMode) {
        syscallPrefix = "SysInline";
        outputProgress(Colors::OKBLUE() + "Using SysInline prefix for header file generation" + Colors::ENDC());
    } else if (indirectAssemblyMode && syscallMode == "Nt") {
        syscallPrefix = "SysIndirect";
        outputProgress(Colors::OKBLUE() + "Using SysIndirect prefix for header file generation" + Colors::ENDC());
    }
    for (int i = lines.size() - 1; i >= 0; --i) {
        QString line = lines[i].trimmed();
        if (line == "#endif" || line.startsWith("#endif ")) {
            endingLines.insert(0, lines[i]);
            int j = i - 1;
            while (j >= 0 && (lines[j].trimmed().isEmpty() || lines[j].trimmed().startsWith("//"))) {
                endingLines.insert(0, lines[j]);
                --j;
            }
            break;
        }
    }
    QMap<QString, QStringList> functionDeclarations;
    QString currentFunction;
    QStringList functionContent;
    for (int i = 0; i < lines.size(); ++i) {
        QString line = lines[i];
        bool isEndingLine = false;
        for (const QString& endLine : endingLines) {
            if (line == endLine) {
                isEndingLine = true;
                break;
            }
        }
        if (isEndingLine) continue;
        if (!headerPartEnded) {
            QRegularExpression funcDeclRegex(R"((?:extern\s+"C"\s+)?(?:NTSTATUS|ULONG|BOOLEAN|VOID)\s+((?:SC|Sys|SysK|SysInline|SysIndirect)\w+)\()");
            if (funcDeclRegex.match(line).hasMatch()) {
                headerPartEnded = true;
            }
        }
        if (!headerPartEnded) {
            if (line.contains("_WIN64") && line.contains("#ifdef")) {
                updatedLines.append(line);
                updatedLines.append("");
                continue;
            }
            if (line.trimmed() == "extern \"C\" {") {
                updatedLines.append(line);
                updatedLines.append("");
                continue;
            }
            updatedLines.append(line);
            continue;
        }
        QRegularExpression funcDeclRegex(R"((?:extern\s+"C"\s+)?(?:NTSTATUS|ULONG|BOOLEAN|VOID)\s+((?:SC|Sys|SysK|SysInline|SysIndirect)\w+)\()");
        QRegularExpressionMatch match = funcDeclRegex.match(line);
        if (match.hasMatch()) {
            if (!currentFunction.isEmpty() && !functionContent.isEmpty()) {
                functionDeclarations[currentFunction] = functionContent;
                functionContent.clear();
            }
            QString originalName = match.captured(1);
            QString syscallName;
            if (originalName.startsWith("SC")) {
                QString baseName = originalName.mid(2);
                syscallName = syscallPrefix + baseName;
            } else if (originalName.startsWith("SysInline")) {
                if (syscallPrefix == "SysInline") {
                    QString baseName = originalName.mid(9);
                    syscallName = originalName;
                } else {
                    QString baseName = originalName.mid(9);
                    syscallName = syscallPrefix + baseName;
                }
            } else if (originalName.startsWith("Sys")) {
                if (syscallPrefix == "Sys") {
                    QString baseName = originalName.mid(3);
                    syscallName = originalName;
                } else {
                    QString baseName = originalName.mid(3);
                    syscallName = syscallPrefix + baseName;
                }
            } else if (originalName.startsWith("SysK")) {
                if (syscallPrefix == "SysK") {
                    QString baseName = originalName.mid(4);
                    syscallName = originalName;
                } else {
                    QString baseName = originalName.mid(4);
                    syscallName = syscallPrefix + baseName;
                }
            } else if (originalName.startsWith("SysIndirect")) {
                if (syscallPrefix == "SysIndirect") {
                    QString baseName = originalName.mid(11);
                    syscallName = originalName;
                } else {
                    QString baseName = originalName.mid(11);
                    syscallName = syscallPrefix + baseName;
                }
            }
            QString checkName = syscallName;
            if (inlineAssemblyMode && syscallName.startsWith("SysInline")) {
                // convert back to Sys prefix for checking against selectedSyscalls
                checkName = "Sys" + syscallName.mid(9);
            } else if (indirectAssemblyMode && syscallName.startsWith("SysIndirect")) {
                // convert back to Sys prefix for checking against selectedSyscalls
                checkName = "Sys" + syscallName.mid(11);
            }
            if (useAllSyscalls || selectedSyscalls.contains(checkName)) {
                currentFunction = syscallName;
                QString modifiedLine = line;
                modifiedLine.replace(QRegularExpression(QString(R"(\b%1\b)").arg(QRegularExpression::escape(originalName))), syscallName);
                functionContent.append(modifiedLine);
            } else {
                currentFunction.clear();
            }
        } else if (!currentFunction.isEmpty()) {
            if (line.contains("SC")) {
                QString modifiedLine = line;
                QRegularExpression scRegex(R"(\bSC(\w+)\b)");
                QRegularExpressionMatchIterator it = scRegex.globalMatch(line);
                while (it.hasNext()) {
                    QRegularExpressionMatch scMatch = it.next();
                    QString scName = scMatch.captured(0);
                    QString baseName = scMatch.captured(1);
                    QString sysName = syscallPrefix + baseName;
                    modifiedLine.replace(scName, sysName);
                }
                functionContent.append(modifiedLine);
            } else {
                functionContent.append(line);
            }
            if (line.trimmed() == ");") {
                functionDeclarations[currentFunction] = functionContent;
                functionContent.clear();
                currentFunction.clear();
            }
        }
    }
    if (!currentFunction.isEmpty() && !functionContent.isEmpty()) {
        functionDeclarations[currentFunction] = functionContent;
    }
    qDebug() << "Function declarations found:" << functionDeclarations.size();
    for (auto it = functionDeclarations.begin(); it != functionDeclarations.end(); ++it) {
        qDebug() << "  Function:" << it.key();
    }
    int numTables = syscallTables.size();
    for (auto funcIt = functionDeclarations.begin(); funcIt != functionDeclarations.end(); ++funcIt) {
        QString funcName = funcIt.key();
        QStringList content = funcIt.value();
        QString baseName;
        if (funcName.startsWith(syscallPrefix)) {
            baseName = funcName.mid(syscallPrefix.length());
        } else if (funcName.startsWith("SysInline")) {
            baseName = funcName.mid(9);
        } else if (funcName.startsWith("SysIndirect")) {
            baseName = funcName.mid(11);
        } else {
            baseName = funcName;
        }
        bool foundInAnyTable = false;
        for (auto tableIt = syscallTables.begin(); tableIt != syscallTables.end(); ++tableIt) {
            int tableIdx = tableIt.key();
            QMap<QString, int> syscallNumbers = tableIt.value();
            QString expectedDllName, expectedAltName;
            if (syscallMode == "Nt") {
                expectedDllName = "Nt" + baseName;
                expectedAltName = "Zw" + baseName;
            } else {
                expectedDllName = "Zw" + baseName;
                expectedAltName = "Nt" + baseName;
            }
            int syscallId = -1;
            if (syscallNumbers.contains(expectedDllName)) {
                syscallId = syscallNumbers[expectedDllName];
            } else if (syscallNumbers.contains(expectedAltName)) {
                syscallId = syscallNumbers[expectedAltName];
            }
            if (syscallId != -1) {
                outputProgress(Colors::OKGREEN() + QString("Found %1 in Table %2 with ID %3").arg(expectedDllName).arg(tableIdx).arg(syscallId) + Colors::ENDC());
                foundInAnyTable = true;
                break;
            } else {
                qDebug() << "  Not found:" << expectedDllName << "or" << expectedAltName << "in Table" << tableIdx;
            }
        }
        if (!foundInAnyTable) {
            outputProgress(Colors::FAIL() + QString("Removing %1 from header (not found in any ntdll.dll)").arg(funcName) + Colors::ENDC());
            continue;
        }
        // add non versioned functions for table 0
        if (syscallTables.contains(0)) {
            QMap<QString, int> table0 = syscallTables[0];
            QString expectedDllName, expectedAltName;
            if (syscallMode == "Nt") {
                expectedDllName = "Nt" + baseName;
                expectedAltName = "Zw" + baseName;
            } else {
                expectedDllName = "Zw" + baseName;
                expectedAltName = "Nt" + baseName;
            }
            int syscallId = -1;
            if (table0.contains(expectedDllName)) {
                syscallId = table0[expectedDllName];
            } else if (table0.contains(expectedAltName)) {
                syscallId = table0[expectedAltName];
            }
            if (syscallId != -1) {
                for (const QString& line : content) {
                    updatedLines.append(line);
                }
                updatedLines.append("");
            }
        }
        // add versioned functions for additional tables
        for (int tableIdx = 1; tableIdx < numTables; ++tableIdx) {
            if (!syscallTables.contains(tableIdx)) continue;
            QMap<QString, int> table = syscallTables[tableIdx];
            QString expectedDllName, expectedAltName;
            if (syscallMode == "Nt") {
                expectedDllName = "Nt" + baseName;
                expectedAltName = "Zw" + baseName;
            } else {
                expectedDllName = "Zw" + baseName;
                expectedAltName = "Nt" + baseName;
            }
            int syscallId = -1;
            if (table.contains(expectedDllName)) {
                syscallId = table[expectedDllName];
            } else if (table.contains(expectedAltName)) {
                syscallId = table[expectedAltName];
            }
            if (syscallId != -1) {
                for (const QString& line : content) {
                    QString versionedName = funcName + QString(QChar('A' + tableIdx - 1));
                    QString versionedLine = line;
                    versionedLine.replace(QRegularExpression(QString(R"(\b%1\b)").arg(QRegularExpression::escape(funcName))), versionedName);
                    updatedLines.append(versionedLine);
                }
                updatedLines.append("");
            }
        }
    }
    if (!updatedLines.isEmpty() && !updatedLines.last().trimmed().isEmpty()) {
        updatedLines.append("");
    }
    bool hasExternClose = false;
    int searchWindow = qMin(50, updatedLines.size());
    QString tail;
    for (int i = qMax(0, updatedLines.size() - searchWindow); i < updatedLines.size(); ++i) {
        tail += updatedLines[i];
    }
    QRegularExpression externCloseRegex(R"(#ifdef\s+__cplusplus[\s\S]*?\}\s*\n\s*#endif)");
    if (!externCloseRegex.match(tail).hasMatch()) {
        updatedLines.append("");
        updatedLines.append("#ifdef __cplusplus");
        updatedLines.append("}");
        updatedLines.append("#endif");
        updatedLines.append("");
    }
    int externOpenIdx = -1;
    for (int i = 0; i < updatedLines.size(); ++i) {
        if (updatedLines[i].trimmed().startsWith("extern \"C\" {")) {
            externOpenIdx = i;
            break;
        }
    }
    if (externOpenIdx != -1) {
        bool foundClose = false;
        for (int lookAhead = 1; lookAhead <= 5; ++lookAhead) {
            if (externOpenIdx + lookAhead < updatedLines.size()) {
                if (updatedLines[externOpenIdx + lookAhead].trimmed().startsWith("#endif")) {
                    foundClose = true;
                    break;
                }
            }
        }
        if (!foundClose) {
            updatedLines.insert(externOpenIdx + 1, "#endif");
        }
    }
    bool nonEmptyEndingFound = false;
    QStringList filteredEndingLines;
    for (const QString& line : endingLines) {
        if (!line.trimmed().isEmpty() || nonEmptyEndingFound) {
            filteredEndingLines.append(line);
            nonEmptyEndingFound = true;
        }
    }
    updatedLines.append(filteredEndingLines);
    QStringList cleanedLines;
    bool prevEmpty = false;
    for (const QString& line : updatedLines) {
        if (line.trimmed().isEmpty()) {
            if (!prevEmpty) {
                cleanedLines.append(line);
                prevEmpty = true;
            }
        } else {
            cleanedLines.append(line);
            prevEmpty = false;
        }
    }
    while (!cleanedLines.isEmpty() && cleanedLines.last().trimmed().isEmpty()) {
        cleanedLines.removeLast();
    }
    cleanedLines.append("");
    updatedLines = cleanedLines;
    QFile outFile(headerFilePath);
    if (outFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream outStream(&outFile);
        for (const QString& line : updatedLines) {
            outStream << line << "\n";
        }
        outFile.close();
    }
    outputProgress(Colors::OKGREEN() + "Updated Header File with Versioned Syscall Declarations" + Colors::ENDC());
}

void Validator::updateDefFile(const QStringList& syscallNames, const QString& defPath) {
    QFile file(defPath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        stream << "LIBRARY SysCaller\n";
        stream << "EXPORTS\n";
        for (const QString& name : syscallNames) {
            stream << "    " << name << "\n";
        }
        file.close();
    }
}

QString Validator::getIniPath() {
    return PathUtils::getIniPath();
}

QString Validator::getHeaderFilePath(bool isKernelMode) {
    return PathUtils::getSysFunctionsPath(isKernelMode);
}

QString Validator::getAsmFilePath(bool isKernelMode) {
    return PathUtils::getSysCallerAsmPath(isKernelMode);
}

QString Validator::getDefFilePath() {
    return PathUtils::getProjectRoot() + "/SysCaller/Wrapper/SysCaller.def";
}

QString Validator::generateIndirectStub(const QString& stubName, int syscallId) {
    QString baseName = stubName.mid(11);
    QString ntName = "Nt" + baseName;
    QString indirectStub = QString("%1 PROC\n"
                                   "    ; Save non volatile registers\n"
                                   "    push rbx\n"
                                   "    push rsi\n"
                                   "    push rdi\n"
                                   "    push r12\n"
                                   "    push r13\n"
                                   "    push r14\n"
                                   "    push r15\n"
                                   "\n"
                                   "    ; Save original parameters\n"
                                   "    mov rbx, rcx\n"
                                   "    mov rsi, rdx\n"
                                   "    mov rdi, r8\n"
                                   "    mov r12, r9\n"
                                   "\n"
                                   "    ; Call C++ resolver to get syscall number\n"
                                   "    lea rcx, [%2_str]\n"
                                   "    sub rsp, 32\n"
                                   "    call GetSyscallNumber\n"
                                   "    add rsp, 32\n"
                                   "\n"
                                   "    ; Remove this later\n"
                                   "\n"
                                   "    ; Restore original parameters\n"
                                   "    mov rcx, rbx\n"
                                   "    mov rdx, rsi\n"
                                   "    mov r8, rdi\n"
                                   "    mov r9, r12\n"
                                   "\n"
                                   "    ; Restore non volatile registers\n"
                                   "    pop r15\n"
                                   "    pop r14\n"
                                   "    pop r13\n"
                                   "    pop r12\n"
                                   "    pop rdi\n"
                                   "    pop rsi\n"
                                   "    pop rbx\n"
                                   "\n"
                                   "    ; Execute syscall\n"
                                   "    mov r10, rcx\n"
                                   "    syscall\n"
                                   "    ret\n"
                                   "%1 ENDP\n"
                                   "\n"
                                   "%2_str db \"%2\", 0")
                                   .arg(stubName)
                                   .arg(ntName);
    return indirectStub;
}
