#include "include/Core/Obfuscation/Obfuscation.h"
#include "include/Core/Obfuscation/Stub/JunkGenerator.h"
#include "include/Core/Obfuscation/Stub/NameGenerator.h"
#include "include/Core/Obfuscation/Encryption/Encryptor.h"
#include "include/Core/Obfuscation/Stub/StubGenerator.h"
#include "include/Core/Obfuscation/Mapping/StubMapper.h"
#include "include/Core/Utils/PathUtils.h"
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QDebug>
#include <QRandomGenerator>
#include <QDir>

Obfuscation::Obfuscation() : outputCallback(nullptr), settings(nullptr) {
    settings = new QSettings(PathUtils::getIniPath(), QSettings::IniFormat);
}

void Obfuscation::setOutputCallback(std::function<void(const QString&)> callback) {
    outputCallback = callback;
}

void Obfuscation::logMessage(const QString& message) {
    if (outputCallback) {
        outputCallback(message);
    }
    qDebug() << "Obfuscation:" << message;
}

int Obfuscation::extractSyscallOffset(const QString& line) {
    QRegularExpression regex(R"(mov eax,\s*([0-9A-Fa-f]+)h)");
    QRegularExpressionMatch match = regex.match(line);
    if (match.hasMatch()) {
        QString offsetStr = match.captured(1);
        bool ok;
        int offset = offsetStr.toInt(&ok, 16);
        if (ok) {
            return offset;
        }
    }
    return -1;
}

QString Obfuscation::getAsmFilePath(bool isKernelMode) {
    if (isKernelMode) {
        return PathUtils::getSysCallerKPath() + "/Wrapper/src/syscaller.asm";
    } else {
        return PathUtils::getSysCallerPath() + "/Wrapper/src/syscaller.asm";
    }
}

QString Obfuscation::getHeaderFilePath(bool isKernelMode) {
    if (isKernelMode) {
        return PathUtils::getSysCallerKPath() + "/Wrapper/include/SysK/sysFunctions_k.h";
    } else {
        return PathUtils::getSysCallerPath() + "/Wrapper/include/Sys/sysFunctions.h";
    }
}

QString Obfuscation::getDefFilePath(bool isKernelMode) {
    if (isKernelMode) {
        return PathUtils::getSysCallerKPath() + "/Wrapper/SysCallerK.def";
    } else {
        return PathUtils::getSysCallerPath() + "/Wrapper/SysCaller.def";
    }
}

bool Obfuscation::isKernelMode() {
    return settings->value("general/syscall_mode", "Nt").toString() == "Zw";
}

QString Obfuscation::getSyscallPrefix() {
    return isKernelMode() ? "SysK" : "Sys";
}

int Obfuscation::run(const QStringList& dllPaths) {
    try {
        QMap<QString, QVariant> syscallSettings = settings->value("stub_mapper/syscall_settings", QMap<QString, QVariant>()).toMap();
        bool forceNormal = settings->value("obfuscation/force_normal", false).toBool();
        bool forceStubMapper = settings->value("obfuscation/force_stub_mapper", false).toBool();
        if (forceStubMapper || (syscallSettings.size() > 0 && !forceNormal)) {
                    logMessage(Colors::OKBLUE() + "Using Stub Mapper..." + Colors::ENDC());
        StubMapper stubMapper(settings);
        stubMapper.setOutputCallback(outputCallback);
        bool success = stubMapper.generateCustomExports();
        if (success) {
            logMessage(Colors::OKGREEN() + "Stub Mapper Obfuscation Completed!" + Colors::ENDC());
            return 0;
        } else {
            logMessage(Colors::FAIL() + "Stub Mapper Obfuscation Failed!" + Colors::ENDC());
            return 1;
        }
    } else {
        logMessage(Colors::OKBLUE() + "Using Normal Obfuscation..." + Colors::ENDC());
        bool success = generateExports();
        if (success) {
            logMessage(Colors::OKGREEN() + "Normal Obfuscation Completed!" + Colors::ENDC());
            return 0;
        } else {
            logMessage(Colors::FAIL() + "Normal Obfuscation Failed!" + Colors::ENDC());
            return 1;
        }
        }
    } catch (const std::exception& e) {
        logMessage(Colors::FAIL() + QString("Obfuscation Error: %1").arg(e.what()) + Colors::ENDC());
        return 1;
    }
}

bool Obfuscation::generateExports() {
    qDebug() << "Generating Obfuscated Exports...";
    bool isKernel = isKernelMode();
    QString asmPath = getAsmFilePath(isKernel);
    QString headerPath = getHeaderFilePath(isKernel);
    qDebug() << QString("Processing Assembly File: %1").arg(asmPath);
    qDebug() << QString("Processing Header File: %1").arg(headerPath);
    return processAssemblyFile(asmPath, headerPath);
}

bool Obfuscation::processAssemblyFile(const QString& asmPath, const QString& headerPath) {
    QFile asmFile(asmPath);
    if (!asmFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        logMessage(Colors::FAIL() + QString("Failed to open Assembly File: %1").arg(asmPath) + Colors::ENDC());
        return false;
    }
    QTextStream in(&asmFile);
    QStringList content = in.readAll().split('\n');
    asmFile.close();
    QStringList selectedSyscalls = settings->value("integrity/selected_syscalls", QStringList()).toStringList();
    bool useAllSyscalls = selectedSyscalls.isEmpty();
    QString syscallPrefix = getSyscallPrefix();
    QSet<QString> usedNames;
    QSet<int> usedOffsets;
    QSet<QString> usedOffsetNames;
    QMap<int, QString> offsetNameMap;      // maps fake offset to random name
    QMap<QString, QString> syscallMap;     // maps original syscall to random name
    QMap<QString, int> syscallOffsets;     // maps original syscall to its offset
    QMap<int, int> realToFakeOffset;       // maps real offset to fake offset
    QList<QPair<QString, QStringList>> syscallStubs;
    QStringList currentStub;
    QString currentSyscall;
    bool inStub = false;
    for (const QString& line : content) {
        QRegularExpression procRegex(R"((SC\w+|Sys\w+|SysK\w+)\s+PROC)");
        QRegularExpressionMatch procMatch = procRegex.match(line);
        if (procMatch.hasMatch()) {
            currentSyscall = procMatch.captured(1);
            if (currentSyscall.startsWith("SC")) {
                currentSyscall = syscallPrefix + currentSyscall.mid(2);
            }
            inStub = true;
            currentStub.clear();
            currentStub << line;
            if (useAllSyscalls || selectedSyscalls.contains(currentSyscall)) {
                if (!syscallMap.contains(currentSyscall)) {
                    NameGenerator nameGen(settings);
                    syscallMap[currentSyscall] = nameGen.generateRandomName(usedNames);
                }
            }
        } else if (inStub) {
            currentStub << line;
            if (line.contains("mov eax,") && !currentSyscall.isEmpty()) {
                int realOffset = extractSyscallOffset(line);
                if (realOffset != -1) {
                    syscallOffsets[currentSyscall] = realOffset;
                    if (!realToFakeOffset.contains(realOffset)) {
                        NameGenerator nameGen(settings);
                        realToFakeOffset[realOffset] = nameGen.generateRandomOffset(usedOffsets);
                    }
                }
            } else if (line.contains(" ENDP")) {
                inStub = false;
                if (useAllSyscalls || selectedSyscalls.contains(currentSyscall)) {
                    syscallStubs.append(qMakePair(currentSyscall, currentStub));
                }
            }
        }
    }
    bool shuffleSequence = settings->value("obfuscation/shuffle_sequence", true).toBool();
    if (shuffleSequence) {
        for (int i = syscallStubs.size() - 1; i > 0; --i) {
            int j = QRandomGenerator::global()->bounded(0, i + 1);
            syscallStubs.swapItemsAt(i, j);
        }
        logMessage(Colors::OKGREEN() + "Syscall Sequence has been Randomized" + Colors::ENDC());
    }
    QStringList publics;
    QStringList aliases;
    for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it) {
        publics << QString("PUBLIC %1").arg(it.value());
        aliases << QString("ALIAS <%1> = <%2>").arg(it.key()).arg(it.value());
    }
    QStringList newContent;
    newContent << ".data";
    newContent << "ALIGN 8";
    bool enableEncryption = settings->value("obfuscation/enable_encryption", true).toBool();
    int encryptionMethod = settings->value("obfuscation/encryption_method", 1).toInt();
    QMap<QString, QMap<QString, QVariant>> encryptionDataMap;
    Encryptor encryptor(settings);
    NameGenerator nameGen(settings);
    for (auto it = realToFakeOffset.begin(); it != realToFakeOffset.end(); ++it) {
        int realOffset = it.key();
        int fakeOffset = it.value();
        QString offsetName = nameGen.generateRandomOffsetName(usedOffsetNames);
        offsetNameMap[fakeOffset] = offsetName;
        if (enableEncryption) {
            auto encryptionResult = encryptor.encryptOffset(realOffset, encryptionMethod);
            int encryptedOffset = encryptionResult.first;
            encryptionDataMap[offsetName] = encryptionResult.second;
            newContent << QString("%1 dd 0%2h  ; Encrypted Syscall ID (Method %3)")
                           .arg(offsetName).arg(encryptedOffset, 0, 16).arg(encryptionMethod);
        } else {
            newContent << QString("%1 dd 0%2h").arg(offsetName).arg(realOffset, 0, 16);
        }
    }
    newContent << ".code";
    newContent << "";
    newContent << "; Public Declarations";
    for (const QString& pub : publics) {
        newContent << pub;
    }
    newContent << "";
    newContent << "; Export Aliases";
    for (const QString& alias : aliases) {
        newContent << alias;
    }
    newContent << "";
    bool enableInterleaved = settings->value("obfuscation/enable_interleaved", true).toBool();
    StubGenerator stubGen(settings);
    for (const auto& stubPair : syscallStubs) {
        QString originalSyscall = stubPair.first;
        QStringList stubLines = stubPair.second;
        bool skipRest = false;  // flag to skip lines after mov eax
        if (enableInterleaved) {
            newContent << stubGen.generateAlignPadding();
        }
        for (const QString& originalLine : stubLines) {
            if (skipRest) {
                // only process ENDP line when skipping
                if (originalLine.contains(" ENDP")) {
                    QString line = originalLine;
                    QRegularExpression syscallRegex(R"((SC\w+|Sys\w+|SysK\w+)\s+ENDP)");
                    QRegularExpressionMatch match = syscallRegex.match(line);
                    if (match.hasMatch()) {
                        QString syscall = match.captured(1);
                        if (syscall.startsWith("SC")) {
                            syscall = syscallPrefix + syscall.mid(2);
                        }
                        if (syscallMap.contains(syscall)) {
                            line = line.replace(match.captured(1), syscallMap.value(syscall));
                        }
                    }
                    newContent << line;
                    skipRest = false; // reset the flag after processing ENDP
                }
                continue;
            }
            QString line = originalLine;
            if (line.contains(" PROC") || line.contains(" ENDP")) {
                QRegularExpression syscallRegex(R"((SC\w+|Sys\w+|SysK\w+)\s+(PROC|ENDP))");
                QRegularExpressionMatch match = syscallRegex.match(line);
                if (match.hasMatch()) {
                    QString syscall = match.captured(1);
                    if (syscall.startsWith("SC")) {
                        syscall = syscallPrefix + syscall.mid(2);
                    }
                    if (syscallMap.contains(syscall)) {
                        line = line.replace(match.captured(1), syscallMap.value(syscall));
                    }
                }
            } else if (line.contains("mov eax,") && stubLines.join("").contains("syscall")) {
                if (syscallOffsets.contains(originalSyscall)) {
                    int realOffset = syscallOffsets.value(originalSyscall);
                    if (realToFakeOffset.contains(realOffset)) {
                        int fakeOffset = realToFakeOffset.value(realOffset);
                        QString offsetName = offsetNameMap.value(fakeOffset);
                        QMap<QString, QVariant> encryptionData = encryptionDataMap.value(offsetName);
                        line = stubGen.generateChunkedSequence(offsetName, encryptionData, encryptionMethod);
                        newContent << line;
                        skipRest = true;  // skip original syscall/ret
                        continue;
                    }
                }
            }
            newContent << line;
        }
        if (enableInterleaved) {
            newContent << stubGen.generateAlignPadding();
        }
    }
    newContent << "\nend\n";
    QFile outAsmFile(asmPath);
    if (!outAsmFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        logMessage(Colors::FAIL() + QString("Failed to write Assembly File: %1").arg(asmPath) + Colors::ENDC());
        return false;
    }
    QStringList cleanedContent;
    bool prevEmpty = false;
    QString prevLine;
    bool foundSyscallRet = false;
    QSet<QString> seenEndps;
    for (int i = 0; i < newContent.size(); i++) {
        QString line = newContent[i];
        if (line.contains("ENDP")) {
            QString endpName = line.trimmed();
            if (seenEndps.contains(endpName)) {
                continue;
            }
            seenEndps.insert(endpName);
        }
        if (line.trimmed() == "syscall") {
            int nextIdx = i + 1;
            while (nextIdx < newContent.size() && newContent[nextIdx].trimmed().isEmpty()) {
                nextIdx++;
            }
            if (nextIdx < newContent.size() && newContent[nextIdx].trimmed() == "ret") {
                if (foundSyscallRet) {
                    i = nextIdx;
                    continue;
                } else {
                    cleanedContent << line;
                    cleanedContent << newContent[nextIdx];
                    foundSyscallRet = true;
                    i = nextIdx;
                    continue;
                }
            }
        }
        if (line.contains("PROC") || line.contains("ENDP")) {
            foundSyscallRet = false;
        }
        if (line.trimmed() == "ret") {
            cleanedContent << line;
            int j = i + 1;
            while (j < newContent.size() && newContent[j].trimmed().isEmpty()) {
                j++;
            }
            if (j < newContent.size() && newContent[j].contains("ENDP")) {
                i = j - 1;
                prevEmpty = false;
                continue;
            }
        }
        if (line.contains("ENDP")) {
            cleanedContent << line;
            int j = i + 1;
            while (j < newContent.size() && newContent[j].trimmed().isEmpty()) {
                j++;
            }
            if (j < newContent.size() && newContent[j].contains("PROC")) {
                cleanedContent << "";
                i = j - 1;
            }
            prevEmpty = false;
            continue;
        }
        if (line.trimmed() == "syscall") {
            int j = i + 1;
            bool blankFound = false;
            while (j < newContent.size() && newContent[j].trimmed().isEmpty()) {
                blankFound = true;
                j++;
            }
            if (j < newContent.size() && newContent[j].trimmed() == "ret") {
                cleanedContent << line;
                cleanedContent << newContent[j];
                i = j;
                continue;
            }
        }
        if (line.trimmed().isEmpty()) {
            if (!prevEmpty) {
                cleanedContent << line;
                prevEmpty = true;
            }
        } else {
            cleanedContent << line;
            prevEmpty = false;
        }
        prevLine = line;
    }
    QTextStream out(&outAsmFile);
    out << cleanedContent.join("\n");
    outAsmFile.close();
    if (!updateHeaderFile(headerPath, syscallMap)) {
        logMessage(Colors::FAIL() + "Failed to update Header File" + Colors::ENDC());
        return false;
    }
    bool bindingsEnabled = settings->value("general/bindings_enabled", false).toBool();
    if (bindingsEnabled && !isKernelMode()) {
        QString defPath = getDefFilePath(isKernelMode());
        QStringList obfuscatedNames;
        QRegularExpression procRegex(R"(\s*([A-Za-z0-9_]+)\s+PROC)");
        for (const QString& line : newContent) {
            QRegularExpressionMatch match = procRegex.match(line);
            if (match.hasMatch()) {
                obfuscatedNames << match.captured(1);
            }
        }
        if (!updateDefFile(defPath, obfuscatedNames)) {
            logMessage(Colors::FAIL() + "Failed to update DEF File" + Colors::ENDC());
            return false;
        }
    }
    logMessage(Colors::OKGREEN() + QString("Generated %1 unique Syscalls with Obfuscated Names, Offsets, and Junk Instructions")
               .arg(syscallMap.size()) + Colors::ENDC());
    return true;
}

bool Obfuscation::updateHeaderFile(const QString& headerPath, const QMap<QString, QString>& syscallMap) {
    QFile headerFile(headerPath);
    if (!headerFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        logMessage(Colors::FAIL() + QString("Failed to open Header File: %1").arg(headerPath) + Colors::ENDC());
        return false;
    }
    QTextStream in(&headerFile);
    QStringList headerContent = in.readAll().split('\n');
    headerFile.close();
    QStringList selectedSyscalls = settings->value("integrity/selected_syscalls", QStringList()).toStringList();
    bool useAllSyscalls = selectedSyscalls.isEmpty();
    QString syscallPrefix = getSyscallPrefix();
    QStringList newHeaderContent;
    bool headerPartEnded = false;
    bool skipBlock = false;
    QString currentSyscall;
    for (const QString& line : headerContent) {
        if (!headerPartEnded && (
            line.contains(QString("NTSTATUS %1").arg(syscallPrefix)) ||
            line.contains(QString("ULONG %1").arg(syscallPrefix)) ||
            line.contains(QString("BOOLEAN %1").arg(syscallPrefix)) ||
            line.contains(QString("VOID %1").arg(syscallPrefix)) ||
            line.contains("NTSTATUS SC") ||
            line.contains("ULONG SC") ||
            line.contains("BOOLEAN SC") ||
            line.contains("VOID SC") ||
            line.contains("#ifdef __cplusplus")
        )) {
            headerPartEnded = true;
        }
        if (!headerPartEnded) {
            if (line.contains("_WIN64") && line.contains("#ifdef")) {
                newHeaderContent << line;
                newHeaderContent << "";
                continue;
            }
            newHeaderContent << line;
            continue;
        }
        // preserve c++ guards and extern blocks
        if (line.contains("#ifdef __cplusplus") || line.contains("extern \"C\"") || 
            line.trimmed() == "{" || line.trimmed() == "}" || line.contains("#endif")) {
            newHeaderContent << line;
            continue;
        }
        if (line.contains("NTSTATUS SC") || line.contains("ULONG SC") ||
            line.contains("BOOLEAN SC") || line.contains("VOID SC") ||
            line.contains(QString("NTSTATUS %1").arg(syscallPrefix)) ||
            line.contains(QString("ULONG %1").arg(syscallPrefix)) ||
            line.contains(QString("BOOLEAN %1").arg(syscallPrefix)) ||
            line.contains(QString("VOID %1").arg(syscallPrefix))) {
            QRegularExpression regex(QString(R"(extern "C" (?:NTSTATUS|ULONG|BOOLEAN|VOID) ((?:SC|%1)\w+)\()").arg(syscallPrefix));
            QRegularExpressionMatch match = regex.match(line);
            if (!match.hasMatch()) {
                regex = QRegularExpression(QString(R"((?:NTSTATUS|ULONG|BOOLEAN|VOID) ((?:SC|%1)\w+)\()").arg(syscallPrefix));
                match = regex.match(line);
            }
            if (match.hasMatch()) {
                QString originalName = match.captured(1);
                if (originalName.startsWith("SC")) {
                    currentSyscall = syscallPrefix + originalName.mid(2);
                } else {
                    currentSyscall = originalName;
                }
                if (useAllSyscalls || selectedSyscalls.contains(currentSyscall)) {
                    skipBlock = false;
                    if (syscallMap.contains(currentSyscall)) {
                        QString newLine = line;
                        newLine = newLine.replace(originalName, syscallMap.value(currentSyscall));
                        newLine = newLine.replace("extern \"C\" ", "");
                        newHeaderContent << newLine;
                    }
                } else {
                    skipBlock = true;
                }
                continue;
            }
        }
        if (!skipBlock) {
            if (line.contains("SC")) {
                QString updatedLine = line;
                QRegularExpression scRegex(R"(\bSC(\w+)\b)");
                updatedLine = updatedLine.replace(scRegex, QString("%1\\1").arg(syscallPrefix));
                newHeaderContent << updatedLine;
            } else {
                newHeaderContent << line;
            }
        } else if (line.trimmed() == ");") {
            skipBlock = false;
        }
    }
    newHeaderContent << "";
    newHeaderContent << "// Syscall Name Mappings";
    for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it) {
        newHeaderContent << QString("#define %1 %2").arg(it.key()).arg(it.value());
    }
    QStringList cleanedHeaderContent;
    bool prevEmpty = false;
    for (const QString& line : newHeaderContent) {
        if (line.trimmed().isEmpty()) {
            if (!prevEmpty) {
                cleanedHeaderContent << line;
                prevEmpty = true;
            }
        } else {
            cleanedHeaderContent << line;
            prevEmpty = false;
        }
    }
    QFile outHeaderFile(headerPath);
    if (!outHeaderFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        logMessage(Colors::FAIL() + QString("Failed to write Header File: %1").arg(headerPath) + Colors::ENDC());
        return false;
    }
    QTextStream out(&outHeaderFile);
    out << cleanedHeaderContent.join("\n");
    outHeaderFile.close();
    return true;
}

bool Obfuscation::updateDefFile(const QString& defPath, const QStringList& obfuscatedNames) {
    QFile defFile(defPath);
    if (!defFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        logMessage(Colors::FAIL() + QString("Failed to write DEF File: %1").arg(defPath) + Colors::ENDC());
        return false;
    }
    QTextStream out(&defFile);
    out << "EXPORTS\n";
    for (const QString& name : obfuscatedNames) {
        out << "    " << name << "\n";
    }
    defFile.close();
    return true;
} 