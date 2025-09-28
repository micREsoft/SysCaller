#include "include/Core/Obfuscation/Direct/Mapping/DirectStubMapper.h"
#include "include/Core/Obfuscation/Direct/Stub/DirectJunkGenerator.h"
#include "include/Core/Obfuscation/Shared/Stub/NameGenerator.h"
#include "include/Core/Obfuscation/Direct/Encryption/DirectEncryptor.h"
#include "include/Core/Obfuscation/Direct/Stub/DirectStubGenerator.h"
#include "include/Core/Obfuscation/Direct/ControlFlow/DirectControlFlow.h"
#include "include/Core/Utils/PathUtils.h"
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QDebug>
#include <QRandomGenerator>
#include <QDir>

DirectObfuscation::StubMapper::StubMapper(QSettings* settings)
    : settings(settings)
    , outputCallback(nullptr)
{}

void DirectObfuscation::StubMapper::setSettings(QSettings* settings)
{
    this->settings = settings;
}

void DirectObfuscation::StubMapper::setOutputCallback(std::function<void(const QString&)> callback)
{
    outputCallback = callback;
}

void DirectObfuscation::StubMapper::logMessage(const QString& message)
{
    if (outputCallback)
    {
        outputCallback(message);
    }

    qDebug() << "StubMapper:" << message;
}

int DirectObfuscation::StubMapper::extractSyscallOffset(const QString& line)
{
    QRegularExpression regex(R"(mov eax,\s*([0-9A-Fa-f]+)h)");
    QRegularExpressionMatch match = regex.match(line);

    if (match.hasMatch())
    {
        QString offsetStr = match.captured(1);
        bool ok;
        int offset = offsetStr.toInt(&ok, 16);

        if (ok)
        {
            return offset;
        }
    }

    return -1;
}

QString DirectObfuscation::StubMapper::getAsmFilePath(bool isKernelMode)
{
    if (isKernelMode)
    {
        return PathUtils::getSysCallerKPath() + "/Wrapper/src/syscaller.asm";
    }
    else
    {
        return PathUtils::getSysCallerPath() + "/Wrapper/src/syscaller.asm";
    }
}

QString DirectObfuscation::StubMapper::getHeaderFilePath(bool isKernelMode)
{
    if (isKernelMode)
    {
        return PathUtils::getSysCallerKPath() + "/Wrapper/include/SysK/sysFunctions_k.h";
    }
    else
    {
        return PathUtils::getSysCallerPath() + "/Wrapper/include/Sys/sysFunctions.h";
    }
}

QString DirectObfuscation::StubMapper::getDefFilePath(bool isKernelMode)
{
    if (isKernelMode)
    {
        return PathUtils::getSysCallerKPath() + "/Wrapper/SysCallerK.def";
    }
    else
    {
        return PathUtils::getSysCallerPath() + "/Wrapper/SysCaller.def";
    }
}

bool DirectObfuscation::StubMapper::isKernelMode()
{
    return settings->value("general/syscall_mode", "Nt").toString() == "Zw";
}

QString DirectObfuscation::StubMapper::getSyscallPrefix()
{
    return isKernelMode() ? "SysK" : "Sys";
}

QPair<int, QString> DirectObfuscation::StubMapper::applyCustomSyscallSettings(
    const QString& syscallName,
    int realOffset,
    const QMap<QString, QVariant>& customSettings)
{
    QMap<QString, QVariant> settings;

    if (customSettings.isEmpty())
    {
        QMap<QString, QVariant> syscallSettings = this->settings->value(
            "stub_mapper/syscall_settings",
            QMap<QString, QVariant>()).toMap();

        if (syscallSettings.contains(syscallName))
        {
            settings = syscallSettings[syscallName].toMap();
        }
        else
        {
            settings["enable_junk"] = true;
            settings["min_instructions"] = this->settings->value("obfuscation/min_instructions", 2).toInt();
            settings["max_instructions"] = this->settings->value("obfuscation/max_instructions", 8).toInt();
            settings["use_advanced_junk"] = this->settings->value("obfuscation/use_advanced_junk", false).toBool();
            settings["enable_encryption"] = this->settings->value("obfuscation/enable_encryption", true).toBool();
            settings["encryption_method"] = static_cast<int>(DirectObfuscation::EncryptionMethod::BasicXOR);
            settings["enable_chunking"] = this->settings->value("obfuscation/enable_chunking", true).toBool();
            settings["enable_interleaved"] = this->settings->value("obfuscation/enable_interleaved", true).toBool();
            settings["shuffle_sequence"] = this->settings->value("obfuscation/shuffle_sequence", true).toBool();
            settings["syscall_prefix_length"] = this->settings->value("obfuscation/syscall_prefix_length", 8).toInt();
            settings["syscall_number_length"] = this->settings->value("obfuscation/syscall_number_length", 6).toInt();
            settings["offset_name_length"] = this->settings->value("obfuscation/offset_name_length", 8).toInt();
            settings["control_flow_enabled"] = this->settings->value("obfuscation/control_flow_enabled", false).toBool();
            settings["control_flow_opaque_predicates"] = this->settings->value("obfuscation/control_flow_opaque_predicates", false).toBool();
            settings["control_flow_bogus_flow"] = this->settings->value("obfuscation/control_flow_bogus_flow", false).toBool();
            settings["control_flow_indirect_jumps"] = this->settings->value("obfuscation/control_flow_indirect_jumps", false).toBool();
            settings["control_flow_conditional_branches"] = this->settings->value("obfuscation/control_flow_conditional_branches", false).toBool();
            settings["control_flow_complexity"] = this->settings->value("obfuscation/control_flow_complexity", 2).toInt();
        }
    }
    else
    {
        settings = customSettings;
    }

    QSet<int> usedOffsets;
    QSet<QString> usedOffsetNames;

    SharedObfuscation::NameGenerator nameGen(this->settings);
    Encryptor encryptor(this->settings);

    int fakeOffset = nameGen.generateRandomOffset(usedOffsets);
    int offsetNameLength = settings.value("offset_name_length", 8).toInt();
    QString offsetName = nameGen.generateRandomOffsetName(usedOffsetNames, offsetNameLength);

    return qMakePair(fakeOffset, offsetName);
}

bool DirectObfuscation::StubMapper::generateCustomExports()
{
    logMessage(Colors::OKBLUE() + "Starting Stub Mapper Custom Export Generation..." + Colors::ENDC());

    try
    {
        bool success = processAssemblyFile(getAsmFilePath(isKernelMode()), getHeaderFilePath(isKernelMode()));

        if (success)
        {
            logMessage(Colors::OKGREEN() + "Stub Mapper Custom Export Generation Completed Successfully!" + Colors::ENDC());
            return true;
        }
        else
        {
            logMessage(Colors::FAIL() + "Stub Mapper Custom Export Generation Failed!" + Colors::ENDC());
            return false;
        }
    }
    catch (const std::exception& e)
    {
        logMessage(Colors::FAIL() + QString("Stub Mapper Error: %1").arg(e.what()) + Colors::ENDC());
        return false;
    }
}

bool DirectObfuscation::StubMapper::processAssemblyFile(const QString& asmPath, const QString& headerPath)
{
    QFile asmFile(asmPath);

    if (!asmFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
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

    QMap<int, QString> offsetNameMap;       /* maps fake offset to random name */
    QMap<QString, QString> syscallMap;      /* maps original syscall to random name */
    QMap<QString, int> syscallOffsets;      /* maps original syscall to its offset */
    QMap<int, int> realToFakeOffset;        /* maps real offset to fake offset */

    QList<QPair<QString, QStringList>> syscallStubs;
    QStringList currentStub;
    QString currentSyscall;
    bool inStub = false;

    QMap<QString, QVariant> syscallSettings = settings->value("stub_mapper/syscall_settings", QMap<QString, QVariant>()).toMap();
    for (const QString& line : content)
    {
        QRegularExpression procRegex(R"((SC\w+|Sys\w+|SysK\w+)\s+PROC)");
        QRegularExpressionMatch procMatch = procRegex.match(line);

        if (procMatch.hasMatch())
        {
            currentSyscall = procMatch.captured(1);

            if (currentSyscall.startsWith("SC"))
            {
                currentSyscall = syscallPrefix + currentSyscall.mid(2);
            }

            inStub = true;
            currentStub.clear();
            currentStub << line;

            if (useAllSyscalls || selectedSyscalls.contains(currentSyscall))
            {
                if (!syscallMap.contains(currentSyscall))
                {
                    SharedObfuscation::NameGenerator nameGen(settings);
                    int prefixLength = 8;
                    int numberLength = 6;

                    if (syscallSettings.contains(currentSyscall))
                    {
                        QMap<QString, QVariant> customSettings = syscallSettings[currentSyscall].toMap();
                        prefixLength = customSettings.value("syscall_prefix_length", 8).toInt();
                        numberLength = customSettings.value("syscall_number_length", 6).toInt();
                    }

                    syscallMap[currentSyscall] = nameGen.generateRandomName(usedNames, prefixLength, numberLength);
                }
            }
        }
        else if (inStub)
        {
            currentStub << line;

            if (line.contains("mov eax,") && !currentSyscall.isEmpty())
            {
                int realOffset = extractSyscallOffset(line);

                if (realOffset != -1)
                {
                    syscallOffsets[currentSyscall] = realOffset;

                    if (syscallSettings.contains(currentSyscall))
                    {
                        QMap<QString, QVariant> customSettings = syscallSettings[currentSyscall].toMap();
                        auto result = applyCustomSyscallSettings(currentSyscall, realOffset, customSettings);

                        int fakeOffset = result.first;
                        QString offsetName = result.second;

                        realToFakeOffset[realOffset] = fakeOffset;
                        offsetNameMap[fakeOffset] = offsetName;
                        usedOffsets.insert(fakeOffset);
                        usedOffsetNames.insert(offsetName);
                    }
                    else if (!realToFakeOffset.contains(realOffset))
                    {
                        SharedObfuscation::NameGenerator nameGen(settings);
                        int fakeOffset = nameGen.generateRandomOffset(usedOffsets);
                        QString offsetName = nameGen.generateRandomOffsetName(usedOffsetNames);

                        realToFakeOffset[realOffset] = fakeOffset;
                        offsetNameMap[fakeOffset] = offsetName;
                    }
                }
            }
            else if (line.contains(" ENDP"))
            {
                inStub = false;

                if (useAllSyscalls || selectedSyscalls.contains(currentSyscall))
                {
                    syscallStubs.append(qMakePair(currentSyscall, currentStub));
                }
            }
        }
    }
    bool globalShuffle = settings->value("obfuscation/shuffle_sequence", true).toBool();
    QList<QPair<QString, QStringList>> syscallsToShuffle;
    QList<QPair<QString, QStringList>> syscallsToKeepOrder;

    for (const auto& stubPair : syscallStubs)
    {
        QString syscall = stubPair.first;

        if (syscallSettings.contains(syscall) && syscallSettings[syscall].toMap().contains("shuffle_sequence"))
        {
            if (syscallSettings[syscall].toMap()["shuffle_sequence"].toBool())
            {
                syscallsToShuffle.append(stubPair);
            }
            else
            {
                syscallsToKeepOrder.append(stubPair);
            }
        }
        else if (globalShuffle)
        {
            syscallsToShuffle.append(stubPair);
        }
        else
        {
            syscallsToKeepOrder.append(stubPair);
        }
    }

    for (int i = syscallsToShuffle.size() - 1; i > 0; --i)
    {
        int j = getRandomInt(0, i);
        syscallsToShuffle.swapItemsAt(i, j);
    }

    syscallStubs = syscallsToShuffle + syscallsToKeepOrder;

    QStringList publics;
    QStringList aliases;
    bool enableControlFlow = settings->value("obfuscation/control_flow_enabled", false).toBool();

    QMap<QString, QString> functionSuffixes; /* store suffixes for each function */

    if (enableControlFlow)
    {
        for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it)
        {
            QString suffix = QString::number(getRandomInt(1000, 999999));
            functionSuffixes[it.key()] = suffix;
        }
    }

    for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it)
    {
        QString obfuscatedName = it.value();

        if (enableControlFlow && functionSuffixes.contains(it.key()))
        {
            obfuscatedName = QString("%1_%2").arg(obfuscatedName).arg(functionSuffixes[it.key()]);
        }

        publics << QString("PUBLIC %1").arg(obfuscatedName);
        aliases << QString("ALIAS <%1> = <%2>").arg(it.key()).arg(obfuscatedName);
    }
    QStringList newContent;
    newContent << ".data";
    newContent << "ALIGN 8";

    QMap<QString, QMap<QString, QVariant>> encryptionDataMap;
    Encryptor encryptor(settings);
    SharedObfuscation::NameGenerator nameGen(settings);

    for (auto it = realToFakeOffset.begin(); it != realToFakeOffset.end(); ++it)
    {
        int realOffset = it.key();
        int fakeOffset = it.value();
        QString offsetName = offsetNameMap[fakeOffset];
        bool enableEncryption = true;
        DirectObfuscation::EncryptionMethod encryptionMethod = DirectObfuscation::EncryptionMethod::BasicXOR;

        for (auto syscallIt = syscallOffsets.begin(); syscallIt != syscallOffsets.end(); ++syscallIt)
        {
            if (syscallIt.value() == realOffset)
            {
                QString syscall = syscallIt.key();

                if (syscallSettings.contains(syscall))
                {
                    QMap<QString, QVariant> customSettings = syscallSettings[syscall].toMap();
                    enableEncryption = customSettings.value("enable_encryption", true).toBool();
                    encryptionMethod = static_cast<DirectObfuscation::EncryptionMethod>(customSettings.value("encryption_method", static_cast<int>(DirectObfuscation::EncryptionMethod::BasicXOR)).toInt());
                }

                break;
            }
        }

        if (enableEncryption)
        {
            auto encryptionResult = encryptor.encryptOffset(realOffset, static_cast<int>(encryptionMethod));
            int encryptedOffset = encryptionResult.first;
            encryptionDataMap[offsetName] = encryptionResult.second;

            newContent << QString("%1 dd 0%2h  ; Encrypted Syscall ID (Method %3)")
                               .arg(offsetName)
                               .arg(encryptedOffset, 0, 16)
                               .arg(static_cast<int>(encryptionMethod));
        }
        else
        {
            newContent << QString("%1 dd 0%2h").arg(offsetName).arg(realOffset, 0, 16);
        }
    }
    newContent << ".code";
    newContent << "";
    newContent << "; Public Declarations";

    for (const QString& pub : publics)
    {
        newContent << pub;
    }

    newContent << "";
    newContent << "; Export Aliases";

    for (const QString& alias : aliases)
    {
        newContent << alias;
    }

    newContent << "";

    StubGenerator stubGen(settings);
    ControlFlow controlFlow(settings);

    for (const auto& stubPair : syscallStubs)
    {
        QString originalSyscall = stubPair.first;
        QStringList stubLines = stubPair.second;
        bool skipRest = false;
        QString functionSuffix; /* store the random suffix for this function */

        if (enableControlFlow && functionSuffixes.contains(originalSyscall))
        {
            functionSuffix = functionSuffixes[originalSyscall];
        }

        if (enableControlFlow)
        {
            QString labelPrefix;

            if (syscallMap.contains(originalSyscall))
            {
                labelPrefix = QString("%1_").arg(syscallMap.value(originalSyscall));
            }
            else
            {
                labelPrefix = QString("%1_").arg(originalSyscall);
            }

            stubLines = controlFlow.wrapWithControlFlow(stubLines, labelPrefix);
        }        
        bool enableInterleaved = true;

        if (syscallSettings.contains(originalSyscall))
        {
            QMap<QString, QVariant> customSettings = syscallSettings[originalSyscall].toMap();
            enableInterleaved = customSettings.value("enable_interleaved", true).toBool();
        }

        if (enableInterleaved)
        {
            newContent << stubGen.generateAlignPadding();
        }

        for (const QString& originalLine : stubLines)
        {
            if (skipRest)
            {
                if (originalLine.contains(" ENDP"))
                {
                    QString line = originalLine;
                    QRegularExpression syscallRegex(R"((SC\w+|Sys\w+|SysK\w+)\s+ENDP)");
                    QRegularExpressionMatch match = syscallRegex.match(line);

                    if (match.hasMatch())
                    {
                        QString syscall = match.captured(1);

                        if (syscall.startsWith("SC"))
                        {
                            syscall = syscallPrefix + syscall.mid(2);
                        }

                        if (syscallMap.contains(syscall))
                        {
                            QString obfuscatedName = syscallMap.value(syscall);

                            if (enableControlFlow && !functionSuffix.isEmpty())
                            {
                                obfuscatedName = QString("%1_%2").arg(obfuscatedName).arg(functionSuffix);
                            }

                            line = line.replace(match.captured(1), obfuscatedName);
                        }
                    }

                    newContent << line;
                    skipRest = false;
                }

                continue;
            }
            QString line = originalLine;

            if (line.contains(" PROC") || line.contains(" ENDP"))
            {
                QRegularExpression syscallRegex(R"((SC\w+|Sys\w+|SysK\w+)\s+(PROC|ENDP))");
                QRegularExpressionMatch match = syscallRegex.match(line);

                if (match.hasMatch())
                {
                    QString syscall = match.captured(1);

                    if (syscall.startsWith("SC"))
                    {
                        syscall = syscallPrefix + syscall.mid(2);
                    }

                    if (syscallMap.contains(syscall))
                    {
                        QString obfuscatedName = syscallMap.value(syscall);

                        if (enableControlFlow && !functionSuffix.isEmpty())
                        {
                            obfuscatedName = QString("%1_%2").arg(obfuscatedName).arg(functionSuffix);
                        }

                        line = line.replace(match.captured(1), obfuscatedName);
                    }
                }
            }
            else if (line.contains("mov eax,") && stubLines.join("").contains("syscall"))
            {
                if (syscallOffsets.contains(originalSyscall))
                {
                    int realOffset = syscallOffsets.value(originalSyscall);

                    if (realToFakeOffset.contains(realOffset))
                    {
                        int fakeOffset = realToFakeOffset.value(realOffset);
                        QString offsetName = offsetNameMap.value(fakeOffset);
                        QMap<QString, QVariant> encryptionData = encryptionDataMap.value(offsetName);
                        bool enableChunking = true;
                        DirectObfuscation::EncryptionMethod encryptionMethod = DirectObfuscation::EncryptionMethod::BasicXOR;

                        if (syscallSettings.contains(originalSyscall))
                        {
                            QMap<QString, QVariant> customSettings = syscallSettings[originalSyscall].toMap();
                            enableChunking = customSettings.value("enable_chunking", true).toBool();
                            encryptionMethod = static_cast<DirectObfuscation::EncryptionMethod>(customSettings.value("encryption_method", static_cast<int>(DirectObfuscation::EncryptionMethod::BasicXOR)).toInt());
                        }

                        if (enableChunking)
                        {
                            line = stubGen.generateChunkedSequence(offsetName, encryptionData, static_cast<int>(encryptionMethod));
                        }
                        else
                        {
                            line = QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
                        }

                        newContent << line;
                        skipRest = true;
                        continue;
                    }
                }
            }
            if (syscallSettings.contains(originalSyscall))
            {
                QMap<QString, QVariant> customSettings = syscallSettings[originalSyscall].toMap();

                if (customSettings.value("enable_junk", false).toBool() &&
                    (line.contains("ret") || line.contains("syscall")))
                {
                    int minInst = customSettings.value("min_instructions", 2).toInt();
                    int maxInst = customSettings.value("max_instructions", 8).toInt();
                    bool useAdvanced = customSettings.value("use_advanced_junk", false).toBool();

                    JunkGenerator junkGen(settings);
                    QString junk = junkGen.generateJunkInstructions(minInst, maxInst, useAdvanced);

                    if (!junk.isEmpty())
                    {
                        newContent << line;
                        newContent << junk;
                        continue;
                    }
                }
            }

            newContent << line;
        }

        if (enableInterleaved)
        {
            newContent << stubGen.generateAlignPadding();
        }
    }

    newContent << "\nend\n";

    QFile outAsmFile(asmPath);

    if (!outAsmFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        logMessage(Colors::FAIL() + QString("Failed to write Assembly File: %1").arg(asmPath) + Colors::ENDC());
        return false;
    }

    QTextStream out(&outAsmFile);
    out << newContent.join("\n");
    outAsmFile.close();

    if (!updateHeaderFile(headerPath, syscallMap, functionSuffixes))
    {
        logMessage(Colors::FAIL() + "Failed to update Header File" + Colors::ENDC());
        return false;
    }

    bool bindingsEnabled = settings->value("general/bindings_enabled", false).toBool();

    if (bindingsEnabled && !isKernelMode())
    {
        QString defPath = getDefFilePath(isKernelMode());
        QStringList obfuscatedNames;
        QRegularExpression procRegex(R"(\s*([A-Za-z0-9_]+)\s+PROC)");

        for (const QString& line : newContent)
        {
            QRegularExpressionMatch match = procRegex.match(line);

            if (match.hasMatch())
            {
                obfuscatedNames << match.captured(1);
            }
        }

        if (!updateDefFile(defPath, obfuscatedNames))
        {
            logMessage(Colors::FAIL() + "Failed to update DEF File" + Colors::ENDC());
            return false;
        }
    }

    logMessage(Colors::OKGREEN() + QString("Generated %1 Unique Syscalls with Custom Obfuscation Settings")
                      .arg(syscallMap.size()) + Colors::ENDC());
    logMessage(Colors::OKGREEN() + "Applied Stub Mapper Settings to Syscalls" + Colors::ENDC());
    return true;
}

bool DirectObfuscation::StubMapper::updateHeaderFile(const QString& headerPath,
                                                     const QMap<QString, QString>& syscallMap,
                                                     const QMap<QString, QString>& functionSuffixes)
{
    QFile headerFile(headerPath);

    if (!headerFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        logMessage(Colors::FAIL() + QString("Failed to open Header File: %1").arg(headerPath) + Colors::ENDC());
        return false;
    }

    QTextStream in(&headerFile);
    QStringList headerContent = in.readAll().split('\n');
    headerFile.close();

    QStringList selectedSyscalls = settings->value("integrity/selected_syscalls", QStringList()).toStringList();
    bool useAllSyscalls = selectedSyscalls.isEmpty();
    bool enableControlFlow = settings->value("obfuscation/control_flow_enabled", false).toBool();
    QString syscallPrefix = getSyscallPrefix();
    QStringList newHeaderContent;
    bool headerPartEnded = false;
    bool skipBlock = false;
    QString currentSyscall;

    for (const QString& line : headerContent)
    {
        if (!headerPartEnded &&
            (line.contains(QString("NTSTATUS %1").arg(syscallPrefix)) ||
             line.contains(QString("ULONG %1").arg(syscallPrefix)) ||
             line.contains(QString("BOOLEAN %1").arg(syscallPrefix)) ||
             line.contains(QString("VOID %1").arg(syscallPrefix)) ||
             line.contains("NTSTATUS SC") ||
             line.contains("ULONG SC") ||
             line.contains("BOOLEAN SC") ||
             line.contains("VOID SC") ||
             line.contains("#ifdef __cplusplus")))
        {
            headerPartEnded = true;
        }

        if (!headerPartEnded)
        {
            if (line.contains("_WIN64") && line.contains("#ifdef"))
            {
                newHeaderContent << line;
                newHeaderContent << "";
                continue;
            }

            newHeaderContent << line;
            continue;
        }
        /* preserve c++ guards and extern blocks */
        if (line.contains("#ifdef __cplusplus") ||
            line.contains("extern \"C\"") ||
            line.trimmed() == "{" ||
            line.trimmed() == "}" ||
            line.contains("#endif"))
        {
            newHeaderContent << line;
            continue;
        }

        if (line.contains("NTSTATUS SC") || line.contains("ULONG SC") ||
            line.contains("BOOLEAN SC") || line.contains("VOID SC") ||
            line.contains(QString("NTSTATUS %1").arg(syscallPrefix)) ||
            line.contains(QString("ULONG %1").arg(syscallPrefix)) ||
            line.contains(QString("BOOLEAN %1").arg(syscallPrefix)) ||
            line.contains(QString("VOID %1").arg(syscallPrefix)))
        {
            QRegularExpression regex(QString(R"(extern "C" (?:NTSTATUS|ULONG|BOOLEAN|VOID) ((?:SC|%1)\w+)\()").arg(syscallPrefix));
            QRegularExpressionMatch match = regex.match(line);

            if (!match.hasMatch())
            {
                regex = QRegularExpression(QString(R"((?:NTSTATUS|ULONG|BOOLEAN|VOID) ((?:SC|%1)\w+)\()").arg(syscallPrefix));
                match = regex.match(line);
            }

            if (match.hasMatch())
            {
                QString originalName = match.captured(1);

                if (originalName.startsWith("SC"))
                {
                    currentSyscall = syscallPrefix + originalName.mid(2);
                }
                else
                {
                    currentSyscall = originalName;
                }

                if (useAllSyscalls || selectedSyscalls.contains(currentSyscall))
                {
                    skipBlock = false;

                    if (syscallMap.contains(currentSyscall))
                    {
                        QString newLine = line;
                        QString obfuscatedName = syscallMap.value(currentSyscall);

                        if (enableControlFlow && functionSuffixes.contains(currentSyscall))
                        {
                            obfuscatedName = QString("%1_%2").arg(obfuscatedName).arg(functionSuffixes[currentSyscall]);
                        }

                        newLine = newLine.replace(originalName, obfuscatedName);
                        newLine = newLine.replace("extern \"C\" ", "");
                        newHeaderContent << newLine;
                    }
                }
                else
                {
                    skipBlock = true;
                }

                continue;
            }
        }

        if (!skipBlock)
        {
            if (line.contains("SC"))
            {
                QString updatedLine = line;
                QRegularExpression scRegex(R"(\bSC(\w+)\b)");
                updatedLine = updatedLine.replace(scRegex, QString("%1\\1").arg(syscallPrefix));
                newHeaderContent << updatedLine;
            }
            else
            {
                newHeaderContent << line;
            }
        }
        else if (line.trimmed() == ");")
        {
            skipBlock = false;
        }
    }
    newHeaderContent << "";
    newHeaderContent << "/* Syscall Name Mappings */";

    for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it)
    {
        QString obfuscatedName = it.value();

        if (enableControlFlow && functionSuffixes.contains(it.key()))
        {
            obfuscatedName = QString("%1_%2").arg(obfuscatedName).arg(functionSuffixes[it.key()]);
        }

        newHeaderContent << QString("#define %1 %2").arg(it.key()).arg(obfuscatedName);
    }

    QStringList cleanedHeaderContent;
    bool prevEmpty = false;

    for (const QString& line : newHeaderContent)
    {
        if (line.trimmed().isEmpty())
        {
            if (!prevEmpty)
            {
                cleanedHeaderContent << line;
                prevEmpty = true;
            }
        }
        else
        {
            cleanedHeaderContent << line;
            prevEmpty = false;
        }
    }

    QFile outHeaderFile(headerPath);

    if (!outHeaderFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        logMessage(Colors::FAIL() + QString("Failed to write Header File: %1").arg(headerPath) + Colors::ENDC());
        return false;
    }

    QTextStream out(&outHeaderFile);
    out << cleanedHeaderContent.join("\n");
    outHeaderFile.close();
    return true;
}

bool DirectObfuscation::StubMapper::updateDefFile(const QString& defPath, const QStringList& obfuscatedNames)
{
    QFile defFile(defPath);

    if (!defFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        logMessage(Colors::FAIL() + QString("Failed to write DEF File: %1").arg(defPath) + Colors::ENDC());
        return false;
    }

    QTextStream out(&defFile);
    out << "LIBRARY SysCaller\n";
    out << "EXPORTS\n";

    for (const QString& name : obfuscatedNames)
    {
        out << "    " << name << "\n";
    }

    defFile.close();
    return true;
}

int DirectObfuscation::StubMapper::getRandomInt(int min, int max)
{
    return QRandomGenerator::global()->bounded(min, max + 1);
}
