#include "include/Core/Utils/Utils.h"
#include "include/Core/Utils/PathUtils.h"
#include <QDebug>
#include <QByteArray>
#include <cstring>
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

QMap<QString, int> SyscallExtractor::getSyscallsFromDll(const QString& dllPath) {
    QMap<QString, int> syscallNumbers;
    qDebug() << QString("Starting to parse DLL: %1").arg(dllPath);
    QByteArray dllPathBytes = dllPath.toLocal8Bit();
    const char* dllPathCStr = dllPathBytes.constData();
    qDebug() << "DLL Path as Const Char*:" << dllPathCStr;
    peparse::parsed_pe* pe = peparse::ParsePEFromFile(dllPathCStr);
    if (!pe) {
        qWarning() << "Failed to parse PE File:" << dllPath;
        return syscallNumbers;
    }
    uint64_t imageBase = pe->peHeader.nt.OptionalHeader64.ImageBase;
    qDebug() << "Image Base:" << QString("0x%1").arg(imageBase, 0, 16);
    static int exportCount = 0;
    exportCount = 0;
    struct CallbackData {
        QMap<QString, int>* syscallNumbers;
        peparse::parsed_pe* pe;
        uint64_t imageBase;
    };
    CallbackData callbackData = { &syscallNumbers, pe, imageBase };
    auto callback = [](void* N, const peparse::VA& addr, const std::string& mod, const std::string& fn) -> int {
        auto* data = static_cast<CallbackData*>(N);
        if (fn.empty()) {
            return 0;
        }
        QString funcName;
        try {
            funcName = QString::fromUtf8(fn.c_str(), fn.length());
        } catch (...) {
            qDebug() << "Failed to convert Function Name, skipping.";
            return 0;
        }
        static int exportCount = 0;
        exportCount++;
        if (exportCount % 100 == 0) {
            qDebug() << "Processed" << exportCount << "Exports...";
        }
        if (!funcName.startsWith("Nt") && !funcName.startsWith("Zw")) {
            return 0;
        }
        static int processedCount = 0;
        if (processedCount < 3) {
            qDebug() << "Processing Function:" << funcName;
            processedCount++;
        }
        uint32_t funcRVA = static_cast<uint32_t>(addr - data->imageBase);
        uint32_t fileOffset = 0;
        if (addr < data->imageBase) {
            qDebug() << "Invalid Address, Skipping Function:" << funcName;
            return 0;
        }
        if (SyscallExtractor::rvaToFileOffset(data->pe, funcRVA, fileOffset)) {
            if (!data->pe || !data->pe->fileBuffer) {
                qDebug() << "PE File or buffer is null, skipping Function:" << funcName;
                return 0;
            }
            std::vector<uint8_t> funcBytes;
            size_t bytesRead = SyscallExtractor::readBytesFromBuffer(data->pe->fileBuffer, fileOffset, 32, funcBytes);
            if (bytesRead > 0) {
                static int debugCount = 0;
                if (debugCount < 3) {
                    QString bytesHex;
                    for (size_t i = 0; i < qMin(bytesRead, size_t(16)); ++i) {
                        bytesHex += QString("%1 ").arg(funcBytes[i], 2, 16, QChar('0'));
                    }
                    qDebug() << "Function:" << funcName << "RVA:" << QString("0x%1").arg(funcRVA, 0, 16) << "File Offset:" << QString("0x%1").arg(fileOffset, 0, 16);
                    qDebug() << "First 16 Bytes:" << bytesHex;
                    debugCount++;
                }
                bool foundSyscall = false;
                if (bytesRead >= 8) {
                    for (size_t i = 0; i <= bytesRead - 8; ++i) {
                        if (funcBytes[i] == 0x4c && funcBytes[i+1] == 0x8b && funcBytes[i+2] == 0xd1) {
                            if (funcBytes[i+3] == 0xb8) {
                                uint32_t syscallId = funcBytes[i+4] | 
                                                   (funcBytes[i+5] << 8) | 
                                                   (funcBytes[i+6] << 16) | 
                                                   (funcBytes[i+7] << 24);
                                if (syscallId <= 0xFFFF) {
                                    static int syscallLogCount = 0;
                                    if (syscallLogCount < 5) {
                                        qDebug() << "Found Syscall ID:" << syscallId << "For" << funcName;
                                        syscallLogCount++;
                                    }
                                    (*data->syscallNumbers)[funcName] = static_cast<int>(syscallId);
                                    foundSyscall = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (!foundSyscall) {
                        static int failureLogCount = 0;
                        if (failureLogCount < 3) {
                            qDebug() << "Syscall Pattern not found for" << funcName;
                            failureLogCount++;
                        }
                    }
                } else {
                    qDebug() << "Not enough bytes to parse Syscall Pattern for" << funcName;
                }
            } else {
                qDebug() << "Failed to read bytes for Function:" << funcName;
            }
        } else {
            qDebug() << "Failed to convert RVA to File Offset for Function:" << funcName;
        }
        return 0;
    };
    
    peparse::IterExpVA(pe, callback, &callbackData);
    
    peparse::DestructParsedPE(pe);
    qDebug() << QString("Finished parsing DLL, found %1 Syscalls").arg(syscallNumbers.size());
    if (syscallNumbers.size() > 0) {
        qDebug() << "Sample Syscalls Found:";
        int count = 0;
        for (auto it = syscallNumbers.begin(); it != syscallNumbers.end() && count < 5; ++it, ++count) {
            qDebug() << "  " << it.key() << "->" << it.value();
        }
    }
    return syscallNumbers;
}

bool SyscallExtractor::rvaToFileOffset(peparse::parsed_pe* pe, uint32_t rva, uint32_t& fileOffset) {
    struct CallbackData {
        bool found;
        uint32_t address;
        uint32_t result;
    } data{false, rva, 0};
    auto L_inspectSection = [](void* N,
                               const peparse::VA& secBase,
                               const std::string& secName,
                               const peparse::image_section_header& s,
                               const peparse::bounded_buffer* dataSec) -> int {
        static_cast<void>(secBase);
        static_cast<void>(secName);
        static_cast<void>(dataSec);
        auto callback_data = static_cast<CallbackData*>(N);
        uint32_t sectionBaseAddress = s.VirtualAddress;
        uint32_t sectionSize;
        if (s.SizeOfRawData != 0) {
            sectionSize = s.SizeOfRawData;
        } else {
            sectionSize = s.Misc.VirtualSize;
        }
        uint32_t sectionEndAddress = sectionBaseAddress + sectionSize;
        if (callback_data->address >= sectionBaseAddress &&
            callback_data->address < sectionEndAddress) {
            callback_data->result = s.PointerToRawData + (callback_data->address - sectionBaseAddress);
            callback_data->found = true;
            qDebug() << "Found in Section:" << QString::fromStdString(secName) 
                     << "RVA:" << QString("0x%1").arg(callback_data->address, 0, 16)
                     << "-> File Offset:" << QString("0x%1").arg(callback_data->result, 0, 16);
            return 1;
        }
        return 0;
    };
    peparse::IterSec(pe, L_inspectSection, &data);
    if (data.found) {
        fileOffset = data.result;
        return true;
    }
    qDebug() << "Failed to convert RVA" << QString("0x%1").arg(rva, 0, 16) << "to File Offset";
    return false;
}

size_t SyscallExtractor::readBytesFromBuffer(const peparse::bounded_buffer* buffer, uint32_t offset, size_t size, std::vector<uint8_t>& data) {
    if (!buffer) {
        qDebug() << "Buffer is Null";
        return 0;
    }
    if (offset >= buffer->bufLen) {
        qDebug() << "Offset" << QString("0x%1").arg(offset, 0, 16) << ">= Buffer Length" << QString("0x%1").arg(buffer->bufLen, 0, 16);
        return 0;
    }
    if (offset + size > buffer->bufLen) {
        qDebug() << "Offset + Size" << QString("0x%1").arg(offset + size, 0, 16) << "> Buffer Length" << QString("0x%1").arg(buffer->bufLen, 0, 16);
        return 0;
    }
    data.resize(size);
    memcpy(data.data(), buffer->buf + offset, size);
    qDebug() << "Successfully read" << size << "bytes from Offset" << QString("0x%1").arg(offset, 0, 16);
    return size;
}

QVariantMap StubHashGenerator::generateStubHashes(const QString& asmFilePath, const QString& headerFilePath, const QString& obfuscationMethod) {
    QVariantMap stubHashes;
    qDebug() << "Generating Stub Hashes...";
    qDebug() << "  ASM File:" << asmFilePath;
    qDebug() << "  Header File:" << headerFilePath;
    qDebug() << "  Obfuscation Method:" << obfuscationMethod;
    try {
        QSettings settings(PathUtils::getIniPath(), QSettings::IniFormat);
        bool usingStubMapper = false;
        if (!obfuscationMethod.isEmpty()) {
            usingStubMapper = (obfuscationMethod == "stub_mapper");
        } else {
            bool forceStubMapper = settings.value("obfuscation/force_stub_mapper", false).toBool();
            bool forceNormal = settings.value("obfuscation/force_normal", false).toBool();
            QMap<QString, QVariant> syscallSettings = settings.value("stub_mapper/syscall_settings", QMap<QString, QVariant>()).toMap();
            usingStubMapper = forceStubMapper || (syscallSettings.size() > 0 && !forceNormal);
        }
        QMap<QString, QVariant> syscallSettings = settings.value("stub_mapper/syscall_settings", QMap<QString, QVariant>()).toMap();
        QVariantMap config;
        if (usingStubMapper && syscallSettings.size() > 0) {
            config["obfuscation_method"] = "Stub Mapper";
            QVariantMap globalSettings;
            QVariantMap junkInstructions;
            junkInstructions["min"] = settings.value("obfuscation/min_instructions", 2).toInt();
            junkInstructions["max"] = settings.value("obfuscation/max_instructions", 8).toInt();
            junkInstructions["advanced"] = settings.value("obfuscation/use_advanced_junk", false).toBool();
            globalSettings["junk_instructions"] = junkInstructions;
            QVariantMap nameRandomization;
            nameRandomization["prefix_length"] = settings.value("obfuscation/syscall_prefix_length", 8).toInt();
            nameRandomization["number_length"] = settings.value("obfuscation/syscall_number_length", 6).toInt();
            nameRandomization["offset_length"] = settings.value("obfuscation/offset_name_length", 8).toInt();
            globalSettings["name_randomization"] = nameRandomization;
            globalSettings["sequence_shuffling"] = settings.value("obfuscation/shuffle_sequence", true).toBool();
            QVariantMap encryption;
            encryption["enabled"] = settings.value("obfuscation/enable_encryption", true).toBool();
            encryption["method"] = settings.value("obfuscation/encryption_method", 1).toInt();
            globalSettings["encryption"] = encryption;
            globalSettings["function_chunking"] = settings.value("obfuscation/enable_chunking", true).toBool();
            globalSettings["interleaved_execution"] = settings.value("obfuscation/enable_interleaved", true).toBool();
            config["global_settings"] = globalSettings;
            config["syscall_specific_settings"] = syscallSettings;
        } else {
            config["obfuscation_method"] = "Normal";
            QVariantMap junkInstructions;
            junkInstructions["min"] = settings.value("obfuscation/min_instructions", 2).toInt();
            junkInstructions["max"] = settings.value("obfuscation/max_instructions", 8).toInt();
            junkInstructions["advanced"] = settings.value("obfuscation/use_advanced_junk", false).toBool();
            config["junk_instructions"] = junkInstructions;
            QVariantMap nameRandomization;
            nameRandomization["prefix_length"] = settings.value("obfuscation/syscall_prefix_length", 8).toInt();
            nameRandomization["number_length"] = settings.value("obfuscation/syscall_number_length", 6).toInt();
            nameRandomization["offset_length"] = settings.value("obfuscation/offset_name_length", 8).toInt();
            config["name_randomization"] = nameRandomization;
            config["sequence_shuffling"] = settings.value("obfuscation/shuffle_sequence", true).toBool();
            QVariantMap encryption;
            encryption["enabled"] = settings.value("obfuscation/enable_encryption", true).toBool();
            encryption["method"] = settings.value("obfuscation/encryption_method", 1).toInt();
            config["encryption"] = encryption;
            config["function_chunking"] = settings.value("obfuscation/enable_chunking", true).toBool();
            config["interleaved_execution"] = settings.value("obfuscation/enable_interleaved", true).toBool();
        }
        stubHashes["timestamp"] = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
        stubHashes["config"] = config;
        stubHashes["stubs"] = QVariantMap();
        QFile asmFile(asmFilePath);
        if (asmFile.exists() && asmFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString asmContent = asmFile.readAll();
            asmFile.close();
            qDebug() << "Processing ASM File:" << asmFilePath;
            qDebug() << "ASM Content Length:" << asmContent.length();
            QMap<QString, QString> obfuscatedToSyscall;
            QRegularExpression aliasRegex("ALIAS\\s+<(Sys[A-Za-z0-9_]+)>\\s*=\\s*<([A-Za-z0-9_]+)>", QRegularExpression::CaseInsensitiveOption);
            QRegularExpressionMatchIterator aliasIterator = aliasRegex.globalMatch(asmContent);
            while (aliasIterator.hasNext()) {
                QRegularExpressionMatch match = aliasIterator.next();
                QString syscall = match.captured(1);
                QString obfuscated = match.captured(2);
                obfuscatedToSyscall[obfuscated] = syscall;
                qDebug() << "Found ALIAS:" << syscall << "->" << obfuscated;
            }
            qDebug() << "Found" << obfuscatedToSyscall.size() << "ALIAS Declarations";
            QRegularExpression procRegex("([A-Za-z0-9_]+)\\s+PROC", QRegularExpression::CaseInsensitiveOption);
            QRegularExpressionMatchIterator procIterator = procRegex.globalMatch(asmContent);
            int procCount = 0;
            int matchedProcCount = 0;
            while (procIterator.hasNext()) {
                QRegularExpressionMatch match = procIterator.next();
                QString procName = match.captured(1);
                procCount++;
                if (!obfuscatedToSyscall.contains(procName)) {
                    qDebug() << "PROC not in ALIAS Map:" << procName;
                    continue;
                }
                matchedProcCount++;
                QString syscallName = obfuscatedToSyscall[procName];
                int startPos = match.capturedStart();
                int endPos = -1;
                QRegularExpression endpRegex(QString("%1\\s+ENDP").arg(procName), QRegularExpression::CaseInsensitiveOption);
                QRegularExpressionMatch endpMatch = endpRegex.match(asmContent, startPos);
                if (endpMatch.hasMatch()) {
                    endPos = endpMatch.capturedEnd();
                }
                if (endPos != -1) {
                    QString stubCode = asmContent.mid(startPos, endPos - startPos);
                    // generate MD5 hash
                    QByteArray md5Hash = QCryptographicHash::hash(stubCode.toUtf8(), QCryptographicHash::Md5);
                    QString md5Hex = md5Hash.toHex();
                    // generate SHA256 hash
                    QByteArray sha256Hash = QCryptographicHash::hash(stubCode.toUtf8(), QCryptographicHash::Sha256);
                    QString sha256Hex = sha256Hash.toHex();
                    QVariantMap hashData;
                    hashData["md5"] = md5Hex;
                    hashData["sha256"] = sha256Hex;
                    hashData["size"] = stubCode.length();
                    hashData["obfuscated_name"] = procName;
                    if (usingStubMapper && syscallSettings.contains(syscallName)) {
                        hashData["custom_config"] = syscallSettings[syscallName];
                    }
                    QVariantMap stubs = stubHashes["stubs"].toMap();
                    stubs[syscallName] = hashData;
                    stubHashes["stubs"] = stubs;
                    qDebug() << "Added Stub Hash for:" << syscallName << "(" << procName << ")";
                }
            }
            qDebug() << "Total PROC Declarations:" << procCount;
            qDebug() << "Matched PROC Declarations:" << matchedProcCount;
            qDebug() << "Final Stub Count:" << stubHashes["stubs"].toMap().size();
        }
        QFile headerFile(headerFilePath);
        if (headerFile.exists() && headerFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString headerContent = headerFile.readAll();
            headerFile.close();
            QRegularExpression funcRegex("EXTERN_C\\s+(?:__kernel_entry\\s+)?(?:NTSYSCALLAPI\\s+)?(?:NTSTATUS|BOOL|VOID|HANDLE|PVOID|ULONG|.*?)\\s+(?:NTAPI|WINAPI)?\\s*(Sys[A-Za-z0-9_]+)\\s*\\(([^;]*)\\);", QRegularExpression::CaseInsensitiveOption);
            QRegularExpressionMatchIterator funcIterator = funcRegex.globalMatch(headerContent);
            while (funcIterator.hasNext()) {
                QRegularExpressionMatch match = funcIterator.next();
                QString name = match.captured(1);
                QString params = match.captured(2);
                QVariantMap stubs = stubHashes["stubs"].toMap();
                if (stubs.contains(name)) {
                    QVariantMap hashData = stubs[name].toMap();
                    QByteArray headerHash = QCryptographicHash::hash(params.toUtf8(), QCryptographicHash::Sha256);
                    hashData["header_hash"] = headerHash.toHex();
                    hashData["params"] = params.trimmed();
                    stubs[name] = hashData;
                    stubHashes["stubs"] = stubs;
                }
            }
        }
        return stubHashes;
    } catch (...) {
        QVariantMap error;
        error["error"] = "Error Generating Stub Hashes";
        return error;
    }
}

QPair<bool, QString> StubHashGenerator::saveStubHashes(const QVariantMap& stubHashes, const QString& timestamp) {
    try {
        QString hashBackupsDir = PathUtils::getHashBackupsPath();
        QDir().mkpath(hashBackupsDir);
        QString actualTimestamp = timestamp;
        if (actualTimestamp.isEmpty()) {
            actualTimestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
        }
        QString jsonPath = QString("%1/stub_hashes_%2.json").arg(hashBackupsDir, actualTimestamp);
        QVariantMap formattedOutput;
        formattedOutput["timestamp"] = stubHashes["timestamp"];
        formattedOutput["config"] = stubHashes["config"];
        formattedOutput["stubs"] = QVariantMap();
        QVariantMap stubs = stubHashes["stubs"].toMap();
        QVariantMap formattedStubs;
        qDebug() << "Saving" << stubs.size() << "Stubs";
        for (auto it = stubs.begin(); it != stubs.end(); ++it) {
            QString syscallName = it.key();
            QVariantMap hashData = it.value().toMap();
            QString formattedHash = QString("MD5: %1 SHA-256: %2").arg(hashData["md5"].toString(), hashData["sha256"].toString());
            formattedStubs[syscallName] = formattedHash;
            qDebug() << "Formatted Stub:" << syscallName << "->" << formattedHash;
        }
        formattedOutput["stubs"] = formattedStubs;
        // generate build ID
        QStringList allHashes;
        QStringList sortedSyscalls = stubs.keys();
        std::sort(sortedSyscalls.begin(), sortedSyscalls.end());
        for (const QString& syscallName : sortedSyscalls) {
            QVariantMap hashData = stubs[syscallName].toMap();
            allHashes << QString("%1:%2:%3").arg(syscallName, hashData["md5"].toString(), hashData["sha256"].toString());
        }
        QJsonDocument configDoc = QJsonDocument::fromVariant(stubHashes["config"]);
        QString buildIdInput = allHashes.join(":") + QString(configDoc.toJson());
        QByteArray buildIdHash = QCryptographicHash::hash(buildIdInput.toUtf8(), QCryptographicHash::Sha256);
        formattedOutput["build_id"] = buildIdHash.toHex();
        QFile jsonFile(jsonPath);
        if (jsonFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QJsonDocument doc = QJsonDocument::fromVariant(formattedOutput);
            jsonFile.write(doc.toJson(QJsonDocument::Indented));
            jsonFile.close();
            return qMakePair(true, jsonPath);
        } else {
            return qMakePair(false, QString("Failed to write JSON File"));
        }
    } catch (...) {
        return qMakePair(false, QString("Error Saving Stub Hashes"));
    }
}

QString InlineAssemblyConverter::convertStubToInline(const QString& stubName, int syscallId) {
    QString syscallIdHex = QString("%1").arg(syscallId, 8, 16, QChar('0')).toUpper();
    QString lowByte = syscallIdHex.mid(6, 2);
    QString highByte = syscallIdHex.mid(4, 2);
    QString inlineStub = QString("%1 PROC\n"
                                "    ; mov r10, rcx\n"
                                "    ; mov eax, %2h\n"
                                "    ; syscall\n"
                                "    ; ret\n"
                                "    db 04Ch, 08Bh, 0D1h, 0B8h, 0%3h, 0%4h, 000h, 000h, 0Fh, 005h, 0C3h\n"
                                "%1 ENDP")
                                .arg(stubName)
                                .arg(syscallId, 0, 16)
                                .arg(lowByte)
                                .arg(highByte);
    return inlineStub;
}
