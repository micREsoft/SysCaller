#include "include/Core/Obfuscation/Indirect/IndirectObfuscation.h"
#include "include/Core/Utils/PathUtils.h"
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QDebug>
#include <QRandomGenerator>
#include <QDir>

IndirectObfuscation::IndirectObfuscation(QSettings* settings) 
    : settings(settings), outputCallback(nullptr) {
}

void IndirectObfuscation::setOutputCallback(std::function<void(const QString&)> callback) {
    outputCallback = callback;
}

void IndirectObfuscation::logMessage(const QString& message) {
    if (outputCallback) {
        outputCallback(message);
    }
    qDebug() << "IndirectObfuscation:" << message;
}

QString IndirectObfuscation::getIndirectPrefix() {
    return "SysIndirect";
}

bool IndirectObfuscation::isIndirectMode() {
    return settings->value("general/indirect_assembly", false).toBool();
}

bool IndirectObfuscation::generateIndirectObfuscation() {
    logMessage("Starting Indirect Obfuscation...");
    bool isKernel = settings->value("general/syscall_mode", "Nt").toString() == "Zw";
    QString asmPath = isKernel ? 
        PathUtils::getSysCallerKPath() + "/Wrapper/src/syscaller.asm" :
        PathUtils::getSysCallerPath() + "/Wrapper/src/syscaller.asm";
    QString headerPath = isKernel ?
        PathUtils::getSysCallerKPath() + "/Wrapper/include/SysK/sysFunctions_k.h" :
        PathUtils::getSysCallerPath() + "/Wrapper/include/Sys/sysFunctions.h";
    return processIndirectAssemblyFile(asmPath, headerPath);
}

bool IndirectObfuscation::processIndirectAssemblyFile(const QString& asmPath, const QString& headerPath) {
    QFile asmFile(asmPath);
    if (!asmFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        logMessage("Failed to open Assembly File: " + asmPath);
        return false;
    }
    QTextStream in(&asmFile);
    QStringList content = in.readAll().split('\n');
    asmFile.close();
    QStringList selectedSyscalls = settings->value("integrity/selected_syscalls", QStringList()).toStringList();
    bool useAllSyscalls = selectedSyscalls.isEmpty();
    QString indirectPrefix = getIndirectPrefix();
    QMap<QString, QStringList> indirectStubs;
    QStringList currentStub;
    QString currentSyscall;
    bool inStub = false;
    for (const QString& line : content) {
        QRegularExpression procRegex(QString("(%1\\w+)\\s+PROC").arg(indirectPrefix));
        QRegularExpressionMatch procMatch = procRegex.match(line);
        if (procMatch.hasMatch()) {
            currentSyscall = procMatch.captured(1);
            inStub = true;
            currentStub.clear();
            currentStub << line;
            if (useAllSyscalls || selectedSyscalls.contains(currentSyscall)) {
                indirectStubs[currentSyscall] = currentStub;
            }
        } else if (inStub) {
            currentStub << line;
            if (line.contains(" ENDP")) {
                inStub = false;
                if (useAllSyscalls || selectedSyscalls.contains(currentSyscall)) {
                    indirectStubs[currentSyscall] = currentStub;
                }
            }
        }
    }
    for (auto it = indirectStubs.begin(); it != indirectStubs.end(); ++it) {
        QStringList obfuscatedStub;
        bool inProcBlock = false;
        bool pendingEncString = false;
        QByteArray pendingEncBytes;
        int pendingPlainLen = 0;
        quint8 pendingKey = 0;
        bool encAdjustActive = false; // when true, convert next add rsp,32 to add rsp,64
        for (const QString& line : it.value()) {
            QString obfuscatedLine = line;
            if (line.contains(" PROC")) {
                inProcBlock = true;
                obfuscatedStub << line;
                continue;
            }
            if (line.contains(" ENDP")) {
                inProcBlock = false;
                pendingEncString = false;
                pendingEncBytes.clear();
                pendingPlainLen = 0;
                obfuscatedStub << line;
                continue;
            }
            if (inProcBlock) {
                if (settings->value("obfuscation/indirect_enable_junk", true).toBool()) {
                    QString junkCode = generateRegisterSafeJunk();
                    if (!junkCode.isEmpty()) {
                        QStringList junkLines = junkCode.split('\n');
                        for (const QString& junkLine : junkLines) {
                            if (!junkLine.trimmed().isEmpty()) {
                                obfuscatedStub << "    " + junkLine.trimmed();
                            }
                        }
                    }
                }
                if (settings->value("obfuscation/indirect_encrypt_strings", false).toBool()) {
                    QRegularExpression strRx(R"(^\s*lea\s+rcx,\s*\[(\w+)_str\]\s*$)", QRegularExpression::CaseInsensitiveOption);
                    auto m = strRx.match(line);
                    if (m.hasMatch()) {
                        QString label = m.captured(1);
                        QByteArray plain = label.toUtf8();
                        plain.append('\0');
                        if (plain.size() <= 32) {
                            pendingKey = static_cast<quint8>(QRandomGenerator::global()->bounded(1, 256));
                            pendingEncBytes = QByteArray(plain);
                            for (int i = 0; i < pendingEncBytes.size(); ++i) pendingEncBytes[i] = pendingEncBytes[i] ^ pendingKey;
                            pendingPlainLen = plain.size();
                            pendingEncString = true;
                            continue;
                        }
                    }
                }
                // if we have pending enc string and see shadow space reservation, emit the build+decrypt into shadow space
                if (pendingEncString && line.trimmed().startsWith("sub rsp, 32")) {
                    // replace with sub rsp, 64 to allocate extra 32 bytes (shadow + our buffer)
                    obfuscatedStub << "    sub rsp, 64";
                    encAdjustActive = true;
                    // now emit write+decrypt sequence using only rax, rcx, r11, r8b; buffer base is [rsp+20h]
                    obfuscatedStub << "    ; Build decrypted resolver string in shadow space";
                    int lblId = QRandomGenerator::global()->bounded(100000, 999999);
                    QString loopLbl = QString("dec_loop_cf_%1").arg(lblId);
                    QString doneLbl = QString("dec_done_cf_%1").arg(lblId);
                    // write encrypted qwords into [rsp+off]
                    for (int off = 0; off < 32; off += 8) {
                        quint64 q = 0;
                        for (int b = 0; b < 8; ++b) {
                            int idx = off + b;
                            unsigned char val = 0;
                            if (idx < pendingEncBytes.size()) val = static_cast<unsigned char>(pendingEncBytes[idx]);
                            q |= (static_cast<quint64>(val) << (8 * b));
                        }
                        QString hex = QString::number(static_cast<qulonglong>(q), 16).toUpper();
                        while (hex.length() < 16) hex.prepend('0');
                        obfuscatedStub << QString("    mov rax, 0%1h").arg(hex);
                        if (off == 0) {
                            obfuscatedStub << "    mov qword ptr [rsp+20h], rax";
                        } else {
                            obfuscatedStub << QString("    mov qword ptr [rsp+20h+%1], rax").arg(off);
                        }
                    }
                    obfuscatedStub << QString("    mov r11d, %1").arg(pendingPlainLen);
                    {
                        QString khex = QString::number(pendingKey, 16).toUpper();
                        if (khex.length() < 2) khex.prepend('0');
                        obfuscatedStub << QString("    mov al, 0%1h").arg(khex);
                    }
                    obfuscatedStub << "    ; decrypt in place: for i in [0..len) shadow[i] ^= al";
                    obfuscatedStub << "    xor rcx, rcx";
                    obfuscatedStub << loopLbl + ":";
                    obfuscatedStub << "    cmp rcx, r11";
                    obfuscatedStub << "    jae " + doneLbl;
                    obfuscatedStub << "    mov r8b, byte ptr [rsp+rcx+20h]";
                    obfuscatedStub << "    xor r8b, al";
                    obfuscatedStub << "    mov byte ptr [rsp+rcx+20h], r8b";
                    obfuscatedStub << "    inc rcx";
                    obfuscatedStub << "    jmp " + loopLbl;
                    obfuscatedStub << doneLbl + ":";
                    obfuscatedStub << "    lea rcx, [rsp+20h]"; // rcx = decrypted buffer out of callee home space
                    pendingEncString = false;
                    pendingEncBytes.clear();
                    pendingPlainLen = 0;
                    continue;
                }
                if (encAdjustActive && line.trimmed().startsWith("add rsp, 32")) {
                    obfuscatedStub << "    add rsp, 64";
                    encAdjustActive = false;
                    continue;
                }
                if (line.contains("call GetSyscallNumber")) {
                    obfuscatedLine = obfuscateResolverCall(line);
                }
                if (settings->value("obfuscation/indirect_enable_control_flow", false).toBool()) {
                    QString controlFlowCode = generateControlFlowObfuscation();
                    if (!controlFlowCode.isEmpty()) {
                        QStringList controlFlowLines = controlFlowCode.split('\n');
                        for (const QString& flowLine : controlFlowLines) {
                            if (!flowLine.trimmed().isEmpty()) {
                                obfuscatedStub << "    " + flowLine.trimmed();
                            }
                        }
                    }
                }
            }
            obfuscatedStub << obfuscatedLine;
        }
        it.value() = obfuscatedStub;
    }
    QFile outAsmFile(asmPath);
    if (!outAsmFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        logMessage("Failed to write Assembly File: " + asmPath);
        return false;
    }
    QTextStream out(&outAsmFile);
    bool inProcessedStub = false;
    QString currentStubName;
    for (const QString& line : content) {
        QRegularExpression procRegex(QString("(%1\\w+)\\s+PROC").arg(indirectPrefix));
        QRegularExpressionMatch procMatch = procRegex.match(line);
        if (procMatch.hasMatch()) {
            QString stubName = procMatch.captured(1);
            if (indirectStubs.contains(stubName)) {
                inProcessedStub = true;
                currentStubName = stubName;
                for (const QString& stubLine : indirectStubs[stubName]) {
                    out << stubLine << "\n";
                }
                continue;
            }
        }
        if (inProcessedStub && line.contains(" ENDP")) {
            inProcessedStub = false;
            currentStubName.clear();
            continue;
        }
        if (inProcessedStub) {
            continue;
        }
        out << line << "\n";
    }
    outAsmFile.close();
    logMessage("Indirect Obfuscation completed successfully!");
    return true;
}
