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
                    // now emit write+decrypt sequence using only rax, rcx, r11, r8b buffer base is [rsp+20h]
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

QString IndirectObfuscation::obfuscateResolverCall(const QString& originalCall) {
    if (settings->value("obfuscation/indirect_obfuscate_calls", true).toBool()) {
        QString method = settings->value("obfuscation/indirect_resolver_method", "random").toString();
        if (method == "random") {
            method = QString::number(QRandomGenerator::global()->bounded(4));
        }
        QMap<QString, int> methodMap;
        methodMap["register"] = 0;
        methodMap["stack"] = 1;
        methodMap["indirect"] = 2;
        methodMap["shuffle"] = 3;
        int pattern = methodMap.value(method, 0);
        switch (pattern) {
            case 0:
                // Pattern 1: Register pointer call via R10
                return "    ; RegPtr_R10_Call\n"
                       "    lea r10, [GetSyscallNumber]\n"
                       "    call r10";
            case 1:
                // Pattern 2: Stack indirect call (16 byte aligned)
                return "    ; StackIndirect_Aligned\n"
                       "    sub rsp, 16\n"                    // Align stack to 16 byte boundary
                       "    lea rax, [GetSyscallNumber]\n"
                       "    mov [rsp], rax\n"
                       "    call qword ptr [rsp]\n"
                       "    add rsp, 16";                     // Restore stack
            case 2:
                // Pattern 3: Stack scratch space indirect call
                return "    ; StackScratchIndirect\n"
                       "    lea rax, [GetSyscallNumber]\n"
                       "    mov [rsp-8], rax\n"
                       "    lea rax, [rsp-8]\n"
                       "    call qword ptr [rax]";
            case 3:
                // Pattern 4: Register shuffle call via R10
                return "    ; RegShuffle_R10_Call\n"
                       "    push r10\n"
                       "    lea r10, [GetSyscallNumber]\n"
                       "    call r10\n"
                       "    pop r10";
        }
    }
    return originalCall;
}

QString IndirectObfuscation::generateEncryptedSyscallNumbers() {
    QString encryptedCode;
    int encryptionKey = QRandomGenerator::global()->bounded(1, 256);
    QString khex = QString::number(encryptionKey, 16).toUpper();
    if (khex.length() < 2) khex.prepend('0');
    int offset = QRandomGenerator::global()->bounded(8, 32);
    encryptedCode = QString("    ; Encrypted syscall number handling\n"
                           "    ; Key: 0%1h\n"
                           "    mov rax, [rsp+%2]\n"
                           "    xor rax, 0%1h\n"
                           "    mov [rsp+%2], rax\n")
                           .arg(khex)
                           .arg(offset);
    return encryptedCode;
}

QString IndirectObfuscation::generateControlFlowObfuscation() {
    QString method = settings->value("obfuscation/indirect_control_flow_method", "random").toString();
    int pattern;
    if (method == "random") {
        pattern = QRandomGenerator::global()->bounded(4);
    } else {
        QMap<QString, int> methodMap;
        methodMap["register"] = 0;
        methodMap["value"] = 1;
        methodMap["flag"] = 2;
        methodMap["mixed"] = 3;
        pattern = methodMap.value(method, 0);
    }
    QStringList controlFlowPatterns = {
        // Pattern 0: Register Based
        QString("    ; Opaque Predicate - Register Based\n"
                "    test r11, r11\n"           // r11 is always 0, so test sets ZF=1
                "    jnz fake_branch_%1\n"      // Never taken (ZF=1, so jnz fails)
                "    ; Real code continues here\n"
                "    jmp real_code_%1\n"
                "fake_branch_%1:\n"
                "    nop\n"                      // Dead code
                "    xor r13, r13\n"            // Dead code
                "    add r14, 0\n"              // Dead code
                "real_code_%1:\n")
                .arg(QRandomGenerator::global()->bounded(100000, 999999)),
        // Pattern 1: Value Based
        QString("    ; Opaque Predicate - Value Based\n"
                "    mov r15, 0\n"              // Set r15 to 0
                "    cmp r15, 1\n"              // Compare 0 with 1 (always false)
                "    je fake_branch_%1\n"       // Never taken
                "    ; Real code continues here\n"
                "    jmp real_code_%1\n"
                "fake_branch_%1:\n"
                "    push r11\n"                // Dead code
                "    pop r11\n"                 // Dead code
                "    test r13, r13\n"           // Dead code
                "real_code_%1:\n")
                .arg(QRandomGenerator::global()->bounded(100000, 999999)),
        // Pattern 2: Flag Based
        QString("    ; Opaque Predicate - Flag Based\n"
                "    clc\n"                     // Clear carry flag
                "    jc fake_branch_%1\n"       // Never taken (CF=0)
                "    ; Real code continues here\n"
                "    jmp real_code_%1\n"
                "fake_branch_%1:\n"
                "    lea r11, [r11]\n"         // Dead code
                "    mov r13, r13\n"            // Dead code
                "    xchg r14, r14\n"          // Dead code
                "real_code_%1:\n")
                .arg(QRandomGenerator::global()->bounded(100000, 999999)),
        // Pattern 3: Mixed Junk Code
        QString("    ; Opaque Predicate - Mixed Junk Code\n"
                "    xor r11, r11\n"            // r11 = 0
                "    or r11, 0\n"               // r11 still = 0
                "    test r11, r11\n"           // Test 0 (always zero)
                "    jnz fake_branch_%1\n"      // Never taken
                "    ; Real code continues here\n"
                "    jmp real_code_%1\n"
                "fake_branch_%1:\n"
                "    pushfq\n"                  // Dead code
                "    popfq\n"                   // Dead code
                "    fnop\n"                    // Dead code
                "    pause\n"                   // Dead code
                "real_code_%1:\n")
                .arg(QRandomGenerator::global()->bounded(100000, 999999))
    };
    return controlFlowPatterns[pattern];
}

QString IndirectObfuscation::generateRegisterSafeJunk() {
    QStringList safeJunkInstructions = {
        "    nop\n",
        "    xchg r11, r11\n",
        "    xchg r13, r13\n",
        "    xchg r14, r14\n",
        "    xchg r15, r15\n",
        "    xchg rax, rax\n",
        "    push r11\n    pop r11\n",
        "    push r13\n    pop r13\n",
        "    push r14\n    pop r14\n",
        "    push r15\n    pop r15\n",
        "    pushfq\n    popfq\n",
        "    test r11, r11\n",
        "    test r13, r13\n",
        "    test r14, r14\n",
        "    test r15, r15\n",
        "    lea r11, [r11]\n",
        "    lea r13, [r13]\n",
        "    lea r14, [r14]\n",
        "    lea r15, [r15]\n",
        "    mov r11, r11\n",
        "    mov r13, r13\n",
        "    mov r14, r14\n",
        "    mov r15, r15\n",
        "    pause\n",
        "    fnop\n",
        "    cld\n",
        "    clc\n",
        "    stc\n    clc\n",
        "    cmc\n    cmc\n",
        "    xor r11d, 0\n",
        "    and r13d, -1\n",
        "    or r14d, 0\n",
        "    add r15d, 0\n",
        "    sub rax, 0\n",
        "    db 66h\n    nop\n",
        "    db 0Fh, 1Fh, 00h\n",
        "    db 0Fh, 1Fh, 40h, 00h\n",
        "    shl r11, 0\n",
        "    shr r13, 0\n",
        "    inc r14\n    dec r14\n",
        "    inc r15\n    dec r15\n",
        "    prefetchnta [rsp]\n",
        "    sfence\n",
        "    lfence\n",
        "    mfence\n"
    };
    int numInstructions = QRandomGenerator::global()->bounded(1, 4);
    QString junkCode;
    for (int i = 0; i < numInstructions; ++i) {
        int index = QRandomGenerator::global()->bounded(safeJunkInstructions.size());
        junkCode += safeJunkInstructions[index];
    }
    return junkCode;
}
