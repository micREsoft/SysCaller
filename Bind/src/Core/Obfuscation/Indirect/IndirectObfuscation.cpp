#include "include/Core/Obfuscation/Indirect/IndirectObfuscation.h"
#include "include/Core/Utils/PathUtils.h"
#include "include/Core/Obfuscation/Direct/Stub/JunkGenerator.h"
#include "include/Core/Obfuscation/Direct/Stub/NameGenerator.h"
#include "include/Core/Obfuscation/Direct/Encryption/Encryptor.h"
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
        for (const QString& line : it.value()) {
            QString obfuscatedLine = line;
            if (line.contains(" PROC")) {
                inProcBlock = true;
                obfuscatedStub << line;
                continue;
            }
            if (line.contains(" ENDP")) {
                inProcBlock = false;
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
                if (line.contains("call GetSyscallNumber")) {
                    obfuscatedLine = obfuscateResolverCall(line);
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
                return "    ; Register based function pointer obfuscation\n"
                       "    lea r10, [GetSyscallNumber]\n"
                       "    call r10";
            case 1:
                return "    ; Stack based function pointer with proper alignment\n"
                       "    sub rsp, 16\n"                    
                       "    lea rax, [GetSyscallNumber]\n"
                       "    mov [rsp], rax\n"
                       "    call qword ptr [rsp]\n"
                       "    add rsp, 16";                     
            case 2:
                return "    ; Indirect call through data section\n"
                       "    lea rax, [GetSyscallNumber]\n"
                       "    mov [rsp-8], rax\n"
                       "    lea rax, [rsp-8]\n"
                       "    call qword ptr [rax]";
            case 3:
                return "    ; Register shuffle obfuscation\n"
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
    encryptedCode = QString("    ; Encrypted syscall number handling\n"
                           "    ; Key: 0x%1\n"
                           "    mov rax, [rsp+%2]\n"  // get syscall number from stack
                           "    xor rax, 0x%3\n"       // decrypt with key
                           "    mov [rsp+%2], rax\n"   // store decrypted number back
                           "    ; Continue with normal syscall\n")
                           .arg(encryptionKey, 2, 16, QChar('0'))
                           .arg(QRandomGenerator::global()->bounded(8, 32))
                           .arg(encryptionKey, 2, 16, QChar('0'));
    return encryptedCode;
}

QString IndirectObfuscation::generateRegisterSafeJunk() {
    // for indirect stubs we need to be careful about register usage:
    // rcx, rdx, r8, r9 are function parameters dont touch those!
    // rbx, rsi, rdi, r12 are used to save rcx, rdx, r8, r9 dont touch those!
    // r10 is used for function pointer dont touch this!
    // we can ONLY safely use r11, r13, r14, r15, rax
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
