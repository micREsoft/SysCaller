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
                    JunkGenerator junkGen(settings);
                    QString junkCode = junkGen.generateJunkInstructions();
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
    return originalCall;
}

QString IndirectObfuscation::generateObfuscatedResolver() {
    QString resolver = "GetSyscallNumber PROC\n";
    resolver += "    ; Obfuscated resolver implementation\n";
    resolver += "    push rcx\n";
    resolver += "    push rdx\n";
    resolver += "    push r8\n";
    resolver += "    push r9\n";
    resolver += "    ; Add junk instructions\n";
    resolver += "    xor rax, rax\n";
    resolver += "    test rcx, rcx\n";
    resolver += "    ; Actual resolver logic\n";
    resolver += "    call ResolveSyscallNumber\n";
    resolver += "    pop r9\n";
    resolver += "    pop r8\n";
    resolver += "    pop rdx\n";
    resolver += "    pop rcx\n";
    resolver += "    ret\n";
    resolver += "GetSyscallNumber ENDP\n";
    return resolver;
}

QString IndirectObfuscation::generateObfuscatedHashTable() {
    return "HashTable PROC\n    ; Obfuscated hash table\n    ret\nHashTable ENDP\n";
}

QString IndirectObfuscation::generateObfuscatedFunctionPointers() {
    return "FunctionPointers PROC\n    ; Obfuscated function pointers\n    ret\nFunctionPointers ENDP\n";
}

QString IndirectObfuscation::generateJunkCodeForIndirect() {
    JunkGenerator junkGen(settings);
    return junkGen.generateJunkInstructions();
}

QString IndirectObfuscation::generateEncryptedSyscallNumbers() {
    return "EncryptedNumbers PROC\n    ; Encrypted syscall numbers\n    ret\nEncryptedNumbers ENDP\n";
}

QString IndirectObfuscation::obfuscateHashComputation(const QString& functionName) {
    return QString("    ; Obfuscated hash computation for %1\n").arg(functionName);
}

QString IndirectObfuscation::obfuscateFunctionPointerLookup(const QString& functionName) {
    return QString("    ; Obfuscated function pointer lookup for %1\n").arg(functionName);
}
