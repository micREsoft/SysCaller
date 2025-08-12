#include "include/Core/Obfuscation/Indirect/Stub/IndirectStub.h"
#include <QRandomGenerator>
#include <QMap>
#include <QStringList>

IndirectObfuscation::Stub::Stub(QSettings* settings)
    : settings(settings) {}

QString IndirectObfuscation::Stub::obfuscateResolverCall(const QString& originalCall) {
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
                       "    sub rsp, 16\n"
                       "    lea rax, [GetSyscallNumber]\n"
                       "    mov [rsp], rax\n"
                       "    call qword ptr [rsp]\n"
                       "    add rsp, 16";
            case 2:
                // Pattern 3: Stack scratch space indirect call
                return "    ; StackScratchIndirect\n"
                       "    lea rax, [GetSyscallNumber]\n"
                       "    mov [rsp-8], rax\n"
                       "    lea rax, [rsp-8]\n"
                       "    call qword ptr [rax]";
            case 3:
                /// Pattern 4: Register shuffle call via R10
                return "    ; RegShuffle_R10_Call\n"
                       "    push r10\n"
                       "    lea r10, [GetSyscallNumber]\n"
                       "    call r10\n"
                       "    pop r10";
        }
    }
    return originalCall;
}
