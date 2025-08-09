#include "include/Core/Obfuscation/Indirect/IndirectObfuscation.h"
#include <QRandomGenerator>
#include <QMap>
#include <QStringList>

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

QString IndirectObfuscation::generateRegisterSafeJunk() {
    // rcx, rdx, r8, r9 are function parameters, NEVER touch these!
    // rbx, rsi, rdi, r12 are used to save rcx, rdx, r8, r9, NEVER touch these!
    // r10 is used for function pointer, NEVER touch this!
    // so we can ONLY safely use: r11, r13, r14, r15, rax
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
    int minJ = settings->value("obfuscation/indirect_min_instructions", 2).toInt();
    int maxJ = settings->value("obfuscation/indirect_max_instructions", 8).toInt();
    if (minJ < 1) minJ = 1;
    if (maxJ < minJ) maxJ = minJ;
    numInstructions = QRandomGenerator::global()->bounded(minJ, maxJ + 1);
    QString junkCode;
    for (int i = 0; i < numInstructions; ++i) {
        int index = QRandomGenerator::global()->bounded(safeJunkInstructions.size());
        junkCode += safeJunkInstructions[index];
    }
    return junkCode;
}
