#include "include/Core/Obfuscation/Indirect/ControlFlow/IndirectControlFlow.h"
#include <QRandomGenerator>
#include <QMap>
#include <QStringList>

IndirectObfuscation::ControlFlow::ControlFlow(QSettings* settings)
    : settings(settings) {}

QString IndirectObfuscation::ControlFlow::generateControlFlowObfuscation() {
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
                .arg(QRandomGenerator::global()->bounded(1000, 999999)),
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
                .arg(QRandomGenerator::global()->bounded(1000, 999999)),
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
                .arg(QRandomGenerator::global()->bounded(1000, 999999)),
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
                .arg(QRandomGenerator::global()->bounded(1000, 999999))
    };
    return controlFlowPatterns[pattern];
}
