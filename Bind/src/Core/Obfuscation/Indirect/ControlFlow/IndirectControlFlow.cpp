#include <Core/Obfuscation/Indirect/Indirect.h>
#include <Core/Utils/QtDependencies.h>

IndirectObfuscation::ControlFlow::ControlFlow(QSettings* settings)
    : settings(settings)
{}

QString IndirectObfuscation::ControlFlow::generateControlFlowObfuscation()
{
    QString method = settings->value("obfuscation/indirect_control_flow_method", "random").toString();

    ControlFlowPattern flowPattern;

    if (method == "random")
    {
        int randomValue = QRandomGenerator::global()->bounded(4);
        flowPattern = static_cast<ControlFlowPattern>(randomValue);
    }
    else
    {
        flowPattern = stringToControlFlowPattern(method);
    }

    QStringList controlFlowPatterns = {
        QString("    ; Opaque Predicate - Register Based\n"
                "    test r11, r11\n"           /* r11 is always 0, so test sets ZF=1 */
                "    jnz fake_branch_%1\n"      /* never taken (ZF=1, so jnz fails) */
                "    ; Real code continues here\n"
                "    jmp real_code_%1\n"
                "fake_branch_%1:\n"
                "    nop\n"                      /* dead code */
                "    xor r13, r13\n"            /* dead code */
                "    add r14, 0\n"              /* dead code */
                "real_code_%1:\n")
                .arg(QRandomGenerator::global()->bounded(1000, 999999)),

        QString("    ; Opaque Predicate - Value Based\n"
                "    mov r15, 0\n"              /* set r15 to 0 */
                "    cmp r15, 1\n"              /* compare 0 with 1 (always false) */
                "    je fake_branch_%1\n"       /* never taken */
                "    ; Real code continues here\n"
                "    jmp real_code_%1\n"
                "fake_branch_%1:\n"
                "    push r11\n"                /* dead code */
                "    pop r11\n"                 /* dead code */
                "    test r13, r13\n"           /* dead code */
                "real_code_%1:\n")
                .arg(QRandomGenerator::global()->bounded(1000, 999999)),

        QString("    ; Opaque Predicate - Flag Based\n"
                "    clc\n"                     /* clear carry flag */
                "    jc fake_branch_%1\n"       /* never taken (CF=0) */
                "    ; Real code continues here\n"
                "    jmp real_code_%1\n"
                "fake_branch_%1:\n"
                "    lea r11, [r11]\n"         /* dead code */
                "    mov r13, r13\n"            /* dead code */
                "    xchg r14, r14\n"          /* dead code */
                "real_code_%1:\n")
                .arg(QRandomGenerator::global()->bounded(1000, 999999)),

        QString("    ; Opaque Predicate - Mixed Junk Code\n"
                "    xor r11, r11\n"            /* r11 = 0 */
                "    or r11, 0\n"               /* r11 still = 0 */
                "    test r11, r11\n"           /* test 0 (always zero) */
                "    jnz fake_branch_%1\n"      /* never taken */
                "    ; Real code continues here\n"
                "    jmp real_code_%1\n"
                "fake_branch_%1:\n"
                "    pushfq\n"                  /* dead code */
                "    popfq\n"                   /* dead code */
                "    fnop\n"                    /* dead code */
                "    pause\n"                   /* dead code */
                "real_code_%1:\n")
                .arg(QRandomGenerator::global()->bounded(1000, 999999))
    };

    return controlFlowPatterns[static_cast<int>(flowPattern)];
}