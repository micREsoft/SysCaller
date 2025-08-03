#include "include/Core/Obfuscation/Direct/ControlFlow/ControlFlow.h"
#include <QRandomGenerator>
#include <QDebug>

ControlFlow::ControlFlow(QSettings* settings) : settings(settings) {
}

void ControlFlow::setSettings(QSettings* settings) {
    this->settings = settings;
}

QString ControlFlow::generateRandomLabel(const QString& prefix) {
    QString label;
    do {
        QString suffix = QString::number(getRandomInt(100000, 999999));
        label = prefix + suffix;
    } while (usedLabels.contains(label));
    usedLabels.insert(label);
    return label;
}

QStringList ControlFlow::generateOpaquePredicates(const QString& labelPrefix) {
    if (!settings || !isOpaquePredicatesEnabled()) {
        return QStringList();
    }
    QStringList predicates;
    int complexity = getControlFlowComplexity();
    for (int i = 0; i < complexity; ++i) {
        QString label = generateRandomLabel(labelPrefix);
        QString endLabel = generateRandomLabel(labelPrefix);
        QStringList predicate = generateComplexPredicate();
        predicates << QString("%1:").arg(label);
        predicates << predicate;
        predicates << QString("    jmp %1").arg(endLabel);
        predicates << QString("%1:").arg(endLabel);
    }
    return predicates;
}

QStringList ControlFlow::generateBogusControlFlow(const QString& labelPrefix) {
    if (!settings || !isBogusControlFlowEnabled()) {
        return QStringList();
    }
    QStringList bogusFlow;
    int complexity = getControlFlowComplexity();
    for (int i = 0; i < complexity; ++i) {
        QString label1 = generateRandomLabel(labelPrefix);
        QString label2 = generateRandomLabel(labelPrefix);
        QString reg = getRandomRegister();
        bogusFlow << QString("    mov %1, 1").arg(reg);
        bogusFlow << QString("    test %1, %1").arg(reg);
        bogusFlow << QString("    jnz %1").arg(label1);
        bogusFlow << QString("    jmp %2").arg(label2);
        bogusFlow << QString("%1:").arg(label1);
        bogusFlow << QString("    nop");
        bogusFlow << QString("    jmp %2").arg(label2);
        bogusFlow << QString("%2:").arg(label2);
    }
    return bogusFlow;
}

QStringList ControlFlow::generateIndirectJumps(const QString& labelPrefix) {
    if (!settings || !isIndirectJumpsEnabled()) {
        return QStringList();
    }
    QStringList indirectJumps;
    int complexity = getControlFlowComplexity();
    for (int i = 0; i < complexity; ++i) {
        QString targetLabel = generateRandomLabel(labelPrefix);
        QString tempReg = getRandomRegister();
        indirectJumps << QString("    lea %1, %2").arg(tempReg).arg(targetLabel);
        indirectJumps << QString("    jmp %1").arg(tempReg);
        indirectJumps << QString("%1:").arg(targetLabel);
    }
    return indirectJumps;
}

QStringList ControlFlow::generateConditionalBranches(const QString& labelPrefix) {
    if (!settings || !isConditionalBranchesEnabled()) {
        return QStringList();
    }
    QStringList branches;
    int complexity = getControlFlowComplexity();
    for (int i = 0; i < complexity; ++i) {
        QString trueLabel = generateRandomLabel(labelPrefix);
        QString falseLabel = generateRandomLabel(labelPrefix);
        QString endLabel = generateRandomLabel(labelPrefix);
        branches << generateAlwaysTrueCondition();
        branches << QString("    jnz %1").arg(trueLabel);
        branches << QString("    jmp %2").arg(falseLabel);
        branches << QString("%1:").arg(trueLabel);
        branches << QString("    nop");
        branches << QString("    jmp %3").arg(endLabel);
        branches << QString("%2:").arg(falseLabel);
        branches << QString("    nop");
        branches << QString("    jmp %3").arg(endLabel);
        branches << QString("%3:").arg(endLabel);
    }
    return branches;
}

QStringList ControlFlow::wrapWithControlFlow(const QStringList& originalCode, const QString& labelPrefix) {
    if (!settings) {
        return originalCode;
    }
    QStringList obfuscatedCode;
    if (isOpaquePredicatesEnabled()) {
        obfuscatedCode << generateOpaquePredicates(labelPrefix);
    }
    if (isBogusControlFlowEnabled()) {
        obfuscatedCode << generateBogusControlFlow(labelPrefix);
    }
    obfuscatedCode << originalCode;
    if (isIndirectJumpsEnabled()) {
        obfuscatedCode << generateIndirectJumps(labelPrefix);
    }
    if (isConditionalBranchesEnabled()) {
        obfuscatedCode << generateConditionalBranches(labelPrefix);
    }
    return obfuscatedCode;
}

bool ControlFlow::isOpaquePredicatesEnabled() {
    return settings ? settings->value("obfuscation/control_flow_opaque_predicates", false).toBool() : false;
}

bool ControlFlow::isBogusControlFlowEnabled() {
    return settings ? settings->value("obfuscation/control_flow_bogus_flow", false).toBool() : false;
}

bool ControlFlow::isIndirectJumpsEnabled() {
    return settings ? settings->value("obfuscation/control_flow_indirect_jumps", false).toBool() : false;
}

bool ControlFlow::isConditionalBranchesEnabled() {
    return settings ? settings->value("obfuscation/control_flow_conditional_branches", false).toBool() : false;
}

int ControlFlow::getControlFlowComplexity() {
    return settings ? settings->value("obfuscation/control_flow_complexity", 2).toInt() : 2;
}

int ControlFlow::getRandomInt(int min, int max) {
    return QRandomGenerator::global()->bounded(min, max + 1);
}

QString ControlFlow::getRandomRegister() {
    QStringList registers = {"rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    return registers[getRandomInt(0, registers.size() - 1)];
}

QString ControlFlow::getRandomCondition() {
    QStringList conditions = {"test", "cmp", "and", "or", "xor"};
    return conditions[getRandomInt(0, conditions.size() - 1)];
}

QStringList ControlFlow::generateAlwaysTrueCondition() {
    QStringList conditions;
    QString reg = getRandomRegister();    
    conditions << QString("    mov %1, 1").arg(reg);
    conditions << QString("    test %1, %1").arg(reg);
    return conditions;
}

QStringList ControlFlow::generateAlwaysFalseCondition() {
    QStringList conditions;
    QString reg = getRandomRegister();
    conditions << QString("    mov %1, 0").arg(reg);
    conditions << QString("    test %1, %1").arg(reg);
    return conditions;
}

QStringList ControlFlow::generateComplexPredicate() {
    QStringList predicate;
    QString reg1 = getRandomRegister();
    QString reg2 = getRandomRegister();
    predicate << QString("    mov %1, 1").arg(reg1);
    predicate << QString("    mov %2, 2").arg(reg2);
    predicate << QString("    add %1, %2").arg(reg1).arg(reg2);
    predicate << QString("    sub %1, 2").arg(reg1);
    predicate << QString("    test %1, %1").arg(reg1);
    return predicate;
} 
