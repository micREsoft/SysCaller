#include "include/Core/Obfuscation/Direct/Stub/StubGenerator.h"
#include "include/Core/Obfuscation/Direct/Stub/JunkGenerator.h"
#include "include/Core/Obfuscation/Direct/Encryption/Encryptor.h"
#include "include/Core/Obfuscation/Direct/Stub/NameGenerator.h"
#include <QRandomGenerator>
#include <QDebug>

StubGenerator::StubGenerator(QSettings* settings) : settings(settings) {
}

void StubGenerator::setSettings(QSettings* settings) {
    this->settings = settings;
}

QString StubGenerator::generateMaskedSequence(const QString& offsetName, const QMap<QString, QVariant>& encryptionData, int method) {
    if (!settings) {
        return "";
    }
    JunkGenerator junkGen(settings);
    Encryptor encryptor(settings);
    bool enableEncryption = settings->value("obfuscation/enable_encryption", true).toBool();
    QStringList movR10RcxVariants = {
        "    lea r10, [rcx]\n",
        "    push rcx\n    pop r10\n",
        "    mov r11, rcx\n    xchg r10, r11\n"
    };
    QStringList syscallSequence;
    if (enableEncryption && !encryptionData.isEmpty()) {
        syscallSequence = encryptor.generateDecryptionSequence(offsetName, encryptionData, method);
    } else {
        QStringList movEaxOffsetVariants = {
            QString("    xor eax, eax\n    add eax, dword ptr [%1]\n").arg(offsetName),
            QString("    mov ebx, dword ptr [%1]\n    xchg eax, ebx\n").arg(offsetName)
        };
        syscallSequence << movEaxOffsetVariants[getRandomInt(0, movEaxOffsetVariants.size() - 1)];
    }
    QStringList syscallVariants = {
        "    syscall\n"
    };
    QStringList sequence = {
        movR10RcxVariants[getRandomInt(0, movR10RcxVariants.size() - 1)],
        junkGen.generateJunkInstructions(),
        syscallSequence.join(""),
        junkGen.generateJunkInstructions(),
        syscallVariants[getRandomInt(0, syscallVariants.size() - 1)],
        "    ret"
    };
    return sequence.join("");
}

QString StubGenerator::generateChunkedSequence(const QString& offsetName, const QMap<QString, QVariant>& encryptionData, int method) {
    if (!settings) {
        return "";
    }
    bool enableChunking = settings->value("obfuscation/enable_chunking", true).toBool();
    if (!enableChunking) {
        return generateMaskedSequence(offsetName, encryptionData, method);
    }
    JunkGenerator junkGen(settings);
    Encryptor encryptor(settings);
    NameGenerator nameGen(settings);
    bool enableEncryption = settings->value("obfuscation/enable_encryption", true).toBool();
    QSet<QString> usedLabels;
    QString entryLabel = nameGen.generateRandomLabel();
    QString middleLabel = nameGen.generateRandomLabel();
    QString exitLabel = nameGen.generateRandomLabel();
    QStringList syscallSequence;
    if (enableEncryption && !encryptionData.isEmpty()) {
        syscallSequence = encryptor.generateDecryptionSequence(offsetName, encryptionData, method);
    } else {
        syscallSequence << QString("    xor eax, eax\n    add eax, dword ptr [%1]\n").arg(offsetName);
    }
    QStringList chunks = {
        QString("%1:\n"
                "    mov r10, rcx\n"
                "    %2"
                "    jmp %3\n").arg(entryLabel).arg(junkGen.generateJunkInstructions()).arg(middleLabel),
        QString("%1:\n"
                "%2"
                "    %3"
                "    jmp %4\n").arg(middleLabel).arg(syscallSequence.join("")).arg(junkGen.generateJunkInstructions()).arg(exitLabel),
        QString("%1:\n"
                "    syscall\n"
                "    %2"
                "    ret\n").arg(exitLabel).arg(junkGen.generateJunkInstructions())
    };
    QString entry = chunks[0];
    QStringList rest = chunks.mid(1);
    for (int i = rest.size() - 1; i > 0; --i) {
        int j = getRandomInt(0, i);
        rest.swapItemsAt(i, j);
    }
    chunks = QStringList() << entry << rest;
    return chunks.join("");
}

QString StubGenerator::generateAlignPadding() {
    JunkGenerator junkGen(settings);
    NameGenerator nameGen(settings);
    int alignSize = QList<int>{4, 8, 16}[getRandomInt(0, 2)];
    QStringList padding;
    int paddingCount = getRandomInt(1, 3);
    for (int i = 0; i < paddingCount; ++i) {
        padding << junkGen.generateJunkInstructions();
    }
    padding << QString("ALIGN %1").arg(alignSize);
    return padding.join("");
}

int StubGenerator::getRandomInt(int min, int max) {
    return QRandomGenerator::global()->bounded(min, max + 1);
} 