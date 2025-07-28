#include "include/Core/Obfuscation/Encryption/Encryptor.h"
#include <QRandomGenerator>
#include <QDebug>

Encryptor::Encryptor(QSettings* settings) : settings(settings) {
}

void Encryptor::setSettings(QSettings* settings) {
    this->settings = settings;
}

int Encryptor::getEncryptionMethod() {
    if (!settings) {
        return 1;
    }
    return settings->value("obfuscation/encryption_method", 1).toInt();
}

QPair<int, QMap<QString, QVariant>> Encryptor::encryptOffset(int realOffset, int method) {
    if (method == -1) {
        method = getEncryptionMethod();
    }
    QMap<QString, QVariant> encryptionData;
    int encryptedOffset;
    switch (method) {
        case 1: { // basic xor
            int key = getRandomInt(0x11, 0xFF);
            encryptedOffset = realOffset ^ key;
            encryptionData["key"] = key;
            break;
        }
        case 2: { // multi key xor
            int key1 = getRandomInt(0x11, 0xFF);
            int key2 = getRandomInt(0x11, 0xFF);
            encryptedOffset = (realOffset ^ key1) ^ key2;
            encryptionData["key1"] = key1;
            encryptionData["key2"] = key2;
            break;
        }
        case 3: { // add + xor combo
            int addVal = getRandomInt(0x100, 0xFFF);
            int xorKey = getRandomInt(0x11, 0xFF);
            encryptedOffset = (realOffset + addVal) ^ xorKey;
            encryptionData["add_val"] = addVal;
            encryptionData["xor_key"] = xorKey;
            break;
        }
        case 4: { // enhanced xor
            int xorKey = getRandomInt(0x1000, 0xFFFF);
            encryptedOffset = realOffset ^ xorKey;
            encryptionData["xor_key"] = xorKey;
            break;
        }
        case 5: { // offset shifting
            int mask = getRandomInt(0x100, 0xFFF);
            encryptedOffset = (realOffset + mask) & 0xFFFFFFFF;
            encryptionData["mask"] = mask;
            break;
        }
        default: { // default to basic xor
            int key = getRandomInt(0x11, 0xFF);
            encryptedOffset = realOffset ^ key;
            encryptionData["key"] = key;
            break;
        }
    }
    return qMakePair(encryptedOffset, encryptionData);
}

QStringList Encryptor::generateDecryptionSequence(const QString& offsetName, const QMap<QString, QVariant>& encryptionData, int method) {
    if (method == -1) {
        method = getEncryptionMethod();
    }
    QStringList sequence;
    switch (method) {
        case 1: { // basic xor
            int key = encryptionData["key"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(key, 0, 16);
            sequence << "    xor eax, ebx\n";
            break;
        }
        case 2: { // multi key xor
            int key1 = encryptionData["key1"].toInt();
            int key2 = encryptionData["key2"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(key1, 0, 16);
            sequence << "    xor eax, ebx\n";
            sequence << QString("    mov ebx, 0%1h\n").arg(key2, 0, 16);
            sequence << "    xor eax, ebx\n";
            break;
        }
        case 3: { // add + xor combo
            int xorKey = encryptionData["xor_key"].toInt();
            int addVal = encryptionData["add_val"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(xorKey, 0, 16);
            sequence << "    xor eax, ebx\n";
            sequence << QString("    sub eax, 0%1h\n").arg(addVal, 0, 16);
            break;
        }
        case 4: { // enhanced xor
            int xorKey = encryptionData["xor_key"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(xorKey, 0, 16);
            sequence << "    xor eax, ebx\n";
            break;
        }
        case 5: { // offset shifting
            int mask = encryptionData["mask"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    sub eax, 0%1h\n").arg(mask, 0, 16);
            break;
        }
        default: { // default to basic xor
            int key = encryptionData["key"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(key, 0, 16);
            sequence << "    xor eax, ebx\n";
            break;
        }
    }
    return sequence;
}

int Encryptor::getRandomInt(int min, int max) {
    return QRandomGenerator::global()->bounded(min, max + 1);
} 