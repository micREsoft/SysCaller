#include "include/Core/Obfuscation/Direct/Encryption/DirectEncryptor.h"
#include <QRandomGenerator>
#include <QDebug>

DirectObfuscation::Encryptor::Encryptor(QSettings* settings)
    : settings(settings)
{}

void DirectObfuscation::Encryptor::setSettings(QSettings* settings)
{
    this->settings = settings;
}

DirectObfuscation::EncryptionMethod DirectObfuscation::Encryptor::getEncryptionMethod()
{
    if (!settings)
    {
        return DirectObfuscation::EncryptionMethod::BasicXOR;
    }

    int methodValue = settings->value("obfuscation/encryption_method", static_cast<int>(DirectObfuscation::EncryptionMethod::BasicXOR)).toInt();
    return static_cast<DirectObfuscation::EncryptionMethod>(methodValue);
}

QPair<int, QMap<QString, QVariant>> DirectObfuscation::Encryptor::encryptOffset(int realOffset, int method)
{
    DirectObfuscation::EncryptionMethod encryptionMethod = DirectObfuscation::EncryptionMethod::BasicXOR;

    if (method == -1)
    {
        encryptionMethod = getEncryptionMethod();
    }
    else
    {
        encryptionMethod = static_cast<DirectObfuscation::EncryptionMethod>(method);
    }

    QMap<QString, QVariant> encryptionData;
    int encryptedOffset;

    switch (encryptionMethod)
    {
        case DirectObfuscation::EncryptionMethod::BasicXOR:
        {
            int key = getRandomInt(0x11, 0xFF);
            encryptedOffset = realOffset ^ key;
            encryptionData["key"] = key;
            break;
        }
        case DirectObfuscation::EncryptionMethod::MultiKeyXOR:
        {
            int key1 = getRandomInt(0x11, 0xFF);
            int key2 = getRandomInt(0x11, 0xFF);
            encryptedOffset = (realOffset ^ key1) ^ key2;
            encryptionData["key1"] = key1;
            encryptionData["key2"] = key2;
            break;
        }
        case DirectObfuscation::EncryptionMethod::AddXORCombo:
        {
            int addVal = getRandomInt(0x100, 0xFFF);
            int xorKey = getRandomInt(0x11, 0xFF);
            encryptedOffset = (realOffset + addVal) ^ xorKey;
            encryptionData["add_val"] = addVal;
            encryptionData["xor_key"] = xorKey;
            break;
        }
        case DirectObfuscation::EncryptionMethod::EnhancedXOR:
        {
            int xorKey = getRandomInt(0x1000, 0xFFFF);
            encryptedOffset = realOffset ^ xorKey;
            encryptionData["xor_key"] = xorKey;
            break;
        }
        case DirectObfuscation::EncryptionMethod::OffsetShifting:
        {
            int mask = getRandomInt(0x100, 0xFFF);
            encryptedOffset = (realOffset + mask) & 0xFFFFFFFF;
            encryptionData["mask"] = mask;
            break;
        }
        default: /* default to basic xor */
        {
            int key = getRandomInt(0x11, 0xFF);
            encryptedOffset = realOffset ^ key;
            encryptionData["key"] = key;
            break;
        }
    }

    return qMakePair(encryptedOffset, encryptionData);
}

QStringList DirectObfuscation::Encryptor::generateDecryptionSequence(const QString& offsetName,
                                                                     const QMap<QString, QVariant>& encryptionData,
                                                                     int method)
{
    DirectObfuscation::EncryptionMethod decryptionMethod = DirectObfuscation::EncryptionMethod::BasicXOR;

    if (method == -1)
    {
        decryptionMethod = getEncryptionMethod();
    }
    else
    {
        decryptionMethod = static_cast<DirectObfuscation::EncryptionMethod>(method);
    }

    QStringList sequence;

    switch (decryptionMethod)
    {
        case DirectObfuscation::EncryptionMethod::BasicXOR:
        {
            int key = encryptionData["key"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(key, 0, 16);
            sequence << "    xor eax, ebx\n";
            break;
        }
        case DirectObfuscation::EncryptionMethod::MultiKeyXOR:
        {
            int key1 = encryptionData["key1"].toInt();
            int key2 = encryptionData["key2"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(key1, 0, 16);
            sequence << "    xor eax, ebx\n";
            sequence << QString("    mov ebx, 0%1h\n").arg(key2, 0, 16);
            sequence << "    xor eax, ebx\n";
            break;
        }
        case DirectObfuscation::EncryptionMethod::AddXORCombo:
        {
            int xorKey = encryptionData["xor_key"].toInt();
            int addVal = encryptionData["add_val"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(xorKey, 0, 16);
            sequence << "    xor eax, ebx\n";
            sequence << QString("    sub eax, 0%1h\n").arg(addVal, 0, 16);
            break;
        }
        case DirectObfuscation::EncryptionMethod::EnhancedXOR:
        {
            int xorKey = encryptionData["xor_key"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(xorKey, 0, 16);
            sequence << "    xor eax, ebx\n";
            break;
        }
        case DirectObfuscation::EncryptionMethod::OffsetShifting:
        {
            int mask = encryptionData["mask"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    sub eax, 0%1h\n").arg(mask, 0, 16);
            break;
        }
        default: /* default to basic xor */
        {
            int key = encryptionData["key"].toInt();
            sequence << QString("    mov eax, dword ptr [%1]\n").arg(offsetName);
            sequence << QString("    mov ebx, 0%1h\n").arg(key, 0, 16);
            sequence << "    xor eax, ebx\n";
            break;
        }
    }

    return sequence;
}

int DirectObfuscation::Encryptor::getRandomInt(int min, int max)
{
    return QRandomGenerator::global()->bounded(min, max + 1);
}
