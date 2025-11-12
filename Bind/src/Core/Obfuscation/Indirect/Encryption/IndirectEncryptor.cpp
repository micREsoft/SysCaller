#include <Core/Obfuscation/Indirect/Indirect.h>
#include <Core/Utils/QtDependencies.h>

QString IndirectObfuscation::Encryptor::generateEncryptedSyscallNumbers()
{
    QString encryptedCode;
    int encryptionKey = QRandomGenerator::global()->bounded(1, 256);
    QString khex = QString::number(encryptionKey, 16).toUpper();

    if (khex.length() < 2)
    {
        khex.prepend('0');
    }

    int offset = QRandomGenerator::global()->bounded(8, 32);

    encryptedCode = QString("    ; Encrypted syscall number handling\n"
                           "    ; Key: 0%1h\n"
                           "    mov rax, [rsp+%2]\n"
                           "    xor rax, 0%1h\n"
                           "    mov [rsp+%2], rax\n")
                           .arg(khex)
                           .arg(offset);

    return encryptedCode;
}