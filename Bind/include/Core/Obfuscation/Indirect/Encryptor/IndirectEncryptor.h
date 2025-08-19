#pragma once

#include <QString>
#include <QRandomGenerator>

namespace IndirectObfuscation {

    class Encryptor {
    public:
        static QString generateEncryptedSyscallNumbers();
    };
}
