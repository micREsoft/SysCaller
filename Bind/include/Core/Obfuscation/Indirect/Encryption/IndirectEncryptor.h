#pragma once

#include <QRandomGenerator>
#include <QString>

namespace IndirectObfuscation {

    class Encryptor {
    public:
        static QString generateEncryptedSyscallNumbers();
    };

}