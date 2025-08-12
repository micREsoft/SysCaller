#pragma once

#include <QString>
#include <QMap>
#include <QVariant>
#include <QSettings>
#include <QPair>
#include <QStringList>

namespace DirectObfuscation {

    class Encryptor {
    private:
        QSettings* settings;

        int getRandomInt(int min, int max);

    public:
        explicit Encryptor(QSettings* settings = nullptr);

        int getEncryptionMethod();
        QPair<int, QMap<QString, QVariant>> encryptOffset(int realOffset, int method = -1);
        QStringList generateDecryptionSequence(const QString& offsetName,
                                               const QMap<QString, QVariant>& encryptionData,
                                               int method = -1);
        void setSettings(QSettings* settings);
    };

}
