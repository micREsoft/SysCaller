#pragma once

#include <QString>
#include <QMap>
#include <QVariant>
#include <QSettings>
#include <QPair>
#include <QStringList>

namespace DirectObfuscation {

    enum class EncryptionMethod {
        BasicXOR = 1,           /* simple XOR encryption */
        MultiKeyXOR = 2,        /* multi key XOR encryption */
        AddXORCombo = 3,        /* addition + XOR combination */
        EnhancedXOR = 4,        /* enhanced XOR with larger keys */
        OffsetShifting = 5      /* offset shifting/masking */
    };

    inline QString encryptionMethodToString(EncryptionMethod method) {
        switch (method) {
            case EncryptionMethod::BasicXOR: return "Basic XOR";
            case EncryptionMethod::MultiKeyXOR: return "Multi Key XOR";
            case EncryptionMethod::AddXORCombo: return "Add + XOR Combo";
            case EncryptionMethod::EnhancedXOR: return "Enhanced XOR";
            case EncryptionMethod::OffsetShifting: return "Offset Shifting";
            default: return "Unknown";
        }
    }

    inline EncryptionMethod stringToEncryptionMethod(const QString& str) {
        if (str.contains("basic", Qt::CaseInsensitive)) return EncryptionMethod::BasicXOR;
        if (str.contains("multi", Qt::CaseInsensitive)) return EncryptionMethod::MultiKeyXOR;
        if (str.contains("add", Qt::CaseInsensitive) || str.contains("combo", Qt::CaseInsensitive)) return EncryptionMethod::AddXORCombo;
        if (str.contains("enhanced", Qt::CaseInsensitive)) return EncryptionMethod::EnhancedXOR;
        if (str.contains("offset", Qt::CaseInsensitive) || str.contains("shifting", Qt::CaseInsensitive)) return EncryptionMethod::OffsetShifting;
        return EncryptionMethod::BasicXOR;
    }

    class Encryptor {
    private:
        QSettings* settings;

        int getRandomInt(int min, int max);

    public:
        explicit Encryptor(QSettings* settings = nullptr);

        DirectObfuscation::EncryptionMethod getEncryptionMethod();
        QPair<int, QMap<QString, QVariant>> encryptOffset(int realOffset, int method = -1);
        QStringList generateDecryptionSequence(const QString& offsetName,
                                               const QMap<QString, QVariant>& encryptionData,
                                               int method = -1);
        void setSettings(QSettings* settings);
    };

}
