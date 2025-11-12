#pragma once

#include <QMap>
#include <QSettings>
#include <QString>
#include <QStringList>
#include <QVariant>

namespace DirectObfuscation {

    class StubGenerator {
    private:
        QSettings* settings;

    public:
        explicit StubGenerator(QSettings* settings = nullptr);

        QString generateMaskedSequence(
            const QString& offsetName,
            const QMap<QString, QVariant>& encryptionData = QMap<QString, QVariant>(),
            int method = -1
        );

        QString generateChunkedSequence(
            const QString& offsetName,
            const QMap<QString, QVariant>& encryptionData = QMap<QString, QVariant>(),
            int method = -1
        );

        QString generateAlignPadding();
        void setSettings(QSettings* settings);

    private:
        int getRandomInt(int min, int max);
    };

}