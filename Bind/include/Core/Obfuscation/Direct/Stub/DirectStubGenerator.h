#pragma once

#include <QString>
#include <QStringList>
#include <QMap>
#include <QVariant>
#include <QSettings>

namespace DirectObfuscation {
class StubGenerator {
public:
    explicit StubGenerator(QSettings* settings = nullptr);
    QString generateMaskedSequence(const QString& offsetName, const QMap<QString, QVariant>& encryptionData = QMap<QString, QVariant>(), int method = -1);
    QString generateChunkedSequence(const QString& offsetName, const QMap<QString, QVariant>& encryptionData = QMap<QString, QVariant>(), int method = -1);
    QString generateAlignPadding();
    void setSettings(QSettings* settings);

private:
    QSettings* settings;
    int getRandomInt(int min, int max);
};
}
