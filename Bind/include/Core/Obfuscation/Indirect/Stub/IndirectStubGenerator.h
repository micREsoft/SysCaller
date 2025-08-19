#pragma once

#include <QString>
#include <QStringList>
#include <QSettings>
#include <functional>

namespace IndirectObfuscation {

    class StubGenerator {
    private:
        QSettings* settings;

    public:
        explicit StubGenerator(QSettings* settings);

        QString obfuscateResolverCall(const QString& originalCall);
    };

}