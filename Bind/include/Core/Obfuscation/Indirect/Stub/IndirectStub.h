#pragma once

#include <QString>
#include <QStringList>
#include <QSettings>
#include <functional>

namespace IndirectObfuscation {

    class Stub {
    private:
        QSettings* settings;

    public:
        explicit Stub(QSettings* settings);

        QString obfuscateResolverCall(const QString& originalCall);
    };
}
