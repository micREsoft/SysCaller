#pragma once

#include <QSettings>
#include <QString>
#include <QStringList>
#include <QRandomGenerator>
#include <QMap>

namespace IndirectObfuscation {

    class ControlFlow {
    private:
        QSettings* settings;

    public:
        explicit ControlFlow(QSettings* settings);

        QString generateControlFlowObfuscation();
    };
}
