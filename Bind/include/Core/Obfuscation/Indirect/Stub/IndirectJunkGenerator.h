#pragma once

#include <QString>
#include <QStringList>
#include <QSettings>

namespace IndirectObfuscation {

    class JunkGenerator {
    private:
        QSettings* settings;

    public:
        explicit JunkGenerator(QSettings* settings);

        QString generateRegisterSafeJunk();
    };

}