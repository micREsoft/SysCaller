#pragma once

#include <QSettings>
#include <QString>
#include <QStringList>

namespace IndirectObfuscation {

    class JunkGenerator {
    private:
        QSettings* settings;

    public:
        explicit JunkGenerator(QSettings* settings);

        QString generateRegisterSafeJunk();
    };

}