#pragma once

#include <QSettings>
#include <QString>

namespace DirectObfuscation {

    class JunkGenerator {
    private:
        QSettings* settings;

    public:
        explicit JunkGenerator(QSettings* settings = nullptr);

        QString generateJunkInstructions(int minInst = -1, int maxInst = -1, bool useAdvanced = false);
        void setSettings(QSettings* settings);

    private:
        QString getRandomJunkInstruction();
        QString getRandomAdvancedJunkInstruction();
        int getRandomInt(int min, int max);
    };

}