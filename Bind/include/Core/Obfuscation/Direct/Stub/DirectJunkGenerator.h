#pragma once

#include <QString>
#include <QSettings>

namespace DirectObfuscation {
class JunkGenerator {
public:
    explicit JunkGenerator(QSettings* settings = nullptr);
    QString generateJunkInstructions(int minInst = -1, int maxInst = -1, bool useAdvanced = false);
    void setSettings(QSettings* settings);

private:
    QSettings* settings;
    QString getRandomJunkInstruction();
    QString getRandomAdvancedJunkInstruction();
    int getRandomInt(int min, int max);
}; 
}
