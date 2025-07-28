#pragma once

#include <QString>
#include <QSet>
#include <QSettings>

class NameGenerator {
public:
    explicit NameGenerator(QSettings* settings = nullptr);
    QString generateRandomName(QSet<QString>& usedNames, int prefixLength = -1, int numberLength = -1);
    QString generateRandomOffsetName(QSet<QString>& usedNames, int length = -1);
    int generateRandomOffset(QSet<int>& usedOffsets);
    QString generateRandomLabel();
    void setSettings(QSettings* settings);

private:
    QSettings* settings;
    QString generateRandomString(int length = 8);
    int getRandomInt(int min, int max);
}; 