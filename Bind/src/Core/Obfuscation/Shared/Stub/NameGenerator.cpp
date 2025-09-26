#include "include/Core/Obfuscation/Shared/Stub/NameGenerator.h"
#include <QRandomGenerator>
#include <QDebug>
#include <QtMath>

SharedObfuscation::NameGenerator::NameGenerator(QSettings* settings)
    : settings(settings)
{}

void SharedObfuscation::NameGenerator::setSettings(QSettings* settings)
{
    this->settings = settings;
}

QString SharedObfuscation::NameGenerator::generateRandomString(int length)
{
    const QString chars = "abcdefghijklmnopqrstuvwxyz";
    QString result;

    for (int i = 0; i < length; ++i)
    {
        result += chars[getRandomInt(0, chars.length() - 1)];
    }

    return result;
}

QString SharedObfuscation::NameGenerator::generateRandomName(QSet<QString>& usedNames,
                                                             int prefixLength,
                                                             int numberLength)
{
    if (!settings)
    {
        return "";
    }

    if (prefixLength == -1)
    {
        prefixLength = settings->value("obfuscation/syscall_prefix_length", 8).toInt();
    }

    if (numberLength == -1)
    {
        numberLength = settings->value("obfuscation/syscall_number_length", 6).toInt();
    }

    QString name;

    do
    {
        QString prefix = generateRandomString(prefixLength);
        int minNumber = qPow(10, numberLength - 1);
        int maxNumber = qPow(10, numberLength) - 1;
        int number = getRandomInt(minNumber, maxNumber);
        name = QString("%1_%2").arg(prefix).arg(number);
    }
    while (usedNames.contains(name));

    usedNames.insert(name);
    return name;
}

QString SharedObfuscation::NameGenerator::generateRandomOffsetName(QSet<QString>& usedNames,
                                                                   int length)
{
    if (!settings)
    {
        return "";
    }

    if (length == -1)
    {
        length = settings->value("obfuscation/offset_name_length", 8).toInt();
    }

    QString name;

    do
    {
        name = generateRandomString(length);
    }
    while (usedNames.contains(name));

    usedNames.insert(name);
    return name;
}

int SharedObfuscation::NameGenerator::generateRandomOffset(QSet<int>& usedOffsets)
{
    int offset;

    do
    {
        offset = getRandomInt(0x1000, 0xFFFF);
    } while (usedOffsets.contains(offset));

    usedOffsets.insert(offset);
    return offset;
}

QString SharedObfuscation::NameGenerator::generateRandomLabel()
{
    return generateRandomString(8);
}

int SharedObfuscation::NameGenerator::getRandomInt(int min, int max)
{
    return QRandomGenerator::global()->bounded(min, max + 1);
}
