#include "include/GUI/Threads/ObfuscationThread.h"
#include "include/Core/Obfuscation/Obfuscation.h"
#include "include/Core/Utils/PathUtils.h"
#include "include/Core/Utils/Utils.h"
#include <QDebug>
#include <QSettings>
#include <QDateTime>
#include <QFileInfo>

ObfuscationThread::ObfuscationThread(QObject* parent)
    : QThread(parent)
{}

void ObfuscationThread::setOutputCallback(std::function<void(const QString&)> callback)
{
    outputCallback = callback;
}

void ObfuscationThread::run()
{
    qDebug() << "ObfuscationThread::run() called";
    emit obfuscationStarted();
    emit progressUpdated("Starting Syscall Obfuscation...");

    try
    {
        qDebug() << "Creating Obfuscation Instance...";

        Obfuscation obfuscation;
        obfuscation.setOutputCallback([this](const QString& message)
        {
            emit progressUpdated(message);
        });

        emit progressUpdated("Processing Syscall List For Obfuscation...");
        qDebug() << "Calling obfuscation.run()...";

        int result = obfuscation.run();

        if (result == 0)
        {
            emit progressUpdated("Stubs & Exports Generated Successfully!");

            QSettings settings(PathUtils::getIniPath(), QSettings::IniFormat);
            bool hashStubsEnabled = settings.value("general/hash_stubs", false).toBool();

            if (hashStubsEnabled)
            {
                QString lastMethod = settings.value("obfuscation/last_method", "").toString();
                QString obfuscationType = (lastMethod == "stub_mapper") ? "Stub Mapper" : "Normal";

                emit progressUpdated(QString("Generating Stub Hashes for %1 Obfuscation...").arg(obfuscationType));

                try
                {
                    bool isKernelMode = settings.value("general/syscall_mode", "Nt").toString() == "Zw";
                    QString asmPath = PathUtils::getSysCallerAsmPath(isKernelMode);
                    QString headerPath = PathUtils::getSysFunctionsPath(isKernelMode);
                    QVariantMap stubHashes = StubHashGenerator::generateStubHashes(asmPath, headerPath, lastMethod);
                    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
                    QPair<bool, QString> saveResult = StubHashGenerator::saveStubHashes(stubHashes, timestamp);

                    if (saveResult.first)
                    {
                        QString fileName = QFileInfo(saveResult.second).fileName();
                        emit progressUpdated(QString("Stub Hashes Saved to: %1").arg(fileName));
                    }
                    else
                    {
                        emit progressUpdated(QString("Failed to save Stub Hashes: %1").arg(saveResult.second));
                    }
                }
                catch (const std::exception& e)
                {
                    emit progressUpdated(QString("Error Generating Stub Hashes: %1").arg(e.what()));
                }
                catch (...)
                {
                    emit progressUpdated("Unknown error occurred while generating Stub Hashes");
                }
            }

            emit obfuscationFinished(true, "Obfuscation Completed Successfully!");
        }
        else
        {
            emit progressUpdated("Obfuscation Failed With Error Code: " + QString::number(result));
            emit obfuscationFinished(false, "Obfuscation failed with Error Code: " + QString::number(result));
        }
    }
    catch (const std::exception& e)
    {
        QString errorMsg = QString("Obfuscation Error: %1").arg(e.what());
        emit progressUpdated("Obfuscation Error Occurred");
        emit obfuscationFinished(false, errorMsg);
    }
    catch (...)
    {
        emit progressUpdated("Unknown Obfuscation Error Occurred");
        emit obfuscationFinished(false, "Unknown Error occurred during Obfuscation");
    }
}