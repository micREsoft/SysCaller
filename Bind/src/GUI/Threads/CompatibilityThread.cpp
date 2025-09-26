#include "include/GUI/Threads/CompatibilityThread.h"
#include "include/Core/Integrity/Compatibility/Compatibility.h"
#include <QProcessEnvironment>
#include <QDebug>

CompatibilityThread::CompatibilityThread(QObject* parent)
    : QThread(parent)
{}

void CompatibilityThread::setDllPaths(const QStringList& paths)
{
    dllPaths = paths;
}

void CompatibilityThread::run()
{
    qDebug() << "CompatibilityThread::run() called";
    qDebug() << "DLL paths in thread:" << dllPaths;

    emit compatibilityStarted();
    emit progressUpdated("Starting Compatibility Check...");

    try
    {
        qDebug() << "Creating Compatibility instance...";

        Compatibility compatibility;
        compatibility.setOutputCallback([this](const QString& message)
        {
            emit progressUpdated(message);
        });

        emit progressUpdated("Processing NTDLL...");
        qDebug() << "Calling compatibility.runWithDllPaths()...";

        int result = compatibility.runWithDllPaths(dllPaths);

        if (result == 0)
        {
            emit progressUpdated("Compatibility Check Completed Successfully");
            emit compatibilityFinished(true, "Compatibility Check Completed Successfully!");
        }
        else
        {
            emit progressUpdated("Compatibility Check Failed");
            emit compatibilityFinished(false, "Compatibility Check failed with Error Code: " + QString::number(result));
        }
    }
    catch (const std::exception& e)
    {
        QString errorMsg = QString("Compatibility Error: %1").arg(e.what());
        emit progressUpdated("Compatibility Error Occurred");
        emit compatibilityFinished(false, errorMsg);
    }
    catch (...)
    {
        emit progressUpdated("Unknown Compatibility Error Occurred");
        emit compatibilityFinished(false, "Unknown Error occurred during Compatibility Check");
    }
}