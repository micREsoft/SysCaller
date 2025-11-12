#include <Core/Integrity/Integrity.h>
#include <Core/Utils/Common.h>
#include <GUI/Threads.h>

ValidatorThread::ValidatorThread(QObject* parent)
    : QThread(parent)
{}

void ValidatorThread::setDllPaths(const QStringList& paths)
{
    dllPaths = paths;
}

void ValidatorThread::run()
{
    qDebug() << "ValidatorThread::run() called";
    qDebug() << "DLL paths in thread:" << dllPaths;

    emit validationStarted();
    emit progressUpdated("Starting Validation Check...");

    try
    {
        qDebug() << "Creating Validator Instance...";

        Validator validator;
        validator.setOutputCallback([this](const QString& message)
        {
            emit progressUpdated(message);
        });

        emit progressUpdated("Processing NTDLL...");
        qDebug() << "Calling validator.runWithDllPaths()...";

        int result = validator.runWithDllPaths(dllPaths);

        if (result == 0)
        {
            emit progressUpdated("Validation Check Completed Successfully");
            emit validationFinished(true, "Validation Completed Successfully!");
        }
        else
        {
            emit progressUpdated("Validation Check Failed");
            emit validationFinished(false, "Validation failed with Error Code: " + QString::number(result));
        }
    }
    catch (const std::exception& e)
    {
        QString errorMsg = QString("Validation Error: %1").arg(e.what());
        emit progressUpdated("Validation Error Occurred");
        emit validationFinished(false, errorMsg);
    }
    catch (...)
    {
        emit progressUpdated("Unknown Validation Error Occurred");
        emit validationFinished(false, "Unknown Error occurred during Validation");
    }
}