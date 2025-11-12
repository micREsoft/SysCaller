#include <Core/Utils/Common.h>
#include <GUI/Threads.h>

VerificationThread::VerificationThread(QObject* parent)
    : QThread(parent)
{}

void VerificationThread::setDllPaths(const QStringList& paths)
{
    dllPaths = paths;
}

void VerificationThread::setOutputCallback(std::function<void(const QString&)> callback)
{
    outputCallback = callback;
    verification.setOutputCallback([this](const QString& message)
    {
        emit progressUpdated(message);
    });
}

void VerificationThread::run()
{
    emit verificationStarted();

    try
    {
        int result = verification.runWithDllPaths(dllPaths);
        emit verificationFinished(result == 0, result == 0 ? "Verification Completed Successfully" : "Verification Failed");
    }
    catch (const std::exception& e)
    {
        qDebug() << "Verification Thread Exception:" << e.what();
        emit verificationFinished(false, QString("Verification Failed: %1").arg(e.what()));
    }
}