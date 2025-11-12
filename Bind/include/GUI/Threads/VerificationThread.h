#pragma once

#include <QObject>
#include <QStringList>
#include <QThread>
#include <Core/Integrity/Integrity.h>
#include <Core/Utils/Dependencies.h>

class VerificationThread : public QThread {
    Q_OBJECT

public:
    explicit VerificationThread(QObject* parent = nullptr);

    void setDllPaths(const QStringList& paths);
    void setOutputCallback(std::function<void(const QString&)> callback);

signals:
    void verificationStarted();
    void verificationFinished(bool success, const QString& message);
    void progressUpdated(const QString& status);

protected:
    void run() override;

private:
    QStringList dllPaths;
    std::function<void(const QString&)> outputCallback;
    Verification verification;
};