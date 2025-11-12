#pragma once

#include <QProcessEnvironment>
#include <QStringList>
#include <QThread>

class ValidatorThread : public QThread {
    Q_OBJECT

public:
    explicit ValidatorThread(QObject* parent = nullptr);
    void setDllPaths(const QStringList& paths);

signals:
    void validationStarted();
    void validationFinished(bool success, const QString& message);
    void progressUpdated(const QString& status);

protected:
    void run() override;

private:
    QStringList dllPaths;
};