#pragma once

#include <QThread>
#include <QStringList>
#include <QProcessEnvironment>

class CompatibilityThread : public QThread {
    Q_OBJECT

public:
    explicit CompatibilityThread(QObject* parent = nullptr);
    void setDllPaths(const QStringList& paths);

signals:
    void compatibilityStarted();
    void compatibilityFinished(bool success, const QString& message);
    void progressUpdated(const QString& status);

protected:
    void run() override;

private:
    QStringList dllPaths;
    void setEnvironmentVariables();
}; 