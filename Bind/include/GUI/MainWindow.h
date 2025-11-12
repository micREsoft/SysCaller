#pragma once

#include <QDebug>
#include <QMainWindow>
#include <QPoint>
#include <QThread>
#include <Core/Utils/Constants.h>

class TitleBar;
class LeftPanel;
class RightPanel;
class StatusBar;
class ValidatorThread;
class CompatibilityThread;
class VerificationThread;
class ObfuscationThread;
class OutputPanel;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void showSettings();
    void runValidation();
    void runCompatibility();
    void runVerification();
    void runObfuscation();
    void minimizeWindow();
    void toggleMaximize();
    void closeWindow();

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
    void saveAllSettings();
    void cleanupThread(QThread*& thread);
    template<typename ThreadType>
    void cleanupThreadHelper(ThreadType*& thread)
    {
        if (!thread)
        {
            return;
        }

        QThread* qthread = static_cast<QThread*>(thread);
        if (qthread->isRunning())
        {
            qthread->requestInterruption();
            qthread->quit();
            
            if (!qthread->wait(Constants::THREAD_TERMINATION_TIMEOUT_MS))
            {
                qWarning() << "Thread did not terminate in time, forcing termination";
                qthread->terminate();
                qthread->wait(Constants::THREAD_FORCE_TERMINATION_TIMEOUT_MS);
            }
        }

        qthread->deleteLater();
        thread = nullptr;
    }
    bool validateDllPaths(const QStringList& paths, QString& errorMessage);

    TitleBar* titleBar;
    LeftPanel* leftPanel;
    RightPanel* rightPanel;
    StatusBar* statusBar;
    QPoint dragPos;
    ValidatorThread* validatorThread;
    CompatibilityThread* compatibilityThread;
    VerificationThread* verificationThread;
    ObfuscationThread* obfuscationThread;
};