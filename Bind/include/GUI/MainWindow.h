#pragma once
#include <QMainWindow>
#include <QPoint>

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
    explicit MainWindow(QWidget *parent = nullptr);
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

private:
    void saveAllSettings();

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
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