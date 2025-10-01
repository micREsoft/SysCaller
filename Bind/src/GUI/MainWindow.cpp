#include "include/GUI/MainWindow.h"
#include "include/GUI/Bars/TitleBar.h"
#include "include/GUI/Panels/LeftPanel.h"
#include "include/GUI/Panels/RightPanel.h"
#include "include/GUI/Panels/OutputPanel.h"
#include "include/GUI/Bars/StatusBar.h"
#include "include/GUI/Dialogs/SettingsDialog.h"
#include "include/GUI/Threads/ValidatorThread.h"
#include "include/GUI/Threads/CompatibilityThread.h"
#include "include/GUI/Threads/VerificationThread.h"
#include "include/GUI/Threads/ObfuscationThread.h"
#include "include/Core/Utils/PathUtils.h"
#include "include/GUI/Dialogs/ObfuscationSelectionDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QMouseEvent>
#include <QApplication>
#include <QFontDatabase>
#include <QStyleFactory>
#include <QCloseEvent>
#include <QMessageBox>
#include <QSettings>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , dragPos(0, 0)
    , validatorThread(nullptr)
    , compatibilityThread(nullptr)
    , verificationThread(nullptr)
    , obfuscationThread(nullptr)
{
    setWindowTitle("Bind - v1.3.2");
    setMinimumSize(1400, 900);
    setWindowFlags(Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);

    auto* central = new QWidget();
    central->setStyleSheet(
        "QWidget {"
        " background: #1A1A1A;"
        " border-radius: 15px;"
        "}"
    );

    setCentralWidget(central);

    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    titleBar = new TitleBar(this);
    mainLayout->addWidget(titleBar);

    auto* contentLayout = new QHBoxLayout();
    contentLayout->setContentsMargins(20, 20, 20, 20);
    contentLayout->setSpacing(20);
    mainLayout->addLayout(contentLayout);

    leftPanel = new LeftPanel(this);
    contentLayout->addWidget(leftPanel);

    rightPanel = new RightPanel(this);
    contentLayout->addWidget(rightPanel, 2);

    statusBar = new StatusBar();
    mainLayout->addWidget(statusBar);

    connect(leftPanel, &LeftPanel::settingsButtonClicked, this, &MainWindow::showSettings);
    connect(leftPanel, &LeftPanel::validationButtonClicked, this, &MainWindow::runValidation);
    connect(leftPanel, &LeftPanel::compatibilityButtonClicked, this, &MainWindow::runCompatibility);
    connect(leftPanel, &LeftPanel::verificationButtonClicked, this, &MainWindow::runVerification);
    connect(leftPanel, &LeftPanel::obfuscationButtonClicked, this, &MainWindow::runObfuscation);

    PathUtils::debugPathDetection();

    connect(titleBar, &TitleBar::minimizeClicked, this, &MainWindow::minimizeWindow);
    connect(titleBar, &TitleBar::maximizeClicked, this, &MainWindow::toggleMaximize);
    connect(titleBar, &TitleBar::closeClicked, this, &MainWindow::closeWindow);
}

MainWindow::~MainWindow()
{
    if (validatorThread)
    {
        validatorThread->quit();
        validatorThread->wait();
        delete validatorThread;
    }

    if (compatibilityThread)
    {
        compatibilityThread->quit();
        compatibilityThread->wait();
        delete compatibilityThread;
    }

    if (verificationThread)
    {
        verificationThread->quit();
        verificationThread->wait();
        delete verificationThread;
    }

    if (obfuscationThread)
    {
        obfuscationThread->quit();
        obfuscationThread->wait();
        delete obfuscationThread;
    }
}

void MainWindow::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton)
    {
        dragPos = event->globalPos() - frameGeometry().topLeft();
        event->accept();
    }
}

void MainWindow::mouseMoveEvent(QMouseEvent* event)
{
    if (event->buttons() == Qt::LeftButton)
    {
        move(event->globalPos() - dragPos);
        event->accept();
    }
}

void MainWindow::showSettings()
{
    SettingsDialog dialog(this);
    dialog.exec();
}

void MainWindow::saveAllSettings()
{
    try
    {
        QSettings settings(PathUtils::getIniPath(), QSettings::IniFormat);
    }
    catch (...)
    {
    }
}

void MainWindow::runValidation()
{
    if (validatorThread && validatorThread->isRunning())
    {
        QMessageBox::information(this, "Bind - v1.3.2", "Validation Check is already running. Please wait for it to complete.");
        return;
    }

    QStringList dllPaths = leftPanel->getDllPaths();

    if (dllPaths.isEmpty())
    {
        QMessageBox::warning(this, "Bind - v1.3.2", "No DLL Paths specified. Please add at least one NTDLL path.");
        return;
    }

    if (validatorThread)
    {
        validatorThread->deleteLater();
    }

    validatorThread = new ValidatorThread(this);
    validatorThread->setDllPaths(dllPaths);

    connect(validatorThread, &ValidatorThread::validationStarted, this, [this]()
    {
        leftPanel->setProgressIndeterminate(true);
        leftPanel->updateStatus("Validation Started...");
        statusBar->updateStatus("Running Validation Check...");
        rightPanel->getOutputPanel()->clearText();
    });

    connect(validatorThread, &ValidatorThread::progressUpdated, this, [this](const QString& status)
    {
        leftPanel->updateStatus(status);
        statusBar->updateStatus(status);
        rightPanel->getOutputPanel()->appendText(status);
    });

    connect(validatorThread, &ValidatorThread::validationFinished, this, [this](bool success, const QString& message)
    {
        leftPanel->setProgressIndeterminate(false);

        if (success)
        {
            leftPanel->updateStatus("Validation Completed!");
            statusBar->updateStatus("Validation Completed Successfully!");
        }
        else
        {
            leftPanel->updateStatus("Validation Failed!");
            statusBar->updateStatus("Validation Failed!");
            QMessageBox::critical(this, "Bind - v1.3.2", message);
        }

        validatorThread->deleteLater();
        validatorThread = nullptr;
    });

    validatorThread->start();
}

void MainWindow::minimizeWindow()
{
    showMinimized();
}

void MainWindow::toggleMaximize()
{
    if (isMaximized())
    {
        showNormal();
    }
    else
    {
        showMaximized();
    }
}

void MainWindow::closeWindow()
{
    close();
    QApplication::quit();
}

void MainWindow::runCompatibility()
{
    if (compatibilityThread && compatibilityThread->isRunning())
    {
        QMessageBox::information(this, "Bind - v1.3.2", "Compatibility Check is already running. Please wait for it to complete.");
        return;
    }

    QStringList dllPaths = leftPanel->getDllPaths();

    if (dllPaths.isEmpty())
    {
        QMessageBox::warning(this, "Bind - v1.3.2", "No DLL Paths specified. Please add at least one NTDLL path.");
        return;
    }

    if (compatibilityThread)
    {
        compatibilityThread->deleteLater();
    }

    compatibilityThread = new CompatibilityThread(this);
    compatibilityThread->setDllPaths(dllPaths);

    connect(compatibilityThread, &CompatibilityThread::compatibilityStarted, this, [this]()
    {
        leftPanel->setProgressIndeterminate(true);
        leftPanel->updateStatus("Compatibility Started...");
        statusBar->updateStatus("Running Compatibility Check...");
        rightPanel->getOutputPanel()->clearText();
    });

    connect(compatibilityThread, &CompatibilityThread::progressUpdated, this, [this](const QString& status)
    {
        leftPanel->updateStatus(status);
        statusBar->updateStatus(status);
        rightPanel->getOutputPanel()->appendText(status);
    });

    connect(compatibilityThread, &CompatibilityThread::compatibilityFinished, this, [this](bool success, const QString& message)
    {
        leftPanel->setProgressIndeterminate(false);

        if (success)
        {
            leftPanel->updateStatus("Compatibility Completed!");
            statusBar->updateStatus("Compatibility Completed Successfully!");
        }
        else
        {
            leftPanel->updateStatus("Compatibility Failed!");
            statusBar->updateStatus("Compatibility Failed!");
            QMessageBox::critical(this, "Bind - v1.3.2", message);
        }

        compatibilityThread->deleteLater();
        compatibilityThread = nullptr;
    });

    compatibilityThread->start();
}

void MainWindow::runVerification()
{
    if (verificationThread && verificationThread->isRunning())
    {
        QMessageBox::information(this, "Bind - v1.3.2", "Verification Check is already running. Please wait for it to complete.");
        return;
    }

    QStringList dllPaths = leftPanel->getDllPaths();

    if (dllPaths.isEmpty())
    {
        QMessageBox::warning(this, "Bind - v1.3.2", "No DLL Paths specified. Please add at least one NTDLL path.");
        return;
    }

    if (verificationThread)
    {
        verificationThread->deleteLater();
    }

    verificationThread = new VerificationThread(this);
    verificationThread->setDllPaths(dllPaths);

    verificationThread->setOutputCallback([this](const QString& message)
    {
        leftPanel->updateStatus(message);
        statusBar->updateStatus(message);
        rightPanel->getOutputPanel()->appendText(message);
    });

    connect(verificationThread, &VerificationThread::verificationStarted, this, [this]()
    {
        leftPanel->setProgressIndeterminate(true);
        leftPanel->updateStatus("Verification Started...");
        statusBar->updateStatus("Running Verification Check...");
        rightPanel->getOutputPanel()->clearText();
    });

    connect(verificationThread, &VerificationThread::progressUpdated, this, [this](const QString& status)
    {
        leftPanel->updateStatus(status);
        statusBar->updateStatus(status);
        rightPanel->getOutputPanel()->appendText(status);
    });

    connect(verificationThread, &VerificationThread::verificationFinished, this, [this](bool success, const QString& message)
    {
        leftPanel->setProgressIndeterminate(false);

        if (success)
        {
            leftPanel->updateStatus("Verification Completed!");
            statusBar->updateStatus("Verification Completed Successfully!");
        }
        else
        {
            leftPanel->updateStatus("Verification Failed!");
            statusBar->updateStatus("Verification Failed!");
            QMessageBox::critical(this, "Bind - v1.3.2", message);
        }

        verificationThread->deleteLater();
        verificationThread = nullptr;
    });

    verificationThread->start();
}

void MainWindow::runObfuscation()
{
    if (obfuscationThread && obfuscationThread->isRunning())
    {
        QMessageBox::information(this, "Bind - v1.3.2", "Syscall Obfuscation is already running. Please wait for it to complete.");
        return;
    }

    saveAllSettings();

    ObfuscationSelectionDialog dialog(this);

    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    QString selectedMethod;
    ObfuscationSelectionDialog::Selection selection = dialog.getSelection();

    if (selection == ObfuscationSelectionDialog::NormalObfuscation)
    {
        selectedMethod = "normal";
        QSettings settings(PathUtils::getIniPath(), QSettings::IniFormat);
        settings.setValue("obfuscation/force_normal", true);
        settings.setValue("obfuscation/force_stub_mapper", false);
        settings.setValue("obfuscation/last_method", "normal");
    }
    else if (selection == ObfuscationSelectionDialog::StubMapper)
    {
        selectedMethod = "stub_mapper";
        QSettings settings(PathUtils::getIniPath(), QSettings::IniFormat);
        settings.setValue("obfuscation/force_normal", false);
        settings.setValue("obfuscation/force_stub_mapper", true);
        settings.setValue("obfuscation/last_method", "stub_mapper");
    }
    else
    {
        return;
    }

    if (obfuscationThread)
    {
        obfuscationThread->deleteLater();
    }

    obfuscationThread = new ObfuscationThread(this);

    connect(obfuscationThread, &ObfuscationThread::obfuscationStarted, this, [this]()
    {
        leftPanel->setProgressIndeterminate(true);
        leftPanel->updateStatus("Obfuscation Started...");
        statusBar->updateStatus("Running Syscall Obfuscation...");
        rightPanel->getOutputPanel()->clearText();
    });

    connect(obfuscationThread, &ObfuscationThread::progressUpdated, this, [this](const QString& status)
    {
        leftPanel->updateStatus(status);
        statusBar->updateStatus(status);
        rightPanel->getOutputPanel()->appendText(status);
    });

    connect(obfuscationThread, &ObfuscationThread::obfuscationFinished, this, [this, selectedMethod](bool success, const QString& message)
    {
        leftPanel->setProgressIndeterminate(false);

        if (success)
        {
            leftPanel->updateStatus("Obfuscation Completed!");
            statusBar->updateStatus("Obfuscation Completed Successfully!");
        }
        else
        {
            leftPanel->updateStatus("Obfuscation Failed!");
            statusBar->updateStatus("Obfuscation Failed!");
            QMessageBox::critical(this, "Bind - v1.3.2", message);
        }

        QSettings settings(PathUtils::getIniPath(), QSettings::IniFormat);
        settings.remove("obfuscation/force_normal");
        settings.remove("obfuscation/force_stub_mapper");

        obfuscationThread->deleteLater();
        obfuscationThread = nullptr;
    });

    obfuscationThread->start();
}

void MainWindow::closeEvent(QCloseEvent* event)
{}
