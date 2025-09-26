#include "include/GUI/Panels/LeftPanel.h"
#include "include/GUI/Bars/ProgressBar.h"
#include "include/GUI/Buttons/BindButton.h"
#include "include/GUI/Dialogs/ChangelogDialog.h"
#include <cstdlib>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QListWidget>
#include <QFileDialog>
#include <QMenu>
#include <QApplication>
#include <QFontDatabase>
#include <QPixmap>

LeftPanel::LeftPanel(QWidget* parent)
    : QFrame(parent)
{
    setMaximumWidth(350);
    setStyleSheet(
        "QFrame {"
        " background: #252525;"
        " border-radius: 15px;"
        "}"
    );
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(10);

    auto* topSection = new QVBoxLayout();
    topSection->setSpacing(5);
    topSection->setAlignment(Qt::AlignCenter);

    logoImage = new QLabel(this);
    logoImage->setPixmap(QPixmap(":/src/Res/Icons/syscaller.png")
                               .scaled(128, 128, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    logoImage->setFixedSize(128, 128);
    logoImage->setAlignment(Qt::AlignCenter);
    logoImage->setStyleSheet("QLabel { background: transparent; }");
    logoImage->setContentsMargins(0, 0, 0, 0);
    topSection->addWidget(logoImage, 0, Qt::AlignCenter);

    logoLabel = new QLabel("SysCaller: Bind", this);
    logoLabel->setStyleSheet(
        "color: #0077d4;"
        "font-weight: bold;"
        "padding: 10px;"
        "background: rgba(72, 128, 168, 0.2);"
        "border-radius: 10px;"
    );
    logoLabel->setAlignment(Qt::AlignCenter);
    topSection->addWidget(logoLabel, 0, Qt::AlignCenter);

    versionLabel = new QLabel("v1.3.1", this);
    versionLabel->setStyleSheet("color: #666666; font-size: 12px;");
    versionLabel->setAlignment(Qt::AlignCenter);
    versionLabel->setCursor(Qt::PointingHandCursor);
    versionLabel->setTextFormat(Qt::RichText);
    versionLabel->setText("<a href='#' style='color: #666666; text-decoration: none;'>v1.3.1</a>");
    topSection->addWidget(versionLabel, 0, Qt::AlignCenter);

    layout->addLayout(topSection);
    layout->addSpacing(15);
    auto* dllFrame = new QFrame(this);
    dllFrame->setStyleSheet(
        "QFrame {"
        " background: #1E1E1E;"
        " border-radius: 10px;"
        " padding: 10px;"
        "}"
    );

    auto* dllLayout = new QVBoxLayout(dllFrame);
    dllLayout->setContentsMargins(15, 15, 15, 15);
    dllLayout->setSpacing(8);

    auto* headerBtnLayout = new QHBoxLayout();
    auto* dllHeader = new QLabel("NTDLL PATHS", this);
    dllHeader->setStyleSheet("color: #888888; font-size: 12px; font-weight: bold;");
    headerBtnLayout->addWidget(dllHeader);
    headerBtnLayout->addStretch();

    auto* btnLayout = new QHBoxLayout();
    btnLayout->setSpacing(8);

    addDllBtn = new QPushButton("Add DLL", this);
    addDllBtn->setMaximumWidth(100);
    addDllBtn->setMinimumHeight(26);
    addDllBtn->setStyleSheet(
        "QPushButton {"
        " background: #333333;"
        " border: none;"
        " border-radius: 5px;"
        " padding: 5px;"
        " color: white;"
        " font-weight: bold;"
        " font-size: 10px;"
        "}"
        "QPushButton:hover {"
        " background: #404040;"
        "}"
        "QPushButton:pressed {"
        " background: #2A2A2A;"
        "}"
    );
    btnLayout->addWidget(addDllBtn);

    removeDllBtn = new QPushButton("Remove", this);
    removeDllBtn->setMaximumWidth(80);
    removeDllBtn->setMinimumHeight(26);
    removeDllBtn->setStyleSheet(
        "QPushButton {"
        " background: #333333;"
        " border: none;"
        " border-radius: 5px;"
        " padding: 5px;"
        " color: white;"
        " font-weight: bold;"
        " font-size: 10px;"
        "}"
        "QPushButton:hover {"
        " background: #404040;"
        "}"
        "QPushButton:pressed {"
        " background: #2A2A2A;"
        "}"
    );
    btnLayout->addWidget(removeDllBtn);

    headerBtnLayout->addLayout(btnLayout);
    dllLayout->addLayout(headerBtnLayout);
    dllLayout->addSpacing(3);

    dllList = new QListWidget(this);
    dllList->setStyleSheet(
        "QListWidget {"
        " background: #252525;"
        " border: 1px solid #333333;"
        " border-radius: 5px;"
        " padding: 5px;"
        " color: #FFFFFF;"
        " font-family: 'IBM Plex Mono';"
        " font-size: 12px;"
        "}"
        "QListWidget::item {"
        " padding: 5px;"
        " border-radius: 3px;"
        "}"
        "QListWidget::item:hover {"
        " background: #333333;"
        "}"
        "QListWidget::item:selected {"
        " background: #4880a8;"
        "}"
    );
    dllList->setFixedHeight(90);
    dllList->setContextMenuPolicy(Qt::CustomContextMenu);

    dllLayout->addWidget(dllList);
    dllFrame->setFixedHeight(175);
    layout->addWidget(dllFrame);
    layout->addSpacing(15);
    auto* buttonsSection = new QVBoxLayout();
    buttonsSection->setSpacing(10);

    validateBtn = new BindButton(
        " Validation Check",
        ":/src/Res/Icons/validation.png",
        "Bind Validation",
        "Analyzes and updates syscall offsets in syscaller.asm by comparing against ntdll.dll. <br><br>"
        "• Disassembles ntdll.dll exports to extract syscall IDs and ensures correct mapping <br>"
        "• Updates or removes syscalls based on their presence in the current systems ntdll.dll"
    );
    buttonsSection->addWidget(validateBtn);

    compatibilityBtn = new BindButton(
        " Compatibility Check",
        ":/src/Res/Icons/compatibility.png",
        "Bind Compatibility",
        "Performs compatibility analysis of syscalls against ntdll.dll: <br><br>"
        "• Detects duplicate syscall names and offsets <br>"
        "• Validates both Nt and Zw syscall variants <br>"
        "• Verifies offset matches between implementation and DLL <br>"
        "• Reports valid, invalid, and duplicate syscalls with detailed status"
    );
    buttonsSection->addWidget(compatibilityBtn);

    verifyBtn = new BindButton(
        " Verification Check",
        ":/src/Res/Icons/verification.png",
        "Bind Verification",
        "Performs comprehensive syscall verification: <br><br>"
        "• Validates return types (NTSTATUS, BOOL, HANDLE, etc.) <br>"
        "• Verifies parameter types against system headers <br>"
        "• Checks offset ranges (0x0000-0x0200) <br>"
        "• Traces type definitions in header files"
    );
    buttonsSection->addWidget(verifyBtn);

    obfuscateBtn = new BindButton(
        " Obfuscation",
        ":/src/Res/Icons/obfuscation.png",
        "Bind Obfuscation",
        "Obfuscates syscalls to enhance protection: <br><br>"
        "• Randomizes syscall names and offsets <br>"
        "• Adds junk instructions for anti-pattern <br>"
        "• Maintains compatibility with existing code <br>"
        "• Preserves original syscall functionality"
    );
    buttonsSection->addWidget(obfuscateBtn);

    settingsBtn = new BindButton(
        " Settings",
        ":/src/Res/Icons/settings.png",
        "Bind Settings",
        "Configure SysCaller project settings"
    );
    buttonsSection->addWidget(settingsBtn);

    layout->addLayout(buttonsSection);
    layout->addSpacing(10);
    auto* statusFrame = new QFrame(this);
    statusFrame->setStyleSheet(
        "QFrame {"
        " background: #1E1E1E;"
        " border-radius: 10px;"
        " padding: 10px;"
        "}"
    );

    auto* statusLayout = new QVBoxLayout(statusFrame);
    statusLayout->setContentsMargins(15, 15, 15, 15);

    progressBar = new ProgressBar(this);
    statusLayout->addWidget(progressBar);

    statusLabel = new QLabel("Ready", this);
    statusLabel->setStyleSheet(
        "color: #666666; font-size: 12px; padding: 5px; border-radius: 5px; background: rgba(102, 102, 102, 0.1);"
    );
    statusLabel->setAlignment(Qt::AlignCenter);
    statusLayout->addWidget(statusLabel);

    layout->addWidget(statusFrame);
    layout->addStretch();

    dllList->addItem("C:\\Windows\\System32\\ntdll.dll");

    connect(addDllBtn, &QPushButton::clicked, this, &LeftPanel::browseDll);
    emit dllPathsChanged(getDllPaths());

    connect(removeDllBtn, &QPushButton::clicked, this, &LeftPanel::removeSelectedDll);
    connect(dllList, &QListWidget::customContextMenuRequested, this, &LeftPanel::showContextMenu);
    connect(settingsBtn, &BindButton::clicked, this, &LeftPanel::settingsButtonClicked);
    connect(validateBtn, &BindButton::clicked, this, &LeftPanel::validationButtonClicked);
    connect(compatibilityBtn, &BindButton::clicked, this, &LeftPanel::compatibilityButtonClicked);
    connect(verifyBtn, &BindButton::clicked, this, &LeftPanel::verificationButtonClicked);
    connect(obfuscateBtn, &BindButton::clicked, this, &LeftPanel::obfuscationButtonClicked);
    connect(versionLabel, &QLabel::linkActivated, this, &LeftPanel::showChangelogDialog);
}

void LeftPanel::browseDll()
{
    QString dllPath = QFileDialog::getOpenFileName(
        this,
        "Bind - v1.3.1",
        "",
        "DLL Files (*.dll);;All Files (*.*)"
    );

    if (!dllPath.isEmpty())
    {
        bool exists = false;

        for (int i = 0; i < dllList->count(); ++i)
        {
            if (dllList->item(i)->text() == dllPath)
            {
                exists = true;
                break;
            }
        }

        if (!exists)
        {
            dllList->addItem(dllPath);
            emit dllPathsChanged(getDllPaths());
        }
    }
}

void LeftPanel::removeSelectedDll()
{
    QList<QListWidgetItem*> selectedItems = dllList->selectedItems();

    if (selectedItems.isEmpty() || dllList->count() <= 1)
    {
        return;
    }

    for (QListWidgetItem* item : selectedItems)
    {
        delete dllList->takeItem(dllList->row(item));
    }

    emit dllPathsChanged(getDllPaths());
}

void LeftPanel::showContextMenu(const QPoint& pos)
{
    if (dllList->count() <= 1)
    {
        return;
    }

    QMenu menu(this);
    menu.setStyleSheet(
        "QMenu {"
        " background-color: #252525;"
        " color: white;"
        " border: 1px solid #333333;"
        "}"
        "QMenu::item {"
        " padding: 5px 20px;"
        "}"
        "QMenu::item:selected {"
        " background-color: #4880a8;"
        "}"
    );

    QAction* removeAction = menu.addAction("Remove");
    QAction* selectedAction = menu.exec(dllList->mapToGlobal(pos));

    if (selectedAction == removeAction)
    {
        removeSelectedDll();
    }
}

QStringList LeftPanel::getDllPaths() const
{
    QStringList paths;

    for (int i = 0; i < dllList->count(); ++i)
    {
        paths.append(dllList->item(i)->text());
    }

    return paths;
}

void LeftPanel::setProgressIndeterminate(bool indeterminate)
{
    if (indeterminate)
    {
        progressBar->setRange(0, 0);
    }
    else
    {
        progressBar->setRange(0, 1);
        progressBar->setValue(1);
    }
}

void LeftPanel::updateStatus(const QString& message)
{
    statusLabel->setText(message);
}

void LeftPanel::showChangelogDialog()
{
    ChangelogDialog dialog(this);
    dialog.exec();
}
