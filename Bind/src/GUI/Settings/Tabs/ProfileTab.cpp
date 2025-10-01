#include "include/GUI/Settings/Tabs/ProfileTab.h"
#include "include/Core/Utils/PathUtils.h"
#include <QDir>
#include <QProcess>

ProfileTab::ProfileTab(QSettings* settings, QWidget* parent)
    : QWidget(parent)
    , settings(settings)
{
    initUI();
}

void ProfileTab::initUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->addSpacing(20);

    QPushButton* exportBtn = new QPushButton("Export Profile (.ini)");
    exportBtn->setMinimumHeight(40);
    exportBtn->setStyleSheet(
        "QPushButton {"
        " background: rgba(255, 255, 255, 0.1);"
        " border: 1px solid rgba(255, 255, 255, 0.2);"
        " border-radius: 5px;"
        " padding: 8px 15px;"
        " color: white;"
        " font-weight: bold;"
        "}"
        "QPushButton:hover {"
        " background: rgba(255, 255, 255, 0.15);"
        " border: 1px solid rgba(255, 255, 255, 0.3);"
        "}"
    );

    connect(exportBtn, &QPushButton::clicked, this, &ProfileTab::exportProfile);
    layout->addWidget(exportBtn);

    layout->addSpacing(10);

    QPushButton* importBtn = new QPushButton("Import Profile (.ini)");
    importBtn->setMinimumHeight(40);
    importBtn->setStyleSheet(
        "QPushButton {"
        " background: rgba(255, 255, 255, 0.1);"
        " border: 1px solid rgba(255, 255, 255, 0.2);"
        " border-radius: 5px;"
        " padding: 8px 15px;"
        " color: white;"
        " font-weight: bold;"
        "}"
        "QPushButton:hover {"
        " background: rgba(255, 255, 255, 0.15);"
        " border: 1px solid rgba(255, 255, 255, 0.3);"
        "}"
    );

    connect(importBtn, &QPushButton::clicked, this, &ProfileTab::importProfile);
    layout->addWidget(importBtn);

    layout->addStretch();
}

void ProfileTab::exportProfile()
{
    QString path = QFileDialog::getSaveFileName(this, "Export Profile", "", "INI Files (*.ini);;All Files (*)");

    if (path.isEmpty())
    {
        return;
    }

    if (!path.toLower().endsWith(".ini"))
    {
        path += ".ini";
    }

    try
    {
        QSettings exportSettings(path, QSettings::IniFormat);
        exportSettings.clear();

        settings->sync();

        for (const QString& group : settings->childGroups())
        {
            settings->beginGroup(group);
            exportSettings.beginGroup(group);

            for (const QString& key : settings->childKeys())
            {
                exportSettings.setValue(key, settings->value(key));
            }

            exportSettings.endGroup();
            settings->endGroup();
        }

        exportSettings.sync();

        QMessageBox::information(this, "Bind - v1.3.2",
                               QString("Profile exported to:\n%1")
                               .arg(QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath())));
    }
    catch (...)
    {
        QMessageBox::critical(this, "Bind - v1.3.2", "Failed to export profile.");
    }
}

void ProfileTab::importProfile()
{
    QString path = QFileDialog::getOpenFileName(this, "Bind - v1.3.2", "", "INI Files (*.ini);;All Files (*)");

    if (path.isEmpty())
    {
        return;
    }

    try
    {
        QString iniPath = PathUtils::getIniPath();
        settings->sync();
        delete settings;
        settings = nullptr;

        QFile::remove(iniPath);
        QFile::copy(path, iniPath);

        QMessageBox::information(this, "Bind - v1.3.2",
                               QString("Profile imported from:\n%1\n\nSysCaller will now restart to use the imported profile.")
                               .arg(QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath())));

        QProcess::startDetached(QApplication::applicationFilePath(), QApplication::arguments());
        QApplication::quit();
    }
    catch (...)
    {
        QMessageBox::critical(this, "Bind - v1.3.2", "Failed to import profile.");
    }
}

void ProfileTab::saveSettings()
{
}