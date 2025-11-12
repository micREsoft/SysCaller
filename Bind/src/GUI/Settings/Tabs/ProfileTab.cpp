#include <Core/Utils/Common.h>
#include <GUI/Settings.h>

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

        QMessageBox::information(this, SYSCALLER_WINDOW_TITLE,
                               QString("Profile exported to:\n%1")
                               .arg(QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath())));
    }
    catch (...)
    {
        QMessageBox::critical(this, SYSCALLER_WINDOW_TITLE, "Failed to export profile.");
    }
}

void ProfileTab::importProfile()
{
    QString path = QFileDialog::getOpenFileName(this, SYSCALLER_WINDOW_TITLE, "", "INI Files (*.ini);;All Files (*)");

    if (path.isEmpty())
    {
        return;
    }

    try
    {
        QFileInfo sourceInfo(path);
        if (!sourceInfo.exists() || !sourceInfo.isFile() || !sourceInfo.isReadable())
        {
            QMessageBox::critical(this, SYSCALLER_WINDOW_TITLE, 
                QString("Cannot read source profile file:\n%1").arg(path));
            return;
        }
        
        QString iniPath = PathUtils::getIniPath();
        
        QString backupPath = iniPath + ".backup";
        if (QFile::exists(iniPath))
        {
            if (!QFile::copy(iniPath, backupPath))
            {
                qWarning() << "Failed to create backup of current settings before import";
            }
        }
        
        settings->sync();
        delete settings;
        settings = nullptr;

        if (QFile::exists(iniPath))
        {
            if (!QFile::remove(iniPath))
            {
                QMessageBox::critical(this, SYSCALLER_WINDOW_TITLE, 
                    QString("Failed to remove existing settings file:\n%1\n\nFile may be locked.")
                    .arg(iniPath));
                return;
            }
        }
        
        if (!QFile::copy(path, iniPath))
        {
            if (QFile::exists(backupPath))
            {
                QFile::copy(backupPath, iniPath);
                QFile::remove(backupPath);
            }
            
            QMessageBox::critical(this, SYSCALLER_WINDOW_TITLE, 
                QString("Failed to copy profile file:\n%1\nto:\n%2")
                .arg(path, iniPath));
            return;
        }
        
        if (QFile::exists(backupPath))
        {
            QFile::remove(backupPath);
        }

        QMessageBox::information(this, SYSCALLER_WINDOW_TITLE,
                               QString("Profile imported from:\n%1\n\nSysCaller will now restart to use the imported profile.")
                               .arg(QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath())));

        QProcess::startDetached(QApplication::applicationFilePath(), QApplication::arguments());
        QApplication::quit();
    }
    catch (...)
    {
        QMessageBox::critical(this, SYSCALLER_WINDOW_TITLE, "Failed to import profile.");
    }
}

void ProfileTab::saveSettings()
{}