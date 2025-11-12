#include <Core/Utils/Common.h>
#include <GUI/Settings.h>

InlineObfuscationTab::InlineObfuscationTab(QSettings* settings, QWidget* parent)
    : QWidget(parent)
    , settings(settings)
{
    initUI();
}

void InlineObfuscationTab::initUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);

    QLabel* comingSoonLabel = new QLabel("Inline Assembly Obfuscation is coming soon!");
    comingSoonLabel->setAlignment(Qt::AlignCenter);
    comingSoonLabel->setStyleSheet("font-size: 16px; color: #888888; margin: 50px;");

    layout->addWidget(comingSoonLabel);
}

void InlineObfuscationTab::saveSettings()
{
}