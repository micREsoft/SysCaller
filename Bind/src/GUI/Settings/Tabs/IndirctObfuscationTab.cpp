#include "include/GUI/Settings/Tabs/IndirectObfuscationTab.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>

IndirectObfuscationTab::IndirectObfuscationTab(QSettings* settings, QWidget* parent) 
    : QWidget(parent), settings(settings) {
    initUI();
}

void IndirectObfuscationTab::initUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);
    setupJunkInstructionsGroup();
    setupResolverObfuscationGroup();
    if (junkGroup) layout->addWidget(junkGroup);
    if (resolverGroup) layout->addWidget(resolverGroup);
    loadSettings();
}

void IndirectObfuscationTab::setupJunkInstructionsGroup() {
    junkGroup = new QGroupBox("Indirect Junk Instructions");
    QFormLayout* junkLayout = new QFormLayout();
    indirectMinInstructions = new QSpinBox();
    indirectMinInstructions->setRange(1, 10);
    indirectMinInstructions->setValue(settings->value("obfuscation/indirect_min_instructions", 2).toInt());
    indirectMinInstructions->setToolTip("Minimum number of junk instructions to add to indirect stubs");
    junkLayout->addRow("Minimum Instructions:", indirectMinInstructions);
    indirectMaxInstructions = new QSpinBox();
    indirectMaxInstructions->setRange(1, 20);
    indirectMaxInstructions->setValue(settings->value("obfuscation/indirect_max_instructions", 8).toInt());
    indirectMaxInstructions->setToolTip("Maximum number of junk instructions to add to indirect stubs");
    junkLayout->addRow("Maximum Instructions:", indirectMaxInstructions);
    indirectUseAdvancedJunk = new QCheckBox("Advanced Junk Instructions");
    indirectUseAdvancedJunk->setChecked(settings->value("obfuscation/indirect_use_advanced_junk", false).toBool());
    indirectUseAdvancedJunk->setToolTip("Use more complex junk instructions for indirect stubs");
    junkLayout->addRow(indirectUseAdvancedJunk);
    indirectEnableJunk = new QCheckBox("Enable Junk Instructions");
    indirectEnableJunk->setChecked(settings->value("obfuscation/indirect_enable_junk", true).toBool());
    indirectEnableJunk->setToolTip("Enable junk instruction generation for indirect stubs");
    junkLayout->addRow(indirectEnableJunk);
    junkGroup->setLayout(junkLayout);
}

void IndirectObfuscationTab::setupResolverObfuscationGroup() {
    resolverGroup = new QGroupBox("Resolver Obfuscation");
    QFormLayout* resolverLayout = new QFormLayout();
    indirectObfuscateCalls = new QCheckBox("Obfuscate Resolver Calls");
    indirectObfuscateCalls->setChecked(settings->value("obfuscation/indirect_obfuscate_calls", true).toBool());
    indirectObfuscateCalls->setToolTip("Obfuscate calls to the syscall resolver function");
    resolverLayout->addRow(indirectObfuscateCalls);
    resolverGroup->setLayout(resolverLayout);
}

void IndirectObfuscationTab::saveSettings() {
    settings->setValue("obfuscation/indirect_min_instructions", indirectMinInstructions->value());
    settings->setValue("obfuscation/indirect_max_instructions", indirectMaxInstructions->value());
    settings->setValue("obfuscation/indirect_use_advanced_junk", indirectUseAdvancedJunk->isChecked());
    settings->setValue("obfuscation/indirect_enable_junk", indirectEnableJunk->isChecked());
    settings->setValue("obfuscation/indirect_obfuscate_calls", indirectObfuscateCalls->isChecked());
}

void IndirectObfuscationTab::loadSettings() {
} 
