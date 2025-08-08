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
    setupEncryptionGroup();
    setupControlFlowGroup();
    setupStringEncryptionGroup();
    if (junkGroup) layout->addWidget(junkGroup);
    if (resolverGroup) layout->addWidget(resolverGroup);
    if (encryptionGroup) layout->addWidget(encryptionGroup);
    if (controlFlowGroup) layout->addWidget(controlFlowGroup);
    if (stringEncGroup) layout->addWidget(stringEncGroup);
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
    indirectObfuscateCalls->setToolTip("Obfuscate calls to the syscall resolver function using function pointers");
    resolverLayout->addRow(indirectObfuscateCalls);
    indirectResolverMethod = new QComboBox();
    indirectResolverMethod->addItem("Random Pattern", "random");
    indirectResolverMethod->addItem("Register Based (Safest)", "register");
    indirectResolverMethod->addItem("Stack Based (Aligned)", "stack");
    indirectResolverMethod->addItem("Indirect Data", "indirect");
    indirectResolverMethod->addItem("Register Shuffle", "shuffle");
    QString savedMethod = settings->value("obfuscation/indirect_resolver_method", "random").toString();
    int index = indirectResolverMethod->findData(savedMethod);
    if (index >= 0) {
        indirectResolverMethod->setCurrentIndex(index);
    }
    indirectResolverMethod->setToolTip("Choose the function pointer obfuscation method for resolver calls");
    resolverLayout->addRow("Resolver Method:", indirectResolverMethod);
    resolverGroup->setLayout(resolverLayout);
}

void IndirectObfuscationTab::setupEncryptionGroup() {
    encryptionGroup = new QGroupBox("Encrypted Syscall Numbers");
    QFormLayout* encryptionLayout = new QFormLayout();
    indirectEncryptSyscalls = new QCheckBox("Encrypt Syscall Numbers");
    indirectEncryptSyscalls->setChecked(settings->value("obfuscation/indirect_encrypt_syscalls", false).toBool());
    indirectEncryptSyscalls->setToolTip("Encrypt the syscall numbers in the generated shellcode");
    encryptionLayout->addRow(indirectEncryptSyscalls);
    encryptionGroup->setLayout(encryptionLayout);
}

void IndirectObfuscationTab::setupControlFlowGroup() {
    controlFlowGroup = new QGroupBox("Control Flow Obfuscation");
    QFormLayout* controlFlowLayout = new QFormLayout();
    indirectEnableControlFlow = new QCheckBox("Enable Control Flow Obfuscation");
    indirectEnableControlFlow->setChecked(settings->value("obfuscation/indirect_enable_control_flow", false).toBool());
    indirectEnableControlFlow->setToolTip("Enable control flow obfuscation for indirect stubs");
    controlFlowLayout->addRow(indirectEnableControlFlow);
    indirectControlFlowMethod = new QComboBox();
    indirectControlFlowMethod->addItem("Random Pattern", "random");
    indirectControlFlowMethod->addItem("Register Based (Safest)", "register");
    indirectControlFlowMethod->addItem("Value Based", "value");
    indirectControlFlowMethod->addItem("Flag Based", "flag");
    indirectControlFlowMethod->addItem("Mixed Junk Code", "mixed");
    QString savedMethod = settings->value("obfuscation/indirect_control_flow_method", "random").toString();
    int index = indirectControlFlowMethod->findData(savedMethod);
    if (index >= 0) {
        indirectControlFlowMethod->setCurrentIndex(index);
    }
    indirectControlFlowMethod->setToolTip("Choose the control flow obfuscation method");
    controlFlowLayout->addRow("Control Flow Method:", indirectControlFlowMethod);
    controlFlowGroup->setLayout(controlFlowLayout);
}

void IndirectObfuscationTab::setupStringEncryptionGroup() {
    stringEncGroup = new QGroupBox("Resolver String Encryption");
    QFormLayout* fl = new QFormLayout();
    indirectEncryptStrings = new QCheckBox("Encrypt Nt* resolver names");
    indirectEncryptStrings->setChecked(settings->value("obfuscation/indirect_encrypt_strings", false).toBool());
    indirectEncryptStrings->setToolTip("Encrypt strings like NtOpenProcess and decrypt them on the stack at runtime before calling the resolver");
    fl->addRow(indirectEncryptStrings);
    stringEncGroup->setLayout(fl);
}

void IndirectObfuscationTab::saveSettings() {
    settings->setValue("obfuscation/indirect_min_instructions", indirectMinInstructions->value());
    settings->setValue("obfuscation/indirect_max_instructions", indirectMaxInstructions->value());
    settings->setValue("obfuscation/indirect_use_advanced_junk", indirectUseAdvancedJunk->isChecked());
    settings->setValue("obfuscation/indirect_enable_junk", indirectEnableJunk->isChecked());
    settings->setValue("obfuscation/indirect_obfuscate_calls", indirectObfuscateCalls->isChecked());
    settings->setValue("obfuscation/indirect_resolver_method", indirectResolverMethod->currentData().toString());
    settings->setValue("obfuscation/indirect_encrypt_syscalls", indirectEncryptSyscalls->isChecked());
    settings->setValue("obfuscation/indirect_enable_control_flow", indirectEnableControlFlow->isChecked());
    settings->setValue("obfuscation/indirect_control_flow_method", indirectControlFlowMethod->currentData().toString());
    settings->setValue("obfuscation/indirect_encrypt_strings", indirectEncryptStrings->isChecked());
}

void IndirectObfuscationTab::loadSettings() {
}
