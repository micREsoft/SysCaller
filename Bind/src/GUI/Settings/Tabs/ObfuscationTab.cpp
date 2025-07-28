#include "include/GUI/Settings/Tabs/ObfuscationTab.h"
#include <QFormLayout>

ObfuscationTab::ObfuscationTab(QSettings* settings, QWidget* parent) 
    : QWidget(parent), settings(settings) {
    initUI();
}

void ObfuscationTab::initUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);
    QGroupBox* junkGroup = new QGroupBox("Junk Instructions");
    QFormLayout* junkLayout = new QFormLayout();
    minInstructions = new QSpinBox();
    minInstructions->setRange(1, 10);
    minInstructions->setValue(settings->value("obfuscation/min_instructions", 2).toInt());
    junkLayout->addRow("Minimum Instructions:", minInstructions);
    maxInstructions = new QSpinBox();
    maxInstructions->setRange(1, 20);
    maxInstructions->setValue(settings->value("obfuscation/max_instructions", 8).toInt());
    junkLayout->addRow("Maximum Instructions:", maxInstructions);
    useAdvancedJunk = new QCheckBox("Advanced Junk Instructions");
    useAdvancedJunk->setChecked(settings->value("obfuscation/use_advanced_junk", false).toBool());
    junkLayout->addRow(useAdvancedJunk);
    junkGroup->setLayout(junkLayout);
    layout->addWidget(junkGroup);
    QGroupBox* nameGroup = new QGroupBox("Name Randomization");
    QFormLayout* nameLayout = new QFormLayout();
    QHBoxLayout* syscallPrefixLayout = new QHBoxLayout();
    syscallPrefixLength = new QSpinBox();
    syscallPrefixLength->setRange(4, 16);
    syscallPrefixLength->setValue(settings->value("obfuscation/syscall_prefix_length", 8).toInt());
    syscallPrefixLength->setToolTip("Length of the syscall prefix in the syscall stub");
    syscallNumberLength = new QSpinBox();
    syscallNumberLength->setRange(4, 16);
    syscallNumberLength->setValue(settings->value("obfuscation/syscall_number_length", 6).toInt());
    syscallNumberLength->setToolTip("Length of the syscall number in the syscall stub");
    syscallPrefixLayout->addWidget(new QLabel("Chars:"));
    syscallPrefixLayout->addWidget(syscallPrefixLength);
    syscallPrefixLayout->addWidget(new QLabel("Numbers:"));
    syscallPrefixLayout->addWidget(syscallNumberLength);
    nameLayout->addRow("Syscall Name Length:", syscallPrefixLayout);
    offsetNameLength = new QSpinBox();
    offsetNameLength->setRange(4, 16);
    offsetNameLength->setValue(settings->value("obfuscation/offset_name_length", 8).toInt());
    offsetNameLength->setToolTip("Length of the offset name in the syscall stub");
    nameLayout->addRow("Offset Name Length:", offsetNameLength);
    nameGroup->setLayout(nameLayout);
    layout->addWidget(nameGroup);
    QGroupBox* sequenceGroup = new QGroupBox("Sequence Shuffling");
    QFormLayout* sequenceLayout = new QFormLayout();
    shuffleSequence = new QCheckBox("Enable Sequence Shuffling");
    shuffleSequence->setChecked(settings->value("obfuscation/shuffle_sequence", true).toBool());
    shuffleSequence->setToolTip("Randomize the order of syscall stubs in the assembly file");
    sequenceLayout->addRow(shuffleSequence);
    sequenceGroup->setLayout(sequenceLayout);
    layout->addWidget(sequenceGroup);
    QGroupBox* encryptionGroup = new QGroupBox("Syscall Encryption");
    QFormLayout* encryptionLayout = new QFormLayout();
    enableEncryption = new QCheckBox("Enable Syscall ID Encryption");
    enableEncryption->setChecked(settings->value("obfuscation/enable_encryption", true).toBool());
    enableEncryption->setToolTip("Encrypt syscall IDs in the data section to make static analysis harder");
    encryptionLayout->addRow(enableEncryption);
    encryptionMethod = new QComboBox();
    encryptionMethod->addItem("Basic XOR (Simple)", 1);
    encryptionMethod->addItem("Multi-key XOR (Medium)", 2);
    encryptionMethod->addItem("Add + XOR (Medium)", 3);
    encryptionMethod->addItem("Enhanced XOR (Medium)", 4);
    encryptionMethod->addItem("Offset Shifting (Medium)", 5);
    int currentMethod = settings->value("obfuscation/encryption_method", 1).toInt();
    int index = encryptionMethod->findData(currentMethod);
    if (index >= 0) {
        encryptionMethod->setCurrentIndex(index);
    }
    encryptionMethod->setToolTip("Select the encryption method to use for syscall ID obfuscation");
    encryptionLayout->addRow("Encryption Method:", encryptionMethod);
    encryptionGroup->setLayout(encryptionLayout);
    layout->addWidget(encryptionGroup);
    QGroupBox* chunkingGroup = new QGroupBox("Function Chunking");
    QFormLayout* chunkingLayout = new QFormLayout();
    enableChunking = new QCheckBox("Enable Function Chunking");
    enableChunking->setChecked(settings->value("obfuscation/enable_chunking", true).toBool());
    enableChunking->setToolTip("Split syscall stubs into multiple fragments to make analysis harder");
    chunkingLayout->addRow(enableChunking);
    chunkingGroup->setLayout(chunkingLayout);
    layout->addWidget(chunkingGroup);
    QGroupBox* interleavedGroup = new QGroupBox("Interleaved Execution");
    QFormLayout* interleavedLayout = new QFormLayout();
    enableInterleaved = new QCheckBox("Enable Interleaved Execution");
    enableInterleaved->setChecked(settings->value("obfuscation/enable_interleaved", true).toBool());
    enableInterleaved->setToolTip("Mix code from different syscalls using ALIGN directives and random padding");
    interleavedLayout->addRow(enableInterleaved);
    interleavedGroup->setLayout(interleavedLayout);
    layout->addWidget(interleavedGroup);
    layout->addStretch();
}

void ObfuscationTab::saveSettings() {
    settings->setValue("obfuscation/min_instructions", minInstructions->value());
    settings->setValue("obfuscation/max_instructions", maxInstructions->value());
    settings->setValue("obfuscation/use_advanced_junk", useAdvancedJunk->isChecked());
    settings->setValue("obfuscation/syscall_prefix_length", syscallPrefixLength->value());
    settings->setValue("obfuscation/syscall_number_length", syscallNumberLength->value());
    settings->setValue("obfuscation/offset_name_length", offsetNameLength->value());
    settings->setValue("obfuscation/shuffle_sequence", shuffleSequence->isChecked());
    settings->setValue("obfuscation/enable_encryption", enableEncryption->isChecked());
    settings->setValue("obfuscation/encryption_method", encryptionMethod->currentData().toInt());
    settings->setValue("obfuscation/enable_chunking", enableChunking->isChecked());
    settings->setValue("obfuscation/enable_interleaved", enableInterleaved->isChecked());
} 