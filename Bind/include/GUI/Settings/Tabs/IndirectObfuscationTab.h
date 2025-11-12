#pragma once

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QSettings>
#include <QSpinBox>
#include <QWidget>

class IndirectObfuscationTab : public QWidget {
    Q_OBJECT

public:
    explicit IndirectObfuscationTab(QSettings* settings, QWidget* parent = nullptr);

    void saveSettings();
    void loadSettings();

private:
    QSettings* settings;

    QGroupBox* junkGroup;
    QGroupBox* resolverGroup;
    QGroupBox* encryptionGroup;
    QGroupBox* controlFlowGroup;
    QGroupBox* nameGroup;

    QSpinBox* indirectMinInstructions;
    QSpinBox* indirectMaxInstructions;
    QSpinBox* indirectSyscallPrefixLength;
    QSpinBox* indirectSyscallNumberLength;
    QSpinBox* indirectOffsetNameLength;

    QCheckBox* indirectObfuscateCalls;
    QCheckBox* indirectEncryptSyscalls;
    QCheckBox* indirectEnableControlFlow;
    QCheckBox* indirectEncryptStrings;

    QComboBox* indirectResolverMethod;
    QComboBox* indirectControlFlowMethod;

    void initUI();
    void setupJunkInstructionsGroup();
    void setupResolverObfuscationGroup();
    void setupEncryptionGroup();
    void setupControlFlowGroup();
};