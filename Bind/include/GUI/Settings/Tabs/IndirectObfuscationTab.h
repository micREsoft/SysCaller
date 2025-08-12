#pragma once

#include <QWidget>
#include <QSettings>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QGroupBox>
#include <QFormLayout>

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
    void setupNameRandomizationGroup();
    void setupEncryptionGroup();
    void setupControlFlowGroup();
};