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

private:
    QSettings* settings;
    QGroupBox* junkGroup;
    QGroupBox* resolverGroup;
    QGroupBox* encryptionGroup;
    QGroupBox* controlFlowGroup;
    QSpinBox* indirectMinInstructions;
    QSpinBox* indirectMaxInstructions;
    QCheckBox* indirectObfuscateCalls;
    QComboBox* indirectResolverMethod;
    QCheckBox* indirectEncryptSyscalls;
    QCheckBox* indirectEnableControlFlow;
    QComboBox* indirectControlFlowMethod;
    QCheckBox* indirectEncryptStrings;

public:
    IndirectObfuscationTab(QSettings* settings, QWidget* parent = nullptr);
    void saveSettings();
    void loadSettings();

private:
    void initUI();
    void setupJunkInstructionsGroup();
    void setupResolverObfuscationGroup();
    void setupEncryptionGroup();
    void setupControlFlowGroup();
};
