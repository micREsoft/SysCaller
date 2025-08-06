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
    QSpinBox* indirectMinInstructions;
    QSpinBox* indirectMaxInstructions;
    QCheckBox* indirectUseAdvancedJunk;
    QCheckBox* indirectEnableJunk;
    QCheckBox* indirectObfuscateCalls;

public:
    IndirectObfuscationTab(QSettings* settings, QWidget* parent = nullptr);
    void saveSettings();
    void loadSettings();

private:
    void initUI();
    void setupJunkInstructionsGroup();
    void setupResolverObfuscationGroup();
}; 
