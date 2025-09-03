#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QPushButton>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QSettings>

class ObfuscationTab : public QWidget {
    Q_OBJECT

public:
    explicit ObfuscationTab(QSettings* settings, QWidget* parent = nullptr);
    
    void saveSettings();

private:
    void initUI();

    QSettings* settings;
    QSpinBox* minInstructions;
    QSpinBox* maxInstructions;
    QCheckBox* useAdvancedJunk;
    QSpinBox* syscallPrefixLength;
    QSpinBox* syscallNumberLength;
    QSpinBox* offsetNameLength;
    QCheckBox* shuffleSequence;
    QCheckBox* enableEncryption;
    QComboBox* encryptionMethod;
    QCheckBox* enableChunking;
    QCheckBox* enableInterleaved;
    QCheckBox* enableControlFlow;
    QCheckBox* opaquePredicates;
    QCheckBox* bogusControlFlow;
    QCheckBox* indirectJumps;
    QCheckBox* conditionalBranches;
    QSpinBox* controlFlowComplexity;
};