#pragma once

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QFormLayout>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QPushButton>
#include <QListWidget>
#include <QSplitter>
#include <QWidget>
#include <QTabWidget>
#include <QMessageBox>
#include <QLineEdit>
#include <QSettings>
#include <QMap>
#include <QVariant>
#include <QMouseEvent>

class SettingsTitleBar;

class StubMapperDialog : public QDialog {
    Q_OBJECT

public:
    explicit StubMapperDialog(QWidget* parent = nullptr);
    ~StubMapperDialog() override;

private slots:
    void filterSyscalls(const QString& text);
    void onSyscallSelected(QListWidgetItem* current, QListWidgetItem* previous);
    void onSettingChanged();
    void useGlobalSettings();
    void resetCurrentSettings();
    void validateCurrentSettings();
    void saveSettings();

private:
    void initUI();

    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;

    void loadSyscalls();
    void loadSyscallSpecificSettings(const QString& syscallName);
    void loadGlobalSettings();
    void saveCurrentSyscallSettings(const QString& syscallName);
    void loadSyscallSettings();

    void enableControls(bool enabled);

    bool validateStubSettings(const QMap<QString, QVariant>& settings, QString& errorMessage);
    void showValidationError(const QString& message);
    void showValidationSuccess(const QString& message);

    QLineEdit* filterInput;
    QListWidget* syscallList;
    QLabel* currentSyscallLabel;
    QTabWidget* settingsTabs;

    QCheckBox* enableJunk;
    QSpinBox* minInstructions;
    QSpinBox* maxInstructions;
    QCheckBox* useAdvancedJunk;

    QCheckBox* enableEncryption;
    QComboBox* encryptionMethod;

    QCheckBox* enableChunking;
    QCheckBox* enableInterleaved;
    QCheckBox* shuffleSequence;

    QSpinBox* syscallPrefixLength;
    QSpinBox* syscallNumberLength;
    QSpinBox* offsetNameLength;

    QCheckBox* enableControlFlow;
    QCheckBox* opaquePredicates;
    QCheckBox* bogusControlFlow;
    QCheckBox* indirectJumps;
    QCheckBox* conditionalBranches;
    QSpinBox* controlFlowComplexity;

    QPushButton* useGlobalBtn;
    QPushButton* resetBtn;

    SettingsTitleBar* titleBar;
    QSettings* settings;

    bool m_dragging = false;
    QPoint m_dragPosition;

    QMap<QString, QVariant> syscallSettings;
};