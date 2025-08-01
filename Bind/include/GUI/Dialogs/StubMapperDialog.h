#ifndef STUBMAPPERDIALOG_H
#define STUBMAPPERDIALOG_H

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

class StubMapperDialog : public QDialog {
    Q_OBJECT

public:
    explicit StubMapperDialog(QWidget* parent = nullptr);
    ~StubMapperDialog();

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
    void loadSyscalls();
    void loadSyscallSpecificSettings(const QString& syscallName);
    void loadGlobalSettings();
    void saveCurrentSyscallSettings(const QString& syscallName);
    void enableControls(bool enabled);
    void loadSyscallSettings();
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
    QPushButton* useGlobalBtn;
    QPushButton* resetBtn;
    QSettings* settings;
    QMap<QString, QVariant> syscallSettings;
    bool validateStubSettings(const QMap<QString, QVariant>& settings, QString& errorMessage);
    void showValidationError(const QString& message);
    void showValidationSuccess(const QString& message);
};

#endif
