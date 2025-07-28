#pragma once
#include <QFrame>
#include <QPoint>

class QLabel;
class QPushButton;
class QVBoxLayout;
class QHBoxLayout;
class QListWidget;
class ProgressBar;
class BindButton;

class LeftPanel : public QFrame {
    Q_OBJECT
public:
    explicit LeftPanel(QWidget* parent = nullptr);

signals:
    void settingsButtonClicked();
    void validationButtonClicked();
    void compatibilityButtonClicked();
    void verificationButtonClicked();
    void obfuscationButtonClicked();
    void dllPathsChanged(const QStringList& paths);

private slots:
    void browseDll();
    void removeSelectedDll();
    void showContextMenu(const QPoint& pos);
    void showChangelogDialog();

public slots:
    void setProgressIndeterminate(bool indeterminate);
    void updateStatus(const QString& message);

public:
    QStringList getDllPaths() const;

private:
    QLabel* logoImage;
    QLabel* logoLabel;
    QLabel* versionLabel;
    QListWidget* dllList;
    QPushButton* addDllBtn;
    QPushButton* removeDllBtn;
    BindButton* validateBtn;
    BindButton* compatibilityBtn;
    BindButton* verifyBtn;
    BindButton* obfuscateBtn;
    BindButton* settingsBtn;
    ProgressBar* progressBar;
    QLabel* statusLabel;
}; 