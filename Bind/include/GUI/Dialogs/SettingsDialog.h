#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QPushButton>
#include <QSettings>
#include <QMouseEvent>

class SettingsTitleBar;
class GeneralTab;
class ObfuscationTab;
class IntegrityTab;
class ProfileTab;
class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget* parent = nullptr);

private slots:
    void saveSettings();
    void openStubMapper();

private:
    void initUI();
    void setupStylesheet();
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    QSettings* settings;
    QTabWidget* tabs;
    SettingsTitleBar* titleBar;
    GeneralTab* generalTab;
    ObfuscationTab* obfuscationTab;
    IntegrityTab* integrityTab;
    ProfileTab* profileTab;
    bool m_dragging = false;
    QPoint m_dragPosition;
};

#endif
