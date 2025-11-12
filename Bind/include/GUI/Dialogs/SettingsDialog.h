#pragma once

#include <QDialog>
#include <QHBoxLayout>
#include <QMouseEvent>
#include <QPushButton>
#include <QResizeEvent>
#include <QSettings>
#include <QTabWidget>
#include <QVBoxLayout>

class SettingsTitleBar;
class GeneralTab;
class ObfuscationTab;
class IndirectObfuscationTab;
class InlineObfuscationTab;
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
    void resizeEvent(QResizeEvent* event) override;

    QSettings* settings;
    QTabWidget* tabs;
    SettingsTitleBar* titleBar;
    GeneralTab* generalTab;
    ObfuscationTab* obfuscationTab;
    IndirectObfuscationTab* indirectObfuscationTab;
    InlineObfuscationTab* inlineObfuscationTab;
    IntegrityTab* integrityTab;
    ProfileTab* profileTab;

    bool m_dragging = false;
    QPoint m_dragPosition;
};