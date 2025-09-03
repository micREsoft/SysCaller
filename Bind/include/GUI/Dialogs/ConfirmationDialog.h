#pragma once

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QMouseEvent>
#include <QSettings>

class SettingsTitleBar;

class ConfirmationDialog : public QDialog {
    Q_OBJECT

public:
    enum Result {
        Yes,
        No,
        OK,
        Cancel
    };

    explicit ConfirmationDialog(QWidget* parent = nullptr);
    explicit ConfirmationDialog(const QString& title, QWidget* parent = nullptr);
    ~ConfirmationDialog() override;

    void setTitle(const QString& title);
    void setMessage(const QString& message);
    void setButtons(bool showYes = true, bool showNo = true, bool showOK = false, bool showCancel = false);

    Result getResult() const { return result; }

private slots:
    void onYesClicked();
    void onNoClicked();
    void onOKClicked();
    void onCancelClicked();

private:
    void initUI(const QString& title);
    void setupStylesheet();
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;

    QLabel* messageLabel;
    QPushButton* yesButton;
    QPushButton* noButton;
    QPushButton* okButton;
    QPushButton* cancelButton;
    SettingsTitleBar* titleBar;

    Result result = Cancel;

    bool m_dragging = false;
    QPoint m_dragPosition;
};
