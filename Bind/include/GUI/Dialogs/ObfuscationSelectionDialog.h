#ifndef OBFUSCATIONSELECTIONDIALOG_H
#define OBFUSCATIONSELECTIONDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

class ObfuscationSelectionDialog : public QDialog {
    Q_OBJECT

public:
    explicit ObfuscationSelectionDialog(QWidget* parent = nullptr);
    
    enum Selection {
        NormalObfuscation,
        StubMapper,
        Cancelled
    };
    
    Selection getSelection() const { return selection; }

private slots:
    void onNormalObfuscationClicked();
    void onStubMapperClicked();
    void onCancelClicked();

private:
    void setupStylesheet();
    void initUI();
    
    Selection selection;
    QLabel* titleLabel;
    QLabel* descriptionLabel;
    QPushButton* normalObfuscationButton;
    QPushButton* stubMapperButton;
    QPushButton* cancelButton;
};

#endif