#pragma once

#include <QApplication>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QVBoxLayout>
#include <QWidget>

class ProfileTab : public QWidget {
    Q_OBJECT

public:
    explicit ProfileTab(QSettings* settings, QWidget* parent = nullptr);
    void saveSettings();

private slots:
    void exportProfile();
    void importProfile();

private:
    void initUI();
    QSettings* settings;
};