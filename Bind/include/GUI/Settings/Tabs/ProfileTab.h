#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QFileDialog>
#include <QMessageBox>
#include <QSettings>
#include <QApplication>

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