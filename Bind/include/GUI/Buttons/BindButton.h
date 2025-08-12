#pragma once

#include <QPushButton>
#include <QString>

class BindButton : public QPushButton {
    Q_OBJECT

public:
    BindButton(const QString& text, const QString& iconPath, 
                const QString& title, const QString& description, 
                QWidget* parent = nullptr);

private:
    void setupStyle();
    QString title;
    QString description;
};