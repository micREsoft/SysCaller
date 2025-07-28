#pragma once

#include <QString>

class Colors {
public:
    static QString OKBLUE() { return "<span style='color: #4880a8;'>"; }
    static QString OKGREEN() { return "<span style='color: #4CAF50;'>"; }
    static QString WARNING() { return "<span style='color: #FF9800;'>"; }
    static QString FAIL() { return "<span style='color: #F44336;'>"; }
    static QString ENDC() { return "</span>"; }
    static QString BOLD() { return "<span style='font-weight: bold;'>"; }
    static QString UNDERLINE() { return "<span style='text-decoration: underline;'>"; }
};
