#include <QApplication>
#include "include/GUI/MainWindow.h"
#include "include/Core/Utils/PathUtils.h"
#include <QFontDatabase>
#include <QStyleFactory>
#include <QFont>
#include <QSettings>
#include <QIcon>

int main(int argc, char *argv[]) {
    qputenv("QT_LOGGING_RULES", "*.debug=true;qt.qpa.*=false");
    QApplication app(argc, argv);
    app.setStyle(QStyleFactory::create("Fusion"));
    app.setWindowIcon(QIcon(":/src/Res/Icons/logo.ico"));
    int fontId = QFontDatabase::addApplicationFont(":/src/Res/Fonts/ibmplexmono.ttf");
    if (fontId != -1) {
        QStringList fontFamilies = QFontDatabase::applicationFontFamilies(fontId);
        if (!fontFamilies.isEmpty()) {
            app.setFont(QFont(fontFamilies.first(), 10));
        }
    }
    app.setStyleSheet(
        "* {"
        " font-family: 'IBM Plex Mono';"
        "}"
        "QToolTip {"
        " background-color: #1E1E1E;"
        " color: white;"
        " border: 1px solid #2196F3;"
        " border-radius: 4px;"
        " padding: 5px;"
        " font-family: 'IBM Plex Mono';"
        "}"
    );
    QString projectRoot = PathUtils::getProjectRoot();
    MainWindow w;
    w.show();
    return app.exec();
}