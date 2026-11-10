#include <QApplication>
#include "mainwindow.h"
#include "packetinfo.h"

int main(int argc, char* argv[])
{
    // PacketInfo 通过信号槽跨线程（QueuedConnection）传递，需注册元类型
    qRegisterMetaType<PacketInfo>("PacketInfo");

    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("NetSniffer"));
    app.setOrganizationName(QStringLiteral("NetSecLab"));

    MainWindow w;
    w.show();
    return app.exec();
}
