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
    // --autostart：自动演示（录屏/截图用）：自动抓包→选中 TCP 报文→弹 TCP 流窗口
    if (app.arguments().contains(QStringLiteral("--autostart")))
        w.enableAutoDemo(true);
    w.show();
    return app.exec();
}
