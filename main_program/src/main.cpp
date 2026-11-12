#include <QApplication>
#include "mainwindow.h"
#include "packetinfo.h"

static QString argValue(const QStringList& args, const QString& name)
{
    const int i = args.indexOf(name);
    return (i >= 0 && i + 1 < args.size()) ? args[i + 1] : QString();
}

int main(int argc, char* argv[])
{
    // PacketInfo 通过信号槽跨线程（QueuedConnection）传递，需注册元类型
    qRegisterMetaType<PacketInfo>("PacketInfo");

    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("NetSniffer"));
    app.setOrganizationName(QStringLiteral("NetSecLab"));

    MainWindow w;
    // --autostart：自动演示（录屏/截图用）
    //   --bpf <expr>     BPF 内核捕获过滤器
    //   --display <expr> 用户态显示过滤器
    if (app.arguments().contains(QStringLiteral("--autostart"))) {
        w.enableAutoDemo(true,
                         argValue(app.arguments(), QStringLiteral("--bpf")),
                         argValue(app.arguments(), QStringLiteral("--display")),
                         argValue(app.arguments(), QStringLiteral("--procdemo")),
                         argValue(app.arguments(), QStringLiteral("--shots")));
    }
    w.show();
    return app.exec();
}
