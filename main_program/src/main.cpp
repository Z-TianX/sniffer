#include <QApplication>
#include <QStringList>
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
    const QStringList args = app.arguments();

    // 直接进入主界面：不再弹“选择功能模式”对话框，默认不过滤、不自动开始，
    // 选好网卡点“开始抓包”即可（--launcher 参数保留兼容旧快捷方式，已无作用）
    if (args.contains(QStringLiteral("--autostart"))) {
        w.enableAutoDemo(true,
                         argValue(args, QStringLiteral("--bpf")),
                         argValue(args, QStringLiteral("--display")),
                         argValue(args, QStringLiteral("--procdemo")),
                         argValue(args, QStringLiteral("--shots")));
    }
    // 命令行只预填过滤器（不自动开始）
    else if (args.contains(QStringLiteral("--bpf")) || args.contains(QStringLiteral("--display"))) {
        w.setStartupPreset(argValue(args, QStringLiteral("--bpf")),
                           argValue(args, QStringLiteral("--display")), false, false);
    }

    w.show();
    return app.exec();
}
