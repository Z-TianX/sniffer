#include <QApplication>
#include <QInputDialog>
#include <QStringList>
#include <QVector>
#include "mainwindow.h"
#include "packetinfo.h"

static QString argValue(const QStringList& args, const QString& name)
{
    const int i = args.indexOf(name);
    return (i >= 0 && i + 1 < args.size()) ? args[i + 1] : QString();
}

// 启动器预设：一个功能模式 = 名称 + BPF + 显示过滤器 + 是否自动开始 + 是否自动按进程筛选
struct Preset {
    QString name;
    QString bpf;
    QString display;
    bool autoStart;
    bool autoProc;
    bool isAutoDemo;
};

static QVector<Preset> buildPresets()
{
    return {
        {QStringLiteral("① 通用抓包（不过滤，全部报文）"),      QString(), QString(), true,  false, false},
        {QStringLiteral("② 只看 HTTP 明文（80 端口）"),        QStringLiteral("tcp port 80"), QStringLiteral("http"), true, false, false},
        {QStringLiteral("③ 只看 TCP"),                        QStringLiteral("tcp"), QStringLiteral("tcp"), true, false, false},
        {QStringLiteral("④ 只看 UDP / DNS"),                  QStringLiteral("udp"), QStringLiteral("udp"), true, false, false},
        {QStringLiteral("⑤ 只看 ICMP / ping"),                QStringLiteral("icmp"), QStringLiteral("icmp"), true, false, false},
        {QStringLiteral("⑥ 只看 IPv6 流量"),                  QStringLiteral("ip6"), QStringLiteral("ipv6"), true, false, false},
        {QStringLiteral("⑦ 只看 ARP"),                        QStringLiteral("arp"), QStringLiteral("arp"), true, false, false},
        {QStringLiteral("⑧ 只看 TLS/HTTPS（识别不解密）"),     QStringLiteral("tcp"), QStringLiteral("tls"), true, false, false},
        {QStringLiteral("⑨ 按进程筛选 TCP 流（自动选最活跃进程）"), QStringLiteral("tcp"), QString(), true, true, false},
        {QStringLiteral("⑩ 自动演示（录屏用：自动抓包+流追踪）"),  QString(), QString(), false, false, true},
    };
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

    if (args.contains(QStringLiteral("--launcher"))) {
        // 启动模式选择器（桌面快捷方式使用）
        const QVector<Preset> presets = buildPresets();
        QStringList names;
        for (const Preset& p : presets)
            names << p.name;

        bool ok = false;
        const QString chosen = QInputDialog::getItem(
            nullptr,
            QStringLiteral("网络嗅探器 - 选择功能模式"),
            QStringLiteral("请选择本次启动的功能模式：\n"
                           "（选定后窗口内仍可随时修改 BPF / 显示过滤器）"),
            names, 0, false, &ok);
        if (!ok)
            return 0;

        const int idx = names.indexOf(chosen);
        if (idx >= 0) {
            const Preset& p = presets[idx];
            if (p.isAutoDemo)
                w.enableAutoDemo(true);
            else
                w.setStartupPreset(p.bpf, p.display, p.autoStart, p.autoProc);
        }
    }
    // 命令行直连的自动演示（优先级高于纯预填）
    else if (args.contains(QStringLiteral("--autostart"))) {
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
