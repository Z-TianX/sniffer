#pragma once
#include <QHash>
#include <QObject>
#include <QTimer>
#include <QString>

// 显式加分 2：TCP 流映射本机进程 PID 与进程名
// Windows API GetTcpTable2() 定时获取系统 TCP 连接表，
// 构建 (本地IP, 本地端口) → PID 映射哈希；
// 再通过 OpenProcess + QueryFullProcessImageNameW 获取进程 exe 名称。
// 限制：仅本机 TCP 连接有效，无法获取局域网其他主机的进程信息。
class ProcessMapper : public QObject
{
    Q_OBJECT
public:
    struct Result {
        quint32 pid = 0;
        QString name;
    };

    explicit ProcessMapper(QObject* parent = nullptr);

    void start(int intervalMs = 2000);   // 定时刷新 TCP 连接表
    void stop();

    // 抓到 TCP 报文后用四元组查询：依次尝试 (srcIp,srcPort) 与 (dstIp,dstPort)
    Result lookup(const QString& srcIp, quint16 srcPort,
                  const QString& dstIp, quint16 dstPort);

public slots:
    void refresh();

private:
    QString nameFor(quint32 pid);
    static QString keyOf(const QString& ip, quint16 port);

    QHash<QString, quint32> m_connTable;    // "ip:port" → PID
    QHash<quint32, QString> m_pidNames;     // PID → 进程名缓存
    QTimer* m_timer = nullptr;
};
