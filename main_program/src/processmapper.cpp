#include "processmapper.h"
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

ProcessMapper::ProcessMapper(QObject* parent)
    : QObject(parent)
{
    m_timer = new QTimer(this);
    m_timer->setInterval(2000);
    connect(m_timer, &QTimer::timeout, this, &ProcessMapper::refresh);
}

void ProcessMapper::start(int intervalMs)
{
    m_timer->setInterval(intervalMs);
    refresh();
    m_timer->start();
}

void ProcessMapper::stop()
{
    m_timer->stop();
}

// GetTcpTable2 获取系统 TCP 连接表（含 PID）
void ProcessMapper::refresh()
{
    DWORD size = 0;
    if (GetTcpTable2(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<char> buf(size);
    auto* table = reinterpret_cast<MIB_TCPTABLE2*>(buf.data());
    if (GetTcpTable2(table, &size, FALSE) != NO_ERROR)
        return;

    QHash<QString, quint32> newTable;
    newTable.reserve(int(table->dwNumEntries));
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_TCPROW2& r = table->table[i];
        // dwLocalAddr 为网络字节序；dwLocalPort 需 ntohs 转换
        IN_ADDR a;
        a.S_un.S_addr = r.dwLocalAddr;
        char ip[INET_ADDRSTRLEN] = {0};
        if (!inet_ntop(AF_INET, &a, ip, sizeof(ip)))
            continue;
        const quint16 port = ntohs(u_short(r.dwLocalPort));
        newTable.insert(keyOf(QString::fromLatin1(ip), port), r.dwOwningPid);
    }
    m_connTable = std::move(newTable);
}

ProcessMapper::Result ProcessMapper::lookup(const QString& srcIp, quint16 srcPort,
                                            const QString& dstIp, quint16 dstPort)
{
    Result r;
    // 本机侧端点必在连接表中：先试源端点，再试目的端点
    quint32 pid = m_connTable.value(keyOf(srcIp, srcPort), 0);
    if (!pid)
        pid = m_connTable.value(keyOf(dstIp, dstPort), 0);
    if (!pid)
        return r;   // 非本机 TCP 连接，返回空

    r.pid = pid;
    r.name = nameFor(pid);
    return r;
}

QString ProcessMapper::nameFor(quint32 pid)
{
    if (auto it = m_pidNames.constFind(pid); it != m_pidNames.constEnd())
        return *it;

    QString name;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        WCHAR buf[1024];
        DWORD sz = DWORD(sizeof(buf) / sizeof(WCHAR));
        if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
            const QString path = QString::fromWCharArray(buf, int(sz));
            name = path.section(QLatin1Char('\\'), -1);
        }
        CloseHandle(h);
    }
    m_pidNames.insert(pid, name);
    return name;
}

QString ProcessMapper::keyOf(const QString& ip, quint16 port)
{
    return ip + QLatin1Char(':') + QString::number(port);
}
