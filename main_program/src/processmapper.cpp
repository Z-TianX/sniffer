#include "processmapper.h"
#include "packetinfo.h"   // ipv6ToString()：与解析器保持一致的地址格式
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#endif

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

// 获取系统连接表（TCP4/TCP6/UDP4/UDP6，均含 PID 归属）
void ProcessMapper::refresh()
{
    QHash<QString, quint32> newTable;
    newTable.reserve(512);

    // ---------------- IPv4 TCP（GetTcpTable2） ----------------
    DWORD size = 0;
    if (GetTcpTable2(nullptr, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<char> buf(size);
        auto* t = reinterpret_cast<MIB_TCPTABLE2*>(buf.data());
        if (GetTcpTable2(t, &size, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const MIB_TCPROW2& r = t->table[i];
                IN_ADDR a;
                a.S_un.S_addr = r.dwLocalAddr;      // 网络字节序
                char ip[INET_ADDRSTRLEN] = {0};
                if (!inet_ntop(AF_INET, &a, ip, sizeof(ip)))
                    continue;
                newTable.insert(keyOf(QString::fromLatin1(ip), ntohs(u_short(r.dwLocalPort))),
                                r.dwOwningPid);
            }
        }
    }

    // ---------------- IPv6 TCP（GetTcp6Table2） ----------------
    size = 0;
    if (GetTcp6Table2(nullptr, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<char> buf(size);
        auto* t = reinterpret_cast<MIB_TCP6TABLE2*>(buf.data());
        if (GetTcp6Table2(t, &size, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const MIB_TCP6ROW2& r = t->table[i];
                newTable.insert(keyOf(ipv6ToString(r.LocalAddr.u.Byte), ntohs(u_short(r.dwLocalPort))),
                                r.dwOwningPid);
            }
        }
    }

    // ---------------- IPv4 UDP（GetExtendedUdpTable / OWNER_PID） ----------------
    size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0)
            == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<char> buf(size);
        auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
        if (GetExtendedUdpTable(t, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const MIB_UDPROW_OWNER_PID& r = t->table[i];
                IN_ADDR a;
                a.S_un.S_addr = r.dwLocalAddr;
                char ip[INET_ADDRSTRLEN] = {0};
                if (!inet_ntop(AF_INET, &a, ip, sizeof(ip)))
                    continue;
                newTable.insert(keyOf(QString::fromLatin1(ip), ntohs(u_short(r.dwLocalPort))),
                                r.dwOwningPid);
            }
        }
    }

    // ---------------- IPv6 UDP（GetExtendedUdpTable / AF_INET6） ----------------
    size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0)
            == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<char> buf(size);
        auto* t = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
        if (GetExtendedUdpTable(t, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const MIB_UDP6ROW_OWNER_PID& r = t->table[i];
                newTable.insert(keyOf(ipv6ToString(r.ucLocalAddr), ntohs(u_short(r.dwLocalPort))),
                                r.dwOwningPid);
            }
        }
    }

    m_connTable = std::move(newTable);
    emit tableUpdated();
}

// 查单个端点：先精确匹配 (ip,port)；UDP 套接字通常绑定在通配地址上
// （0.0.0.0 / ::），因此再回退匹配通配地址 + 端口
quint32 ProcessMapper::probe(const QString& ip, quint16 port) const
{
    quint32 pid = m_connTable.value(keyOf(ip, port), 0);
    if (!pid)
        pid = m_connTable.value(keyOf(QStringLiteral("0.0.0.0"), port), 0);
    if (!pid)
        pid = m_connTable.value(keyOf(QStringLiteral("::"), port), 0);
    return pid;
}

ProcessMapper::Result ProcessMapper::lookup(const QString& srcIp, quint16 srcPort,
                                            const QString& dstIp, quint16 dstPort)
{
    Result r;
    // 本机侧端点必在连接表中：先试源端点，再试目的端点
    quint32 pid = probe(srcIp, srcPort);
    if (!pid)
        pid = probe(dstIp, dstPort);
    if (!pid)
        return r;   // 非本机连接，返回空

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
