#include "packetinfo.h"
#include <QStringList>

// IPv6 地址：RFC 5952 压缩写法（最长连续全零段（≥2 组）缩为 ::）
QString ipv6ToString(const unsigned char* p)
{
    quint16 g[8];
    for (int i = 0; i < 8; ++i)
        g[i] = quint16((quint16(p[2 * i]) << 8) | p[2 * i + 1]);

    int bestStart = -1, bestLen = 0;
    for (int i = 0, s = -1, l = 0; i < 8; ++i) {
        if (g[i] == 0) { if (s < 0) s = i; ++l; if (l > bestLen) { bestLen = l; bestStart = s; } }
        else { s = -1; l = 0; }
    }

    QStringList parts;
    if (bestLen >= 2 && bestStart == 0)
        parts.append(QString());                 // "::" 开头
    for (int i = 0; i < 8; ++i) {
        if (bestLen >= 2 && i >= bestStart && i < bestStart + bestLen)
            continue;                            // 被压缩的全零段
        parts.append(QString::number(g[i], 16));
        if (bestLen >= 2 && i + 1 == bestStart)
            parts.append(QString());             // 中间的 "::"
    }
    if (bestLen >= 2 && bestStart + bestLen == 8)
        parts.append(QString());                 // "::" 结尾
    return parts.join(QLatin1Char(':'));
}

// 端点显示：IPv6 地址加方括号，避免与端口混淆（RFC 3986 形式 [addr]:port）
static QString endpoint(const QString& ip, quint16 port)
{
    return ip.contains(QLatin1Char(':'))
        ? QStringLiteral("[%1]:%2").arg(ip).arg(port)
        : QStringLiteral("%1:%2").arg(ip).arg(port);
}

QString PacketInfo::protocolName() const
{
    if (etherType == 0x0806)
        return QStringLiteral("ARP");
    if (!hasIp)
        return (etherType == 0x86DD) ? QStringLiteral("IPv6") : QStringLiteral("Ethernet");
    if (!hasTcp && !hasUdp && !hasIcmp)
        return (ipVersion == 6) ? QStringLiteral("IPv6") : QStringLiteral("IP");

    QString base;
    switch (transport) {
    case TransportType::TCP:  base = QStringLiteral("TCP");  break;
    case TransportType::UDP:  base = QStringLiteral("UDP");  break;
    case TransportType::ICMP: base = QStringLiteral("ICMP"); break;
    default:                  base = QStringLiteral("IP");   break;
    }

    switch (appProto) {
    case AppProto::HTTP: return base + QStringLiteral("/HTTP");
    case AppProto::DNS:  return base + QStringLiteral("/DNS");
    case AppProto::TLS:  return QStringLiteral("TLS");
    case AppProto::DHCP: return base + QStringLiteral("/DHCP");
    default:             return base;
    }
}

QString PacketInfo::summary() const
{
    if (!summaryExtra.isEmpty())
        return summaryExtra;

    if (hasTcp) {
        QStringList fl;
        if (syn)  fl << QStringLiteral("SYN");
        if (ackF) fl << QStringLiteral("ACK");
        if (fin)  fl << QStringLiteral("FIN");
        if (rst)  fl << QStringLiteral("RST");
        if (psh)  fl << QStringLiteral("PSH");
        if (urg)  fl << QStringLiteral("URG");
        QString s = QStringLiteral("%1 -> %2 [%3] Seq=%4 Win=%5 Len=%6")
                        .arg(endpoint(srcIp, srcPort), endpoint(dstIp, dstPort),
                             fl.isEmpty() ? QStringLiteral("-") : fl.join(QLatin1String(", ")))
                        .arg(seq).arg(window).arg(appPayloadLen);
        if (appProto == AppProto::HTTP && !appPayload.isEmpty()) {
            const int eol = appPayload.indexOf("\r\n");
            s += QStringLiteral("\n") + QString::fromUtf8(
                     appPayload.left(eol < 0 ? qMin(appPayload.size(), 120) : eol));
        }
        return s;
    }
    if (hasUdp) {
        QString s = QStringLiteral("%1 -> %2 Len=%3")
                        .arg(endpoint(srcIp, srcPort), endpoint(dstIp, dstPort))
                        .arg(appPayloadLen);
        if (appProto == AppProto::DNS && appPayload.size() >= 2) {
            const quint16 dnsId = quint16(quint8(appPayload[0]) << 8) | quint8(appPayload[1]);
            s += QStringLiteral(" DNS id=0x%1").arg(dnsId, 4, 16, QChar('0'));
        }
        return s;
    }
    if (hasIcmp)
        return QStringLiteral("Type=%1 Code=%2").arg(icmpType).arg(icmpCode);
    return QStringLiteral("");
}
