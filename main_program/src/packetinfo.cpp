#include "packetinfo.h"

QString PacketInfo::protocolName() const
{
    if (etherType == 0x0806)
        return QStringLiteral("ARP");
    if (etherType == 0x86DD)
        return QStringLiteral("IPv6");
    if (!hasIp)
        return QStringLiteral("Ethernet");

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
        QString s = QStringLiteral("%1:%2 -> %3:%4 [%5] Seq=%6 Win=%7 Len=%8")
                        .arg(srcIp).arg(srcPort).arg(dstIp).arg(dstPort)
                        .arg(fl.isEmpty() ? QStringLiteral("-") : fl.join(QLatin1String(", ")))
                        .arg(seq).arg(window).arg(appPayloadLen);
        if (appProto == AppProto::HTTP && !appPayload.isEmpty()) {
            const int eol = appPayload.indexOf("\r\n");
            s += QStringLiteral("\n") + QString::fromUtf8(
                     appPayload.left(eol < 0 ? qMin(appPayload.size(), 120) : eol));
        }
        return s;
    }
    if (hasUdp) {
        QString s = QStringLiteral("%1:%2 -> %3:%4 Len=%5")
                        .arg(srcIp).arg(srcPort).arg(dstIp).arg(dstPort).arg(appPayloadLen);
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
