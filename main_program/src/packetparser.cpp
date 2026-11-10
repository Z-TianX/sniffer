#include "packetparser.h"
#include <QDateTime>
#include <QRegularExpression>
#include <QStringList>
#include <winsock2.h>

// ------------------------------------------------------------------
// 辅助：安全读取大端字段（网络字节序，必须 ntohs/ntohl 转换）
// ------------------------------------------------------------------
static inline quint16 readU16(const unsigned char* p)
{
    u_short v;
    memcpy(&v, p, 2);
    return ntohs(v);
}

static inline quint32 readU32(const unsigned char* p)
{
    u_long v;
    memcpy(&v, p, 4);
    return ntohl(v);
}

static QString macToString(const unsigned char* m)
{
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(m[0], 2, 16, QChar('0')).arg(m[1], 2, 16, QChar('0'))
        .arg(m[2], 2, 16, QChar('0')).arg(m[3], 2, 16, QChar('0'))
        .arg(m[4], 2, 16, QChar('0')).arg(m[5], 2, 16, QChar('0')).toUpper();
}

static QString ipToString(const unsigned char* p)
{
    return QString("%1.%2.%3.%4").arg(p[0]).arg(p[1]).arg(p[2]).arg(p[3]);
}

// IPv6 地址：RFC 5952 压缩写法（最长连续全零段（≥2 组）缩为 ::）
static QString ipv6ToString(const unsigned char* p)
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

// ------------------------------------------------------------------
// 主解析函数：Frame → Ethernet → IPv4(IHL) → TCP/UDP/ICMP → 应用层
// ------------------------------------------------------------------
void Parser::parse(const unsigned char* d, int len, PacketInfo& pkt)
{
    if (!d || len < 14)
        return;

    pkt.raw = QByteArray(reinterpret_cast<const char*>(d), len);

    // ================= 以太网头 =================
    pkt.dstMac = macToString(d);
    pkt.srcMac = macToString(d + 6);

    int off = 12;                 // ether_type 字段位置
    quint16 etherType = readU16(d + off);

    // 处理 802.1Q VLAN 标签（0x8100），真实类型在 4 字节标签之后
    while (etherType == 0x8100 && off + 6 <= len) {
        off += 4;
        etherType = readU16(d + off);
    }
    pkt.etherType = etherType;
    off += 2; // off 现在指向网络层起始

    // ARP 帧（0x0806）
    if (etherType == 0x0806) {
        pkt.transport = TransportType::Other;
        if (off + 28 <= len) {
            const quint16 op = readU16(d + off + 6);
            const QString senderIp = ipToString(d + off + 14);
            const QString targetIp = ipToString(d + off + 24);
            pkt.summaryExtra = (op == 1)
                ? QString("Who has %1? Tell %2").arg(targetIp, senderIp)
                : QString("%1 is at %2").arg(senderIp, macToString(d + off + 8));
        }
        return;
    }

    // IPv6：40 字节定长头 + 扩展头跳过，随后与 IPv4 共用 TCP/UDP/ICMP 解析逻辑
    int pl = 0;                 // 传输层偏移
    int ipPayloadLen = 0;       // 传输层载荷长度
    if (etherType == 0x86DD) {
        if (off + 40 > len || (d[off] >> 4) != 6)
            return;
        pkt.hasIp     = true;
        pkt.ipVersion = 6;
        pkt.ipIhl     = 40;                          // IPv6 固定头 40 字节
        pkt.ipTotalLen = 40 + readU16(d + off + 4);  // 载荷长度字段
        pkt.ttl       = d[off + 7];                  // Hop Limit
        pkt.ipProto   = d[off + 6];                  // Next Header
        pkt.srcIp     = ipv6ToString(d + off + 8);
        pkt.dstIp     = ipv6ToString(d + off + 24);

        // 跳过扩展头：Hop-by-Hop(0)/Routing(43)/Fragment(44)/DestOpts(60)
        // 每个扩展头首字节是下一头部类型，第二字节是长度字段（单位 8 字节，不含前 8 字节）
        quint8 nh = d[off + 6];
        int ext = off + 40;
        while (nh == 0 || nh == 43 || nh == 44 || nh == 60) {
            if (ext + 8 > len)
                return;
            const int extLen = (nh == 44) ? 8 : (d[ext + 1] + 1) * 8;
            nh = d[ext];
            ext += extLen;
        }
        pkt.ipProto = nh;
        pl = ext;
        ipPayloadLen = qMax(0, qMin<int>(pkt.ipTotalLen, len - off) - 40);
    }
    // ================= IPv4 头（处理 IHL 可变头部） =================
    else if (etherType == 0x0800 && off + 20 <= len && (d[off] >> 4) == 4) {
        pkt.hasIp = true;
        pkt.ipVersion = d[off] >> 4;
        pkt.ipIhl = (d[off] & 0x0F) * 4;              // IHL 可变头部，禁止写死 20 字节
        if (pkt.ipIhl < 20 || off + pkt.ipIhl > len)
            return;

        pkt.ipTotalLen = readU16(d + off + 2);
        pkt.ipId       = readU16(d + off + 4);
        pkt.ttl        = d[off + 8];
        pkt.ipProto    = d[off + 9];
        pkt.ipChecksum = readU16(d + off + 10);
        pkt.srcIp      = ipToString(d + off + 12);
        pkt.dstIp      = ipToString(d + off + 16);

        pl = off + pkt.ipIhl;               // 传输层偏移
        ipPayloadLen = (pkt.ipTotalLen > 0)
            ? int(qMin<quint32>(pkt.ipTotalLen, quint32(len - off))) - pkt.ipIhl
            : len - pl;
        ipPayloadLen = qMax(0, ipPayloadLen);
    }
    else {
        return;
    }

    // ================= TCP 头（处理可变头部） =================
    if (pkt.ipProto == 6 && pl + 20 <= len) {
        pkt.hasTcp = true;
        pkt.transport = TransportType::TCP;
        pkt.srcPort = readU16(d + pl);
        pkt.dstPort = readU16(d + pl + 2);
        pkt.seq     = readU32(d + pl + 4);
        pkt.ackNum  = readU32(d + pl + 8);
        pkt.tcpDataOffset = (d[pl + 12] >> 4) * 4;   // TCP 头部长度同样可变

        const quint8 fl = d[pl + 13];
        pkt.fin  = fl & 0x01;
        pkt.syn  = fl & 0x02;
        pkt.rst  = fl & 0x04;
        pkt.psh  = fl & 0x08;
        pkt.ackF = fl & 0x10;
        pkt.urg  = fl & 0x20;

        pkt.window      = readU16(d + pl + 14);
        pkt.tcpChecksum = readU16(d + pl + 16);

        const int appOff = pl + qMax<int>(pkt.tcpDataOffset, 20);
        if (appOff <= len) {
            pkt.appLayerOffset = appOff;
            pkt.appPayloadLen  = qMax(0, qMin(ipPayloadLen - pkt.tcpDataOffset, len - appOff));
            pkt.appPayload = QByteArray(reinterpret_cast<const char*>(d + appOff), pkt.appPayloadLen);
        }
    }
    // ================= UDP 头 =================
    else if (pkt.ipProto == 17 && pl + 8 <= len) {
        pkt.hasUdp = true;
        pkt.transport = TransportType::UDP;
        pkt.srcPort = readU16(d + pl);
        pkt.dstPort = readU16(d + pl + 2);
        pkt.udpLen      = readU16(d + pl + 4);
        pkt.udpChecksum = readU16(d + pl + 6);

        const int appOff = pl + 8;
        if (appOff <= len) {
            pkt.appLayerOffset = appOff;
            const int udpPayload = pkt.udpLen >= 8 ? pkt.udpLen - 8 : 0;
            pkt.appPayloadLen  = qMax(0, qMin(udpPayload, len - appOff));
            pkt.appPayload = QByteArray(reinterpret_cast<const char*>(d + appOff), pkt.appPayloadLen);
        }
    }
    // ================= ICMP / ICMPv6 头（ping 报文解析） =================
    else if ((pkt.ipProto == 1 || pkt.ipProto == 58) && pl + 4 <= len) {
        pkt.hasIcmp = true;
        pkt.transport = TransportType::ICMP;
        pkt.icmpType = d[pl];
        pkt.icmpCode = d[pl + 1];
        const bool v4Echo = (pkt.icmpType == 8 || pkt.icmpType == 0);
        const bool v6Echo = (pkt.icmpType == 128 || pkt.icmpType == 129);
        if (v4Echo || v6Echo) {
            const quint16 ident = readU16(d + pl + 4);
            const quint16 seqn  = readU16(d + pl + 6);
            const bool isReq = (pkt.icmpType == 8 || pkt.icmpType == 128);
            pkt.summaryExtra = isReq
                ? QString("Echo (ping) request  id=0x%1 seq=%2").arg(ident, 4, 16, QChar('0')).arg(seqn)
                : QString("Echo (ping) reply    id=0x%1 seq=%2").arg(ident, 4, 16, QChar('0')).arg(seqn);
        }
    }
    else {
        pkt.transport = TransportType::Other;
        return;
    }

    // ================= 应用层识别 =================
    const QByteArray& p = pkt.appPayload;
    if (pkt.transport == TransportType::TCP && !p.isEmpty()) {
        const bool httpCmd = p.startsWith("GET ") || p.startsWith("POST ") ||
                             p.startsWith("HEAD ") || p.startsWith("PUT ") ||
                             p.startsWith("DELETE ") || p.startsWith("OPTIONS ") ||
                             p.startsWith("HTTP/");
        if (httpCmd || pkt.srcPort == 80 || pkt.dstPort == 80)
            pkt.appProto = AppProto::HTTP;                    // HTTP 明文
        else if ((quint8)p[0] == 0x16 && (quint8)p[1] == 0x03)
            pkt.appProto = AppProto::TLS;                     // TLS 握手记录，密文不解密
        else if (pkt.srcPort == 443 || pkt.dstPort == 443)
            pkt.appProto = AppProto::TLS;                     // HTTPS 识别，输出原始载荷
    } else if (pkt.transport == TransportType::UDP) {
        if (pkt.srcPort == 53 || pkt.dstPort == 53)
            pkt.appProto = AppProto::DNS;                     // DNS (UDP 53)
        else if (pkt.srcPort == 67 || pkt.dstPort == 67 || pkt.srcPort == 68 || pkt.dstPort == 68)
            pkt.appProto = AppProto::DHCP;
    }
}

// ------------------------------------------------------------------
// 十六进制 + ASCII 视图
// ------------------------------------------------------------------
QString Parser::hexDump(const unsigned char* data, int len)
{
    QString out;
    out.reserve(len * 6);
    for (int off = 0; off < len; off += 16) {
        out += QString("%1  ").arg(off, 4, 16, QChar('0')).toUpper();
        QString ascii;
        for (int i = 0; i < 16; ++i) {
            if (off + i < len) {
                const unsigned char c = data[off + i];
                out += QString("%1 ").arg(c, 2, 16, QChar('0')).toUpper();
                ascii += (c >= 0x20 && c < 0x7F) ? QChar(c) : QChar('.');
            } else {
                out += QLatin1String("   ");
            }
            if (i == 7)
                out += QLatin1Char(' ');
        }
        out += QLatin1String(" |") + ascii + QLatin1String("|\n");
    }
    return out;
}

// ------------------------------------------------------------------
// 用户态显示过滤器（软件逻辑过滤，全部报文保留在内存中）
// ------------------------------------------------------------------
static bool matchProtocol(const PacketInfo& pkt, const QString& kw)
{
    if (kw == QLatin1String("arp"))   return pkt.etherType == 0x0806;
    if (kw == QLatin1String("ipv6") || kw == QLatin1String("ip6")) return pkt.etherType == 0x86DD;
    if (kw == QLatin1String("ipv4") || kw == QLatin1String("ip4")) return pkt.etherType == 0x0800;
    if (kw == QLatin1String("ip"))    return pkt.hasIp;
    if (kw == QLatin1String("tcp"))   return pkt.hasTcp;
    if (kw == QLatin1String("udp"))   return pkt.hasUdp;
    if (kw == QLatin1String("icmp"))  return pkt.hasIcmp;
    if (kw == QLatin1String("icmpv6") || kw == QLatin1String("icmp6"))
        return pkt.hasIcmp && pkt.ipVersion == 6;
    if (kw == QLatin1String("http"))  return pkt.appProto == AppProto::HTTP;
    if (kw == QLatin1String("dns"))   return pkt.appProto == AppProto::DNS;
    if (kw == QLatin1String("tls") || kw == QLatin1String("ssl") || kw == QLatin1String("https"))
        return pkt.appProto == AppProto::TLS;
    if (kw == QLatin1String("dhcp"))  return pkt.appProto == AppProto::DHCP;
    // 进程相关关键字：只显示能映射到本机进程的报文
    if (kw == QLatin1String("pid"))   return pkt.pid != 0;
    if (kw == QLatin1String("proc"))  return !pkt.procName.isEmpty();
    return false;
}

static bool evalCompare(const PacketInfo& pkt, const QString& field, const QString& value, bool neq)
{
    bool eq = false;
    if (field == QLatin1String("ip.addr"))        eq = (pkt.srcIp == value || pkt.dstIp == value);
    else if (field == QLatin1String("ip.src"))    eq = (pkt.srcIp == value);
    else if (field == QLatin1String("ip.dst"))    eq = (pkt.dstIp == value);
    else if (field == QLatin1String("tcp.port"))  eq = pkt.hasTcp && (pkt.srcPort == value.toUShort() || pkt.dstPort == value.toUShort());
    else if (field == QLatin1String("udp.port"))  eq = pkt.hasUdp && (pkt.srcPort == value.toUShort() || pkt.dstPort == value.toUShort());
    else if (field == QLatin1String("tcp.srcport")) eq = pkt.hasTcp && pkt.srcPort == value.toUShort();
    else if (field == QLatin1String("tcp.dstport")) eq = pkt.hasTcp && pkt.dstPort == value.toUShort();
    else if (field == QLatin1String("udp.srcport")) eq = pkt.hasUdp && pkt.srcPort == value.toUShort();
    else if (field == QLatin1String("udp.dstport")) eq = pkt.hasUdp && pkt.dstPort == value.toUShort();
    // 进程筛选：某进程产生的所有（TCP）流 —— proc == 进程名（子串，忽略大小写）/ pid == 数字
    else if (field == QLatin1String("pid") || field == QLatin1String("process.pid"))
        eq = pkt.pid != 0 && pkt.pid == value.toUInt();
    else if (field == QLatin1String("proc") || field == QLatin1String("process.name"))
        eq = !pkt.procName.isEmpty() && pkt.procName.toLower().contains(value);
    else if (field == QLatin1String("frame.len"))
        eq = pkt.raw.size() == value.toInt();
    return neq ? !eq : eq;
}

// 在括号之外按逻辑运算符切分（splitOr=true 按 || 切，false 按 && 切）
static QStringList splitTopLevel(const QString& s, bool splitOr)
{
    QStringList out;
    QString cur;
    int depth = 0;
    for (int i = 0; i < s.size(); ++i) {
        const QChar c = s.at(i);
        if (c == QLatin1Char('('))      ++depth;
        else if (c == QLatin1Char(')')) depth = qMax(0, depth - 1);

        if (depth == 0 && i + 1 < s.size()) {
            const QChar n = s.at(i + 1);
            if (splitOr && c == QLatin1Char('|') && n == QLatin1Char('|')) {
                out << cur; cur.clear(); ++i; continue;
            }
            if (!splitOr && c == QLatin1Char('&') && n == QLatin1Char('&')) {
                out << cur; cur.clear(); ++i; continue;
            }
        }
        cur += c;
    }
    out << cur;
    return out;
}

// 原子表达式：! 取反（可叠加）、( ... ) 分组递归、field ==/!= value、协议关键字
static bool evalAtom(const PacketInfo& pkt, const QString& raw)
{
    QString t = raw.trimmed();
    if (t.isEmpty())
        return true;

    bool negate = false;
    while (t.startsWith(QLatin1Char('!'))) {
        negate = !negate;
        t = t.mid(1).trimmed();
    }
    if (t.startsWith(QLatin1Char('(')) && t.endsWith(QLatin1Char(')'))) {
        const bool v = Parser::matchDisplayFilter(pkt, t.mid(1, t.size() - 2));
        return negate ? !v : v;
    }

    const QString lower = t.toLower();
    bool val = false;
    const int neqPos = lower.indexOf(QLatin1String("!="));
    const int eqPos  = lower.indexOf(QLatin1String("=="));
    if (neqPos > 0)
        val = evalCompare(pkt, lower.left(neqPos).trimmed(), lower.mid(neqPos + 2).trimmed(), true);
    else if (eqPos > 0)
        val = evalCompare(pkt, lower.left(eqPos).trimmed(), lower.mid(eqPos + 2).trimmed(), false);
    else
        val = matchProtocol(pkt, lower.trimmed());
    return negate ? !val : val;
}

bool Parser::matchDisplayFilter(const PacketInfo& pkt, const QString& filter)
{
    QString f = filter.trimmed();
    if (f.isEmpty())
        return true;

    // 单词逻辑运算符归一化为符号形式（or → ||、and → &&），供后续统一解析
    static const QRegularExpression orRe(QStringLiteral("\\s+or\\s+"),
                                         QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression andRe(QStringLiteral("\\s+and\\s+"),
                                          QRegularExpression::CaseInsensitiveOption);
    f.replace(orRe, QStringLiteral(" || "));
    f.replace(andRe, QStringLiteral(" && "));

    // 优先级：! (最高) > && > || (最低)；括号可改变优先级
    const QStringList orTerms = splitTopLevel(f, true);
    for (const QString& orTerm : orTerms) {
        if (orTerm.trimmed().isEmpty())
            continue;
        bool all = true;
        const QStringList andTerms = splitTopLevel(orTerm, false);
        for (const QString& andTerm : andTerms) {
            if (andTerm.trimmed().isEmpty())
                continue;
            if (!evalAtom(pkt, andTerm)) { all = false; break; }
        }
        if (all)
            return true;
    }
    return false;
}
