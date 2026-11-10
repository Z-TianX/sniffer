#include "tcpstreamtable.h"

// 端点显示：IPv6 地址加方括号，避免与端口混淆（[addr]:port）
static QString endpointLabel(const QString& ip, quint16 port)
{
    return ip.contains(QLatin1Char(':'))
        ? QStringLiteral("[%1]:%2").arg(ip).arg(port)
        : QStringLiteral("%1:%2").arg(ip).arg(port);
}

// 把二进制载荷转为可显示文本（Wireshark ASCII 风格）：
// 可打印 ASCII 与 \r\n\t 原样保留，其余字节（TLS 密文等）显示为 '.'
static QString renderPayload(const QByteArray& data)
{
    QString out;
    out.reserve(data.size());
    for (int i = 0; i < data.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(data.at(i));
        if (c == '\r' || c == '\n' || c == '\t')
            out += QChar(c);
        else if (c >= 32 && c < 127)
            out += QLatin1Char(static_cast<char>(c));
        else
            out += QLatin1Char('.');
    }
    return out;
}

// 归一化四元组：把端点对 (ip, port) 中较小的一方记为 A，
// 使同一 TCP 会话双向报文映射到同一个 key。
QuadKey TcpStreamTable::keyOf(const PacketInfo& pkt, bool* aToB)
{
    QuadKey k;
    const bool srcFirst = (pkt.srcIp < pkt.dstIp) ||
                          (pkt.srcIp == pkt.dstIp && pkt.srcPort <= pkt.dstPort);
    if (srcFirst) {
        k.aIp = pkt.srcIp; k.aPort = pkt.srcPort;
        k.bIp = pkt.dstIp; k.bPort = pkt.dstPort;
    } else {
        k.aIp = pkt.dstIp; k.aPort = pkt.dstPort;
        k.bIp = pkt.srcIp; k.bPort = pkt.srcPort;
    }
    if (aToB)
        *aToB = srcFirst;
    return k;
}

void TcpStreamTable::addSegment(const PacketInfo& pkt)
{
    if (!pkt.hasTcp || pkt.appPayload.isEmpty())
        return;

    bool a2b = false;
    TcpFlow& flow = m_streams[keyOf(pkt, &a2b)];
    // 按 TCP 序列号存入 std::map：自动排序处理乱序，同 seq 覆盖处理重传
    (a2b ? flow.ab : flow.ba)[pkt.seq] = pkt.appPayload;
}

bool TcpStreamTable::hasFlow(const PacketInfo& pkt) const
{
    if (!pkt.hasTcp)
        return false;
    return m_streams.find(keyOf(pkt, nullptr)) != m_streams.end();
}

QString TcpStreamTable::streamHtml(const PacketInfo& pkt) const
{
    const auto it = m_streams.find(keyOf(pkt, nullptr));
    if (it == m_streams.end())
        return QString();

    const QuadKey& k = it->first;
    const TcpFlow& flow = it->second;

    // 统计双向段数与字节数，便于判断是否真的没有载荷
    qint64 abBytes = 0, baBytes = 0;
    for (const auto& kv : flow.ab) abBytes += kv.second.size();
    for (const auto& kv : flow.ba) baBytes += kv.second.size();

    QString html = QStringLiteral(
        "<pre style=\"font-family:Consolas,monospace;font-size:9pt;\">");
    html += QStringLiteral("<b style=\"color:#2b6cb0\">[A] %1</b>  &lt;-&gt;  "
                           "<b style=\"color:#c53030\">[B] %2</b><br>")
                .arg(endpointLabel(k.aIp, k.aPort), endpointLabel(k.bIp, k.bPort));
    html += QStringLiteral("<span style=\"color:#666666\">A-&gt;B: %1 段 / %2 字节"
                           "　　B-&gt;A: %3 段 / %4 字节"
                           "　　（二进制字节以 '.' 显示，TLS/HTTPS 为密文属正常）</span><br><br>")
                .arg(flow.ab.size()).arg(abBytes)
                .arg(flow.ba.size()).arg(baBytes);

    // A->B：蓝色；B->A：红色；双向各自按 seq 排序拼接
    for (const auto& kv : flow.ab) {
        html += QStringLiteral("<span style=\"color:#2b6cb0\">%1</span>")
                    .arg(renderPayload(kv.second).toHtmlEscaped());
    }
    for (const auto& kv : flow.ba) {
        html += QStringLiteral("<span style=\"color:#c53030\">%1</span>")
                    .arg(renderPayload(kv.second).toHtmlEscaped());
    }
    html += QLatin1String("</pre>");
    return html;
}

void TcpStreamTable::clear()
{
    m_streams.clear();
}
