#include "tcpstreamtable.h"

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

    QString html = QStringLiteral(
        "<pre style=\"font-family:Consolas,monospace;font-size:9pt;\">");
    html += QStringLiteral("<b style=\"color:#2b6cb0\">[A] %1:%2</b>  &lt;-&gt;  "
                           "<b style=\"color:#c53030\">[B] %3:%4</b><br><br>")
                .arg(k.aIp).arg(k.aPort).arg(k.bIp).arg(k.bPort);

    // A->B：蓝色；B->A：红色；双向各自按 seq 排序拼接
    for (const auto& kv : flow.ab) {
        html += QStringLiteral("<span style=\"color:#2b6cb0\">%1</span>")
                    .arg(QString::fromUtf8(kv.second).toHtmlEscaped());
    }
    for (const auto& kv : flow.ba) {
        html += QStringLiteral("<span style=\"color:#c53030\">%1</span>")
                    .arg(QString::fromUtf8(kv.second).toHtmlEscaped());
    }
    html += QLatin1String("</pre>");
    return html;
}

void TcpStreamTable::clear()
{
    m_streams.clear();
}
