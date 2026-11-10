#pragma once
#include <map>
#include <QByteArray>
#include <QString>
#include "packetinfo.h"

// 显式加分 1：TCP 流追踪 Follow TCP Stream
// TCP 四元组 {srcIP, dstIP, srcPort, dstPort} 作为哈希表 key，
// 会话内按 TCP 序列号排序拼接双向载荷（std::map 天然按 seq 排序，处理乱序；
// 同 seq 重复写入覆盖，处理重传）。
struct QuadKey
{
    QString aIp, bIp;
    quint16 aPort = 0, bPort = 0;

    bool operator<(const QuadKey& o) const
    {
        if (aIp != o.aIp)     return aIp < o.aIp;
        if (aPort != o.aPort) return aPort < o.aPort;
        if (bIp != o.bIp)     return bIp < o.bIp;
        return bPort < o.bPort;
    }
};

struct TcpFlow
{
    std::map<quint32, QByteArray> ab;   // A→B 方向载荷，按 seq 排序
    std::map<quint32, QByteArray> ba;   // B→A 方向载荷，按 seq 排序
};

class TcpStreamTable
{
public:
    // 解析出 TCP 载荷后调用，按四元组归一化方向存入会话表
    void addSegment(const PacketInfo& pkt);

    bool hasFlow(const PacketInfo& pkt) const;

    // 拼接双向全部 TCP 载荷，返回带方向颜色的 HTML（用于 Follow TCP Stream 弹窗）
    QString streamHtml(const PacketInfo& pkt) const;

    void clear();

private:
    static QuadKey keyOf(const PacketInfo& pkt, bool* aToB);

    std::map<QuadKey, TcpFlow> m_streams;   // 四元组 → 会话
};
