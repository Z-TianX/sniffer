#pragma once
#include <QByteArray>
#include <QMetaType>
#include <QString>
#include <QtGlobal>

// 传输层类型
enum class TransportType { None, TCP, UDP, ICMP, Other };

// 应用层协议识别结果（TLS 密文不做解密，仅识别）
enum class AppProto { None, HTTP, DNS, TLS, DHCP, Other };

// 解析完成后的自定义报文结构体（通过信号槽跨线程传递给 UI 主线程）
struct PacketInfo
{
    quint64 number = 0;          // 捕获序号（UI 侧递增）
    qint64  timestampUs = 0;     // 捕获时间（epoch 微秒）
    QByteArray raw;              // 原始以太网帧二进制

    // ---- Ethernet ----
    QString  srcMac, dstMac;
    quint16  etherType = 0;

    // ---- IPv4 ----
    bool     hasIp = false;
    quint8   ipVersion = 0;
    quint8   ipIhl = 0;          // IHL 可变头部长度（字节）
    quint16  ipTotalLen = 0;
    quint16  ipId = 0;
    quint8   ttl = 0;
    quint8   ipProto = 0;
    quint16  ipChecksum = 0;
    QString  srcIp, dstIp;

    // ---- TCP ----
    bool     hasTcp = false;
    quint16  srcPort = 0, dstPort = 0;
    quint32  seq = 0, ackNum = 0;
    quint8   tcpDataOffset = 0;  // TCP 头部长度（字节，可变）
    bool     fin = false, syn = false, rst = false, psh = false, ackF = false, urg = false;
    quint16  window = 0, tcpChecksum = 0;

    // ---- UDP ----
    bool     hasUdp = false;
    quint16  udpLen = 0, udpChecksum = 0;

    // ---- ICMP ----
    bool     hasIcmp = false;
    quint8   icmpType = 0, icmpCode = 0;

    // ---- 应用层 ----
    AppProto    appProto = AppProto::None;
    int         appLayerOffset = 0;  // 应用层载荷在帧内的偏移
    int         appPayloadLen = 0;
    QByteArray  appPayload;

    // ---- 进程映射（显式加分 2）----
    quint32  pid = 0;
    QString  procName;

    TransportType transport = TransportType::None;
    QString summaryExtra;        // ICMP/ARP 等额外摘要信息

    QString protocolName() const;  // 协议列显示名
    QString summary() const;       // Info 列摘要
};

Q_DECLARE_METATYPE(PacketInfo)
