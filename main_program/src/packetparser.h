#pragma once
#include <QString>
#include "packetinfo.h"

namespace Parser {

// 手动逐层解析原始以太网帧：Frame → Ethernet → IPv4(IHL) → TCP/UDP/ICMP → 应用层
void parse(const unsigned char* data, int len, PacketInfo& pkt);

// 生成十六进制 + ASCII 视图文本
QString hexDump(const unsigned char* data, int len);

// 用户态显示过滤器：报文匹配返回 true
// 支持协议关键字（tcp/udp/icmp/arp/ip/http/dns/tls）
// 与简单表达式：ip.addr == x.x.x.x、ip.src / ip.dst、tcp.port、udp.port、tcp.srcport、tcp.dstport
// 多个条件用 "||" 分隔，"!" 取反，例如: "tcp || udp", "ip.addr == 192.168.1.10", "!arp"
bool matchDisplayFilter(const PacketInfo& pkt, const QString& filter);

} // namespace Parser
