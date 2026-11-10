# 网络嗅探器（实验 1A）— Qt6 + Npcap 主程序

完全独立可运行的课程实验主程序（不依赖 Wireshark），覆盖实验要求中的必做项、
NPA 高分项与两个显式加分项。`sniffer_extend.lua` Wireshark Lua 插件为后续附加产物，
与本主程序完全无关。

## 功能清单

- **NPS 原始抓包**：`pcap_findalldevs` 枚举网卡、`pcap_open_live` 混杂模式、
  子线程 `pcap_next_ex` 捕获原始以太网帧，信号槽传给 UI（不在子线程操作 UI）
- **NPA 手动逐层解析**：Ethernet / IPv4（处理 IHL 可变头部）/ TCP（可变头部、6 大标志位）
  / UDP / ICMP；应用层识别 HTTP 明文、DNS(UDP 53)、TLS/HTTPS（密文不解密）
- **BPF 内核捕获过滤器**（`pcap_compile` + `pcap_setfilter`）
- **用户态显示过滤器**：全部报文存内存 vector，软件过滤仅隐藏界面条目
  （支持 `tcp` `udp` `icmp` `arp` `http` `dns` `tls`、
  `ip.addr == x.x.x.x`、`tcp.port == 80` 等，多条件用 `||`，`!` 取反）
- **加分 1：Follow TCP Stream**：四元组哈希 key + `std::map` 按 TCP 序列号排序拼接双向载荷
  （排序处理乱序、覆盖处理重传），弹窗按方向着色展示
- **加分 2：TCP 流映射本机进程**：`GetTcpTable2` 定时取连接表构建 (本地IP,本地端口)→PID
  映射，`OpenProcess` + `QueryFullProcessImageNameW` 取进程名，报文列表新增 PID/进程名列
- **Qt6 三栏 GUI**：报文列表（QTableWidget）、协议详情树（QTreeWidget）、
  十六进制+ASCII 原始视图；网卡下拉框、开始/停止按钮
- 程序通过 `app.manifest` 强制**管理员权限**运行；无 ARP 欺骗代码，仅抓本机流量

## 环境要求（所有工具安装到 D:\网安，不要装 C 盘）

| 工具 | 版本 | 说明 |
|------|------|------|
| Qt | 6.5.2 MSVC2022 64-bit | 安装时选择安装到 `D:\网安\Qt` |
| Npcap 驱动 | v1.71 | 内核驱动，系统会强制装入 C 盘系统目录（无法更改），勾选 "WinPcap API compatible Mode" |
| Npcap SDK | 与驱动版本匹配 | 解压到 `D:\网安\npcap-sdk` |
| CMake | ≥ 3.18 | |
| Visual Studio | 2022（含 MSVC v143 + Windows SDK） | |
| Git | 最新 | 版本管理 |
| Wireshark | 最新稳定版 | 可选，仅用于比对解析结果；安装路径选 `D:\网安\Wireshark` |

## 构建

```powershell
cd D:\网安\main_program
cmake -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_PREFIX_PATH="D:\网安\Qt\6.5.2\msvc2019_64" `
  -DNPCAP_SDK="D:\网安\npcap-sdk"
cmake --build build --config Release
```

产物：`build\Release\NetSniffer.exe`（清单文件已内置 requireAdministrator，
双击运行会自动弹出 UAC 提权）。运行还需 `Qt6Widgets.dll` 等 Qt 运行库，
可在 `D:\网安\Qt\6.5.2\msvc2019_64\bin` 目录执行 windeployqt：

```powershell
D:\网安\Qt\6.5.2\msvc2019_64\bin\windeployqt.exe build\Release\NetSniffer.exe
```

## 使用与自测（对照实验文档 2.6）

1. 以管理员身份运行（程序会自动要求提权）。
2. 选择网卡 → 点击【开始抓包】。
3. 测试场景：
   - `ping www.example.com` → 观察 ICMP Echo request/reply 解析
   - 浏览器访问 http 网站 → 观察 HTTP 明文；https 网站 → TLS 密文不解密
   - `nslookup a domain` → 观察 UDP/DNS 报文
4. 与 Wireshark 同时抓包，比对 MAC/IP/端口/TCP 标志位/长度等解析结果。
5. BPF 过滤器输入 `tcp port 80` 再抓包；显示过滤器输入 `http`、`tcp.port == 80`、
   `ip.addr == 本机IP`、`!arp` 等验证软件过滤。
6. 点击任一携带载荷的 TCP 报文（或右键 → Follow TCP Stream）查看流重组弹窗；
   观察 PID/进程名列是否正确（可用 Process Explorer 对照）。

## 目录结构

```
main_program/
├── CMakeLists.txt
├── app.manifest            # 强制管理员权限
└── src/
    ├── main.cpp            # 入口（注册 PacketInfo 元类型）
    ├── packetinfo.h/.cpp   # 自定义报文结构体（信号槽跨线程传递）
    ├── packetparser.h/.cpp # NPA 手动逐层解析 + hexDump + 显示过滤器
    ├── capturethread.h/.cpp# NPS 捕获线程（Npcap API）
    ├── processmapper.h/.cpp# 加分2：GetTcpTable2 → PID/进程名
    ├── tcpstreamtable.h/.cpp# 加分1：四元组+序列号 TCP 流重组
    ├── streamdialog.h/.cpp # Follow TCP Stream 弹窗
    └── mainwindow.h/.cpp   # 三栏 GUI
```

## 红线自查

- `pcap_next_ex` 在 QThread 子线程，UI 只通过信号槽更新 ✔
- IHL / TCP 数据偏移均动态计算，未写死 20 字节 ✔
- 全部多字节字段经 `ntohs()/ntohl()` 大端转换 ✔
- 无 ARP 欺骗代码；混杂模式仅抓取本机收发流量 ✔
- 不依赖 Wireshark、未复制 epan 源码 ✔
