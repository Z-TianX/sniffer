#include "mainwindow.h"
#include "packetparser.h"
#include "streamdialog.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCloseEvent>
#include <QDateTime>
#include <QDir>
#include <QPixmap>
#include <QFile>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QStatusBar>
#include <QTableWidget>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <windows.h>
#include <shellapi.h>   // IsUserAnAdmin

namespace {

QString etherTypeName(quint16 t)
{
    switch (t) {
    case 0x0800: return QStringLiteral("IPv4 (0x0800)");
    case 0x0806: return QStringLiteral("ARP (0x0806)");
    case 0x86DD: return QStringLiteral("IPv6 (0x86DD)");
    default:     return QStringLiteral("0x%1").arg(t, 4, 16, QChar('0'));
    }
}

QString ipProtoName(quint8 p)
{
    switch (p) {
    case 1:  return QStringLiteral("ICMP (1)");
    case 2:  return QStringLiteral("IGMP (2)");
    case 6:  return QStringLiteral("TCP (6)");
    case 17: return QStringLiteral("UDP (17)");
    case 58: return QStringLiteral("ICMPv6 (58)");
    default: return QString::number(p);
    }
}

QString tcpFlagsString(const PacketInfo& p)
{
    QStringList f;
    if (p.syn)  f << QStringLiteral("SYN");
    if (p.ackF) f << QStringLiteral("ACK");
    if (p.fin)  f << QStringLiteral("FIN");
    if (p.rst)  f << QStringLiteral("RST");
    if (p.psh)  f << QStringLiteral("PSH");
    if (p.urg)  f << QStringLiteral("URG");
    return f.isEmpty() ? QStringLiteral("-") : f.join(QLatin1String(", "));
}

QTreeWidgetItem* child(QTreeWidgetItem* parent, const QString& a, const QString& b)
{
    return new QTreeWidgetItem(parent, {a, b});
}

// 判断当前进程是否已提升为管理员（等效 IsUserAnAdmin，且不依赖 shellapi 头文件宏）
bool isProcessElevated()
{
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD cb = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &cb))
            elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setupUi();

    m_processMapper = new ProcessMapper(this);
    // 连接表每次刷新后回填此前“抓包瞬间还查不到进程”的报文（如 TCP 握手首包）
    connect(m_processMapper, &ProcessMapper::tableUpdated,
            this, &MainWindow::backfillProcessInfo);
    m_processMapper->start(2000);

    connect(&m_capture, &CaptureThread::packetCaptured,
            this, &MainWindow::onPacket, Qt::QueuedConnection);
    connect(&m_capture, &CaptureThread::errorOccurred,
            this, &MainWindow::onCaptureError, Qt::QueuedConnection);
    connect(&m_capture, &CaptureThread::captureStarted, this, [this] {
        m_capturing = true;
        updateStatus();
    });
    connect(&m_capture, &CaptureThread::captureStopped, this, [this] {
        m_capturing = false;
        updateStatus();
    });

    refreshDevices();

    if (!isProcessElevated())
        QMessageBox::warning(this, QStringLiteral("权限提示"),
            QStringLiteral("程序未以管理员身份运行，混杂模式开启可能失败、抓不到包！\n"
                           "请右键\"以管理员身份运行\"。"));
}

void MainWindow::setStartupPreset(const QString& bpfFilter, const QString& displayFilter,
                                  bool autoStart, bool autoByProcess)
{
    if (!bpfFilter.isEmpty())
        m_bpfEdit->setText(bpfFilter);
    if (!displayFilter.isEmpty())
        m_displayEdit->setText(displayFilter);

    // 必须先选中有真实流量的物理网卡再开始，否则会抓在 "WAN Miniport (Network Monitor)"
    // 之类的虚拟网卡上，列表永远是空的（表现为“只筛 TCP 没结果”）
    if (autoStart)
        QTimer::singleShot(600, this, [this] {
            selectBestDevice();
            onStart();
        });

    // 自动“按进程筛选”：抓一会儿后在进程下拉框中选中报文数最多的进程
    if (autoByProcess) {
        QTimer::singleShot(8000, this, [this] {
            refreshProcessCombo();
            QHash<quint32, int> cnt;
            for (const PacketInfo& p : m_packets)
                if (p.hasTcp && p.pid)
                    ++cnt[p.pid];
            quint32 bestPid = 0; int best = 0;
            for (auto it = cnt.constBegin(); it != cnt.constEnd(); ++it)
                if (it.value() > best) { best = it.value(); bestPid = it.key(); }
            const int idx = bestPid ? m_procCombo->findData(bestPid) : -1;
            if (idx >= 0)
                m_procCombo->setCurrentIndex(idx);
        });
    }
}

void MainWindow::enableAutoDemo(bool on, const QString& bpfFilter, const QString& displayFilter,
                                const QString& procDemo, const QString& shotsDir)
{
    if (!on)
        return;

    // 自截图（用于实验报告/验证）：程序自己 grab() 窗口，不受前台窗口遮挡影响
    if (!shotsDir.isEmpty()) {
        QDir().mkpath(shotsDir);
        const QList<int> msList = {8000, 16000};
        for (int ms : msList) {
            QTimer::singleShot(ms, this, [this, shotsDir, ms] {
                const QPixmap pm = grab();
                pm.save(QStringLiteral("%1/shot_%2ms.png").arg(shotsDir).arg(ms));
            });
        }
    }
    // 进程筛选演示：14s 后在“进程”下拉框中选中包含该关键字的进程；
    // 若没有匹配项，则兜底选择报文数最多的进程，保证演示可见
    if (!procDemo.isEmpty()) {
        QTimer::singleShot(14000, this, [this, procDemo] {
            refreshProcessCombo();
            for (int i = 0; i < m_procCombo->count(); ++i) {
                if (m_procCombo->itemText(i).contains(procDemo, Qt::CaseInsensitive)) {
                    m_procCombo->setCurrentIndex(i);   // 触发 onProcessFilterChanged
                    return;
                }
            }
            // 兜底：统计各 PID 的 TCP 报文数，选最多的那个
            QHash<quint32, int> cnt;
            for (const PacketInfo& p : m_packets)
                if (p.hasTcp && p.pid)
                    ++cnt[p.pid];
            quint32 bestPid = 0; int best = 0;
            for (auto it = cnt.constBegin(); it != cnt.constEnd(); ++it)
                if (it.value() > best) { best = it.value(); bestPid = it.key(); }
            if (bestPid) {
                const int idx = m_procCombo->findData(bestPid);
                if (idx >= 0)
                    m_procCombo->setCurrentIndex(idx);
            }
        });
    }
    // 1s 后自动开始抓包：智能挑选真实物理网卡（排除 Loopback/Wi-Fi Direct/虚拟网卡）
    QTimer::singleShot(1000, this, [this, bpfFilter] {
        selectBestDevice();
        if (!bpfFilter.isEmpty())
            m_bpfEdit->setText(bpfFilter);
        onStart();
    });
    // 显示过滤器：支持 ";" 分隔多个表达式，每 4 秒依次应用（用于演示逻辑演算）
    const QStringList dfs = displayFilter.split(QLatin1Char(';'), Qt::SkipEmptyParts);
    if (dfs.size() > 1) {
        for (int i = 0; i < dfs.size(); ++i) {
            const QString d = dfs[i].trimmed();
            QTimer::singleShot(6000 + i * 4000, this, [this, d] {
                m_displayEdit->setText(d);   // 触发 textChanged → applyDisplayFilter
            });
        }
        return;   // 过滤器演示模式：不做自动选中/自动弹流窗口
    }
    // 单个表达式：6s 后应用（软件过滤，隐藏不匹配条目）
    QTimer::singleShot(6000, this, [this, displayFilter] {
        if (!displayFilter.isEmpty())
            m_displayEdit->setText(displayFilter);
    });
    // 12s 后自动选中报文：优先 HTTP 明文，其次任意带载荷 TCP（展示协议树 + 十六进制视图）
    QTimer::singleShot(12000, this, [this] {
        int firstTcpPayload = -1;
        for (int i = 0; i < m_packets.size(); ++i) {
            if (!m_packets[i].hasTcp || m_packets[i].appPayload.isEmpty())
                continue;
            if (firstTcpPayload < 0)
                firstTcpPayload = i;
            if (m_packets[i].appProto == AppProto::HTTP) {
                m_table->selectRow(i);
                return;
            }
        }
        if (firstTcpPayload >= 0)
            m_table->selectRow(firstTcpPayload);
    });
    // 16s 后自动弹出 Follow TCP Stream 窗口
    QTimer::singleShot(16000, this, [this] { onFollowStream(); });
}

void MainWindow::setupUi()
{
    setWindowTitle(QStringLiteral("网络嗅探器 (Npcap + Qt6)"));
    resize(1200, 760);

    auto* central = new QWidget(this);
    auto* rootLayout = new QVBoxLayout(central);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    // ---- 第 1 行：网卡选择 + BPF 过滤器 + 开始/停止 ----
    auto* row1 = new QHBoxLayout();
    row1->addWidget(new QLabel(QStringLiteral("网卡:"), central));
    m_devCombo = new QComboBox(central);
    m_devCombo->setMinimumWidth(320);
    row1->addWidget(m_devCombo, 1);

    row1->addWidget(new QLabel(QStringLiteral("BPF捕获过滤器:"), central));
    m_bpfEdit = new QLineEdit(central);
    m_bpfEdit->setPlaceholderText(QStringLiteral("例如: tcp port 80 或 host 192.168.1.10（留空=不过滤）"));
    row1->addWidget(m_bpfEdit, 1);

    m_btnStart = new QPushButton(QStringLiteral("开始抓包"), central);
    m_btnStop  = new QPushButton(QStringLiteral("停止抓包"), central);
    m_btnStop->setEnabled(false);
    row1->addWidget(m_btnStart);
    row1->addWidget(m_btnStop);
    rootLayout->addLayout(row1);

    // ---- 第 2 行：进程筛选 + 显示过滤器 + Follow TCP Stream + 清空 ----
    auto* row2 = new QHBoxLayout();
    row2->addWidget(new QLabel(QStringLiteral("进程:"), central));
    m_procCombo = new QComboBox(central);
    m_procCombo->setMinimumWidth(240);
    m_procCombo->setToolTip(QStringLiteral(
        "选择某个进程 → 自动应用 tcp && pid == <PID>，只看该进程产生/接收的全部 TCP 流\n"
        "（PID 由 Windows IP Helper 连接表映射得到）"));
    m_procCombo->addItem(QStringLiteral("全部进程（不过滤）"), quint32(0));
    row2->addWidget(m_procCombo);

    row2->addWidget(new QLabel(QStringLiteral("显示过滤器:"), central));
    m_displayEdit = new QLineEdit(central);
    m_displayEdit->setPlaceholderText(
        QStringLiteral("支持逻辑演算: tcp && ip.addr == x.x.x.x && tcp.port == 80　"
                       "取反 !tcp　或 ||　括号 ( )　按进程: tcp && proc == wps / pid == 1234　"
                       "协议: tcp/udp/ipv4/ipv6/icmp/icmpv6/arp/http/dns/tls/dhcp"));
    row2->addWidget(m_displayEdit, 1);

    m_btnStream = new QPushButton(QStringLiteral("Follow TCP Stream"), central);
    m_btnStream->setEnabled(false);
    auto* btnClear = new QPushButton(QStringLiteral("清空"), central);
    row2->addWidget(m_btnStream);
    row2->addWidget(btnClear);
    rootLayout->addLayout(row2);

    // ---- 三栏主体 ----
    auto* splitter = new QSplitter(Qt::Vertical, central);

    m_table = new QTableWidget(splitter);
    m_table->setColumnCount(8);
    m_table->setHorizontalHeaderLabels({QStringLiteral("序号"), QStringLiteral("时间"),
                                        QStringLiteral("源"), QStringLiteral("目的"),
                                        QStringLiteral("协议"), QStringLiteral("长度"),
                                        QStringLiteral("PID/进程名"), QStringLiteral("Info")});
    m_table->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setSortingEnabled(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);

    m_tree = new QTreeWidget(splitter);
    m_tree->setColumnCount(2);
    m_tree->setHeaderLabels({QStringLiteral("字段"), QStringLiteral("值")});
    m_tree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);

    m_hexView = new QPlainTextEdit(splitter);
    m_hexView->setReadOnly(true);
    QFont mono(QStringLiteral("Consolas"), 9);
    m_hexView->setFont(mono);

    splitter->addWidget(m_table);
    splitter->addWidget(m_tree);
    splitter->addWidget(m_hexView);
    splitter->setSizes({360, 240, 200});
    rootLayout->addWidget(splitter, 1);

    setCentralWidget(central);

    m_status = new QLabel(QStringLiteral("就绪。请选择网卡后点击\"开始抓包\"。"), this);
    statusBar()->addWidget(m_status, 1);

    connect(m_btnStart, &QPushButton::clicked, this, &MainWindow::onStart);
    connect(m_btnStop,  &QPushButton::clicked, this, &MainWindow::onStop);
    connect(btnClear,   &QPushButton::clicked, this, &MainWindow::onClear);
    connect(m_btnStream,&QPushButton::clicked, this, &MainWindow::onFollowStream);
    connect(m_displayEdit, &QLineEdit::textChanged, this, &MainWindow::onDisplayFilterChanged);
    connect(m_procCombo, &QComboBox::currentIndexChanged,
            this, &MainWindow::onProcessFilterChanged);
    connect(m_table->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::onSelectionChanged);
    connect(m_table, &QTableWidget::customContextMenuRequested,
            this, &MainWindow::showContextMenu);
}

void MainWindow::refreshDevices()
{
    QString err;
    const auto devs = CaptureThread::enumerateDevices(&err);
    const QString prevDesc = m_devCombo->currentText();   // 保留用户此前的选择
    m_devCombo->clear();
    if (devs.isEmpty()) {
        m_status->setText(QStringLiteral("未枚举到网卡: %1").arg(err));
        return;
    }
    for (const auto& dev : devs)
        m_devCombo->addItem(dev.second, dev.first);

    // 枚举顺序第 0 项常是虚拟网卡（WAN Miniport / Loopback），默认必须挑真实物理网卡
    const int prevIdx = prevDesc.isEmpty() ? -1 : m_devCombo->findText(prevDesc);
    if (prevIdx >= 0)
        m_devCombo->setCurrentIndex(prevIdx);
    else
        selectBestDevice();
}

// 智能挑卡：Npcap 枚举出来的第 0 项经常是 "WAN Miniport (Network Monitor)"、
// "Adapter for loopback traffic capture" 之类的虚拟网卡，抓上去永远没有报文。
// 这里按名字打分，优先真实无线/有线网卡，虚拟网卡重罚。
void MainWindow::selectBestDevice()
{
    if (!m_devCombo || m_devCombo->count() == 0)
        return;

    int best = 0, bestScore = -100000;
    for (int i = 0; i < m_devCombo->count(); ++i) {
        const QString d = m_devCombo->itemText(i);
        int score = 0;
        auto has = [&d](const char* s) { return d.contains(QLatin1String(s), Qt::CaseInsensitive); };
        if (has("Loopback"))                                      score -= 100;  // Npcap 回环
        if (has("Wi-Fi Direct") || has("Monitor"))                score -= 100;  // 虚拟直连 / 网络监视器
        if (has("WAN Miniport") || has("Miniport"))               score -= 120;  // WAN Miniport 系列
        if (has("Microsoft"))                                     score -= 50;
        if (has("VMware") || has("Virtual") || has("TAP"))         score -= 30;
        if (has("Wireless") || has("Wi-Fi"))                      score += 20;
        if (has("Ethernet") || has("以太网"))                      score += 15;
        if (score > bestScore) { bestScore = score; best = i; }
    }
    m_devCombo->setCurrentIndex(best);
}

void MainWindow::onStart()
{
    const QString dev = m_devCombo->currentData().toString();
    if (dev.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("提示"), QStringLiteral("请先选择网卡"));
        return;
    }
    m_packets.clear();
    m_rowToPacket.clear();
    m_packetCounter = 0;
    m_visibleRows = 0;
    m_streams.clear();
    m_table->setRowCount(0);
    m_tree->clear();
    m_hexView->clear();

    m_capture.startCapture(dev, m_bpfEdit->text().trimmed());
    m_btnStart->setEnabled(false);
    m_btnStop->setEnabled(true);
    m_devCombo->setEnabled(false);
    m_bpfEdit->setEnabled(false);
}

void MainWindow::onStop()
{
    m_capture.stopCapture();
    m_btnStart->setEnabled(true);
    m_btnStop->setEnabled(false);
    m_devCombo->setEnabled(true);
    m_bpfEdit->setEnabled(true);
    refreshProcessCombo();   // 停止后刷新一次进程列表
}

void MainWindow::onPacket(const PacketInfo& pIn)
{
    PacketInfo pkt = pIn;
    pkt.number = ++m_packetCounter;

    // 显式加分 2：TCP/UDP 报文映射本机 PID / 进程名
    if (pkt.hasTcp || pkt.hasUdp) {
        const auto r = m_processMapper->lookup(pkt.srcIp, pkt.srcPort, pkt.dstIp, pkt.dstPort);
        pkt.pid = r.pid;
        pkt.procName = r.name;
    }
    if (pkt.hasTcp)
        m_streams.addSegment(pkt);   // 显式加分 1：存入 TCP 流会话表

    m_packets.append(pkt);
    addPacketRow(m_packets.size() - 1);

    updateStatus();
}

// 状态栏：把“抓到了多少”和“界面显示了多少”分开说清楚，
// 避免 BPF 明明抓到了报文、却被显示过滤器全部隐藏而误以为“没结果”
void MainWindow::updateStatus()
{
    const int total   = m_packets.size();
    const int visible = m_visibleRows;
    const QString bpf  = m_bpfEdit->text().trimmed();
    const QString disp = m_displayEdit->text().trimmed();
    const QString bpfText = bpf.isEmpty() ? QStringLiteral("无") : bpf;

    if (total > 0 && visible == 0 && !disp.isEmpty()) {
        m_status->setText(QStringLiteral("⚠ 已捕获 %1 个报文，但显示过滤器 \"%2\" 把它们全部隐藏了"
                                         "（清空“显示过滤器”即可看到；BPF: %3）")
                              .arg(total).arg(disp, bpfText));
        return;
    }
    if (total == 0 && !m_capturing) {
        m_status->setText(QStringLiteral("就绪。BPF: %1 | 显示过滤器: %2")
                              .arg(bpfText, disp.isEmpty() ? QStringLiteral("无") : disp));
        return;
    }

    QString s = m_capturing
        ? QStringLiteral("正在抓包... 已捕获 %1 个报文，当前显示 %2 个").arg(total).arg(visible)
        : QStringLiteral("抓包已停止，共捕获 %1 个报文，当前显示 %2 个").arg(total).arg(visible);
    s += QStringLiteral(" | BPF: %1").arg(bpfText);
    if (!disp.isEmpty())
        s += QStringLiteral(" | 显示过滤器: %1").arg(disp);
    if (m_capturing && total == 0)
        s += QStringLiteral("（暂未抓到匹配报文：确认流量确实经过当前网卡）");
    m_status->setText(s);
}

void MainWindow::addPacketRow(int pktIndex)
{
    const PacketInfo& pkt = m_packets[pktIndex];
    const int row = m_table->rowCount();
    m_table->insertRow(row);
    m_rowToPacket.append(pktIndex);

    const QString time = QDateTime::fromMSecsSinceEpoch(pkt.timestampUs / 1000)
                             .toString(QStringLiteral("hh:mm:ss.zzz"));
    const QString pidStr = pkt.pid
        ? QStringLiteral("%1 (%2)").arg(pkt.pid).arg(pkt.procName.isEmpty()
              ? QStringLiteral("?") : pkt.procName)
        : QStringLiteral("-");

    const QStringList cells = {
        QString::number(pkt.number), time,
        pkt.etherType == 0x0806 ? QStringLiteral("-") : pkt.srcIp,
        pkt.etherType == 0x0806 ? QStringLiteral("-") : pkt.dstIp,
        pkt.protocolName(),
        QString::number(pkt.raw.size()),
        pidStr,
        pkt.summary()
    };
    for (int c = 0; c < cells.size(); ++c)
        m_table->setItem(row, c, new QTableWidgetItem(cells[c]));
    m_table->item(row, 0)->setData(Qt::UserRole, pktIndex);

    // 显示过滤器生效时，新增行先按软件逻辑过滤（不匹配则隐藏）
    const bool hidden = !m_displayEdit->text().trimmed().isEmpty() &&
                        !Parser::matchDisplayFilter(pkt, m_displayEdit->text());
    m_table->setRowHidden(row, hidden);
    if (!hidden)
        ++m_visibleRows;
}

void MainWindow::backfillProcessInfo()
{
    if (m_packets.isEmpty() || m_rowToPacket.isEmpty())
        return;

    // 建立 报文下标 → 表格行 的反向索引
    QHash<int, int> pktToRow;
    pktToRow.reserve(m_rowToPacket.size());
    for (int row = 0; row < m_rowToPacket.size(); ++row)
        pktToRow.insert(m_rowToPacket[row], row);

    bool changed = false;
    for (int i = 0; i < m_packets.size(); ++i) {
        PacketInfo& pkt = m_packets[i];
        if (pkt.pid != 0 || (!pkt.hasTcp && !pkt.hasUdp))
            continue;
        const auto r = m_processMapper->lookup(pkt.srcIp, pkt.srcPort, pkt.dstIp, pkt.dstPort);
        if (!r.pid)
            continue;
        pkt.pid = r.pid;
        pkt.procName = r.name;
        const int row = pktToRow.value(i, -1);
        if (row >= 0 && m_table->item(row, 6))
            m_table->item(row, 6)->setText(
                QStringLiteral("%1 (%2)").arg(r.pid).arg(r.name.isEmpty() ? QStringLiteral("?") : r.name));
        changed = true;
    }
    // 若当前选中的报文刚补上 PID，同步刷新协议树
    if (changed && currentPacketIndex() >= 0)
        buildTree(m_packets[currentPacketIndex()]);
    // 补上 PID 后可能改变显示过滤器（如 "proc" / "pid == n"）的匹配结果，需重新应用
    if (changed)
        applyDisplayFilter();
    // 同步刷新“进程筛选”下拉框
    refreshProcessCombo();
}

void MainWindow::refreshProcessCombo()
{
    if (!m_procCombo)
        return;

    // 收集已捕获报文中出现过的 (PID → 进程名)，按 PID 去重
    QMap<quint32, QString> procs;
    for (const PacketInfo& p : m_packets) {
        if (p.pid == 0)
            continue;
        procs.insert(p.pid, p.procName);
    }

    // 内容签名未变则不重建，避免打断用户操作
    QString sig;
    for (auto it = procs.constBegin(); it != procs.constEnd(); ++it)
        sig += QStringLiteral("%1:%2;").arg(it.key()).arg(it.value());
    if (sig == m_procComboSig)
        return;
    m_procComboSig = sig;

    const quint32 curPid = m_procCombo->currentData().toUInt();
    m_procCombo->blockSignals(true);
    m_procCombo->clear();
    m_procCombo->addItem(QStringLiteral("全部进程（不过滤）"), quint32(0));
    for (auto it = procs.constBegin(); it != procs.constEnd(); ++it) {
        const QString name = it.value().isEmpty() ? QStringLiteral("?") : it.value();
        m_procCombo->addItem(QStringLiteral("%1  (%2)").arg(name).arg(it.key()), it.key());
    }
    const int idx = m_procCombo->findData(curPid);
    m_procCombo->setCurrentIndex(idx >= 0 ? idx : 0);
    m_procCombo->blockSignals(false);
}

void MainWindow::onProcessFilterChanged()
{
    const quint32 pid = m_procCombo->currentData().toUInt();
    if (pid == 0) {
        // “全部进程” → 清空显示过滤器
        if (!m_displayEdit->text().trimmed().isEmpty())
            m_displayEdit->clear();
        return;
    }
    // 某进程产生的所有 TCP 流：tcp && pid == N（也可写成 tcp && proc == 进程名）
    m_displayEdit->setText(QStringLiteral("tcp && pid == %1").arg(pid));
}

void MainWindow::onCaptureError(const QString& msg)
{
    m_btnStart->setEnabled(true);
    m_btnStop->setEnabled(false);
    m_devCombo->setEnabled(true);
    m_bpfEdit->setEnabled(true);
    QMessageBox::critical(this, QStringLiteral("抓包错误"), msg);
}

int MainWindow::currentPacketIndex() const
{
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_rowToPacket.size())
        return -1;
    return m_rowToPacket[row];
}

void MainWindow::onSelectionChanged()
{
    const int idx = currentPacketIndex();
    m_btnStream->setEnabled(idx >= 0 && m_packets[idx].hasTcp);
    if (idx < 0) {
        m_tree->clear();
        m_hexView->clear();
        return;
    }
    buildTree(m_packets[idx]);
    showHex(m_packets[idx]);
}

void MainWindow::buildTree(const PacketInfo& pkt)
{
    m_tree->clear();

    // ---- Frame ----
    auto* frame = new QTreeWidgetItem(m_tree, {QStringLiteral("Frame"),
        QStringLiteral("%1 字节捕获").arg(pkt.raw.size())});
    child(frame, QStringLiteral("捕获时间"),
          QDateTime::fromMSecsSinceEpoch(pkt.timestampUs / 1000)
              .toString(QStringLiteral("yyyy-MM-dd hh:mm:ss.zzz")));
    child(frame, QStringLiteral("帧长度"), QStringLiteral("%1 字节").arg(pkt.raw.size()));
    child(frame, QStringLiteral("序号"), QString::number(pkt.number));

    // ---- Ethernet II ----
    auto* eth = new QTreeWidgetItem(m_tree, {QStringLiteral("Ethernet II"),
        QStringLiteral("%1 -> %2").arg(pkt.srcMac, pkt.dstMac)});
    child(eth, QStringLiteral("目的 MAC"), pkt.dstMac);
    child(eth, QStringLiteral("源 MAC"), pkt.srcMac);
    child(eth, QStringLiteral("类型"), etherTypeName(pkt.etherType));

    // ---- IPv6 ----
    if (pkt.hasIp && pkt.ipVersion == 6) {
        auto* ip = new QTreeWidgetItem(m_tree, {QStringLiteral("Internet Protocol Version 6"),
            QStringLiteral("%1 -> %2").arg(pkt.srcIp, pkt.dstIp)});
        child(ip, QStringLiteral("版本"), QString::number(pkt.ipVersion));
        child(ip, QStringLiteral("载荷长度"), QStringLiteral("%1 字节").arg(pkt.ipTotalLen - 40));
        child(ip, QStringLiteral("下一头部"), ipProtoName(pkt.ipProto));
        child(ip, QStringLiteral("Hop Limit"), QString::number(pkt.ttl));
        child(ip, QStringLiteral("源 IP"), pkt.srcIp);
        child(ip, QStringLiteral("目的 IP"), pkt.dstIp);
    }
    // ---- IPv4 ----
    else if (pkt.hasIp) {
        auto* ip = new QTreeWidgetItem(m_tree, {QStringLiteral("Internet Protocol Version 4"),
            QStringLiteral("%1 -> %2").arg(pkt.srcIp, pkt.dstIp)});
        child(ip, QStringLiteral("版本"), QString::number(pkt.ipVersion));
        child(ip, QStringLiteral("头部长度 (IHL)"), QStringLiteral("%1 字节").arg(pkt.ipIhl));
        child(ip, QStringLiteral("总长度"), QStringLiteral("%1 字节").arg(pkt.ipTotalLen));
        child(ip, QStringLiteral("标识"), QStringLiteral("0x%1").arg(pkt.ipId, 4, 16, QChar('0')));
        child(ip, QStringLiteral("TTL"), QString::number(pkt.ttl));
        child(ip, QStringLiteral("协议"), ipProtoName(pkt.ipProto));
        child(ip, QStringLiteral("头部校验和"), QStringLiteral("0x%1").arg(pkt.ipChecksum, 4, 16, QChar('0')));
        child(ip, QStringLiteral("源 IP"), pkt.srcIp);
        child(ip, QStringLiteral("目的 IP"), pkt.dstIp);
    }

    // ---- TCP ----
    if (pkt.hasTcp) {
        auto* tcp = new QTreeWidgetItem(m_tree, {QStringLiteral("Transmission Control Protocol"),
            QStringLiteral("%1 -> %2").arg(pkt.srcPort).arg(pkt.dstPort)});
        child(tcp, QStringLiteral("源端口"), QString::number(pkt.srcPort));
        child(tcp, QStringLiteral("目的端口"), QString::number(pkt.dstPort));
        child(tcp, QStringLiteral("Sequence Number"), QString::number(pkt.seq));
        child(tcp, QStringLiteral("Acknowledgment Number"), QString::number(pkt.ackNum));
        child(tcp, QStringLiteral("头部长度"), QStringLiteral("%1 字节").arg(pkt.tcpDataOffset));
        child(tcp, QStringLiteral("标志位"), tcpFlagsString(pkt));
        child(tcp, QStringLiteral("窗口大小"), QString::number(pkt.window));
        child(tcp, QStringLiteral("校验和"), QStringLiteral("0x%1").arg(pkt.tcpChecksum, 4, 16, QChar('0')));
    }

    // ---- UDP ----
    if (pkt.hasUdp) {
        auto* udp = new QTreeWidgetItem(m_tree, {QStringLiteral("User Datagram Protocol"),
            QStringLiteral("%1 -> %2").arg(pkt.srcPort).arg(pkt.dstPort)});
        child(udp, QStringLiteral("源端口"), QString::number(pkt.srcPort));
        child(udp, QStringLiteral("目的端口"), QString::number(pkt.dstPort));
        child(udp, QStringLiteral("长度"), QString::number(pkt.udpLen));
        child(udp, QStringLiteral("校验和"), QStringLiteral("0x%1").arg(pkt.udpChecksum, 4, 16, QChar('0')));
    }

    // ---- ICMP ----
    if (pkt.hasIcmp) {
        auto* icmp = new QTreeWidgetItem(m_tree, {QStringLiteral("Internet Control Message Protocol"),
            QStringLiteral("Type=%1 Code=%2").arg(pkt.icmpType).arg(pkt.icmpCode)});
        child(icmp, QStringLiteral("Type"), QString::number(pkt.icmpType));
        child(icmp, QStringLiteral("Code"), QString::number(pkt.icmpCode));
        child(icmp, QStringLiteral("说明"),
              pkt.icmpType == 8 ? QStringLiteral("Echo (ping) 请求")
              : pkt.icmpType == 0 ? QStringLiteral("Echo (ping) 应答")
              : QStringLiteral("其他 ICMP 报文"));
    }

    // ---- 应用层 ----
    if (pkt.appProto != AppProto::None) {
        QString name;
        switch (pkt.appProto) {
        case AppProto::HTTP: name = QStringLiteral("HTTP"); break;
        case AppProto::DNS:  name = QStringLiteral("DNS");  break;
        case AppProto::TLS:  name = QStringLiteral("TLS");  break;
        case AppProto::DHCP: name = QStringLiteral("DHCP"); break;
        default:             name = QStringLiteral("Application"); break;
        }
        auto* app = new QTreeWidgetItem(m_tree, {name, QString()});
        if (pkt.appProto == AppProto::HTTP && !pkt.appPayload.isEmpty()) {
            const int eol = pkt.appPayload.indexOf("\r\n");
            child(app, QStringLiteral("请求/状态行"),
                  pkt.appPayload.left(eol < 0 ? qMin(pkt.appPayload.size(), 120) : eol));
        }
        if (pkt.appProto == AppProto::TLS)
            child(app, QStringLiteral("说明"), QStringLiteral("TLS/HTTPS 密文，不解密，输出原始载荷"));
        if (!pkt.appPayload.isEmpty())
            child(app, QStringLiteral("载荷长度"), QStringLiteral("%1 字节").arg(pkt.appPayloadLen));
    }

    // ---- 进程信息（显式加分 2） ----
    if (pkt.pid) {
        auto* proc = new QTreeWidgetItem(m_tree, {QStringLiteral("进程信息"), QString()});
        child(proc, QStringLiteral("PID"), QString::number(pkt.pid));
        child(proc, QStringLiteral("进程名"), pkt.procName.isEmpty() ? QStringLiteral("?") : pkt.procName);
    }

    m_tree->expandAll();
}

void MainWindow::showHex(const PacketInfo& pkt)
{
    m_hexView->setPlainText(
        Parser::hexDump(reinterpret_cast<const unsigned char*>(pkt.raw.constData()),
                        pkt.raw.size()));
}

void MainWindow::onDisplayFilterChanged()
{
    applyDisplayFilter();
}

void MainWindow::applyDisplayFilter()
{
    // 用户态软件过滤：全部报文仍在内存 vector 中，仅界面隐藏不匹配条目
    const QString filter = m_displayEdit->text();
    m_visibleRows = 0;
    for (int row = 0; row < m_rowToPacket.size(); ++row) {
        const PacketInfo& pkt = m_packets[m_rowToPacket[row]];
        const bool hidden = !Parser::matchDisplayFilter(pkt, filter);
        m_table->setRowHidden(row, hidden);
        if (!hidden)
            ++m_visibleRows;
    }
    updateStatus();
}

void MainWindow::onFollowStream()
{
    const int idx = currentPacketIndex();
    if (idx < 0 || !m_packets[idx].hasTcp)
        return;
    const PacketInfo& pkt = m_packets[idx];
    const QString html = m_streams.streamHtml(pkt);
    if (html.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Follow TCP Stream"),
            QStringLiteral("该会话暂无捕获到 TCP 载荷数据"));
        return;
    }
    auto ep = [](const QString& ip, quint16 port) {
        return ip.contains(QLatin1Char(':')) ? QStringLiteral("[%1]:%2").arg(ip).arg(port)
                                             : QStringLiteral("%1:%2").arg(ip).arg(port);
    };
    const QString title = QStringLiteral("TCP 流: %1 <-> %2")
                              .arg(ep(pkt.srcIp, pkt.srcPort), ep(pkt.dstIp, pkt.dstPort));
    StreamDialog dlg(html, title, this);
    dlg.exec();
}

void MainWindow::onClear()
{
    m_packets.clear();
    m_rowToPacket.clear();
    m_packetCounter = 0;
    m_visibleRows = 0;
    m_streams.clear();
    m_table->setRowCount(0);
    m_tree->clear();
    m_hexView->clear();
    // 重置进程筛选下拉框
    m_procComboSig.clear();
    m_procCombo->blockSignals(true);
    m_procCombo->clear();
    m_procCombo->addItem(QStringLiteral("全部进程（不过滤）"), quint32(0));
    m_procCombo->blockSignals(false);
    m_status->setText(QStringLiteral("已清空"));
}

void MainWindow::showContextMenu(const QPoint& pos)
{
    const int idx = currentPacketIndex();
    if (idx < 0)
        return;
    QMenu menu(this);
    QAction* actStream = menu.addAction(QStringLiteral("Follow TCP Stream"));
    actStream->setEnabled(m_packets[idx].hasTcp);
    QAction* actCopy = menu.addAction(QStringLiteral("复制报文摘要"));
    QAction* actSave = menu.addAction(QStringLiteral("保存原始帧为二进制文件..."));

    // 加分项 2：一键筛选“某进程产生的所有 TCP 流”
    QAction* actProcTcp = nullptr;
    QAction* actProcAll = nullptr;
    QAction* actCopyProc = nullptr;
    if (m_packets[idx].pid != 0) {
        menu.addSeparator();
        const quint32 pid = m_packets[idx].pid;
        const QString name = m_packets[idx].procName;
        actProcTcp = menu.addAction(QStringLiteral("只看该进程的 TCP 流：%1 (PID %2)").arg(name).arg(pid));
        actProcAll = menu.addAction(QStringLiteral("只看该进程的全部报文：%1 (PID %2)").arg(name).arg(pid));
        actCopyProc = menu.addAction(QStringLiteral("复制进程名"));
    }

    QAction* chosen = menu.exec(m_table->viewport()->mapToGlobal(pos));
    if (!chosen)
        return;

    const PacketInfo& pkt = m_packets[idx];
    if (chosen == actStream) {
        onFollowStream();
    } else if (chosen && chosen == actProcTcp) {
        // 某进程产生的所有 TCP 流
        m_displayEdit->setText(QStringLiteral("tcp && pid == %1").arg(pkt.pid));
        m_status->setText(QStringLiteral("已筛选：%1 (PID %2) 的全部 TCP 流")
                              .arg(pkt.procName).arg(pkt.pid));
    } else if (chosen && chosen == actProcAll) {
        m_displayEdit->setText(QStringLiteral("pid == %1").arg(pkt.pid));
        m_status->setText(QStringLiteral("已筛选：%1 (PID %2) 的全部报文")
                              .arg(pkt.procName).arg(pkt.pid));
    } else if (chosen && chosen == actCopyProc) {
        QApplication::clipboard()->setText(QStringLiteral("%1 (PID %2)")
                                              .arg(pkt.procName).arg(pkt.pid));
    } else if (chosen == actCopy) {
        QApplication::clipboard()->setText(pkt.summary());
    } else if (chosen == actSave) {
        const QString file = QFileDialog::getSaveFileName(
            this, QStringLiteral("保存原始帧"), QString(),
            QStringLiteral("pcap/二进制 (*.bin *.pcap)"));
        if (!file.isEmpty()) {
            QFile f(file);
            f.open(QIODevice::WriteOnly);
            f.write(pkt.raw);
        }
    }
}

void MainWindow::closeEvent(QCloseEvent* e)
{
    m_capture.stopCapture();
    m_capture.wait(3000);
    QMainWindow::closeEvent(e);
}
