#include "capturethread.h"
#include "packetparser.h"
#include <QDateTime>
#include <winsock2.h>
#include <pcap.h>

CaptureThread::CaptureThread(QObject* parent) : QThread(parent) {}

CaptureThread::~CaptureThread()
{
    stopCapture();
    wait(3000);
}

QList<QPair<QString, QString>> CaptureThread::enumerateDevices(QString* errorMsg)
{
    QList<QPair<QString, QString>> list;
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // pcap_findalldevs 枚举全部网卡
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        if (errorMsg) *errorMsg = QString::fromLatin1(errbuf);
        return list;
    }
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        const QString name = QString::fromLatin1(d->name);
        const QString desc = d->description ? QString::fromLatin1(d->description) : name;
        list.append(qMakePair(name, desc));
    }
    pcap_freealldevs(alldevs);
    return list;
}

void CaptureThread::startCapture(const QString& deviceName, const QString& bpfFilter)
{
    if (m_running.load()) {
        emit errorOccurred(QStringLiteral("已在抓包中，请先停止"));
        return;
    }
    m_device    = deviceName;
    m_bpfFilter = bpfFilter;
    m_running.store(true);
    start();   // 启动子线程进入 run()
}

void CaptureThread::stopCapture()
{
    if (!m_running.load())
        return;
    m_running.store(false);
    // pcap_breakloop 让 pcap_next_ex 立即返回，加速退出
    if (pcap* h = reinterpret_cast<pcap*>(m_handle.load()))
        pcap_breakloop(h);
}

void CaptureThread::run()
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // 打开网卡：65535 = 整帧捕获，1 = 混杂模式，100ms 超时
    pcap_t* handle = pcap_open_live(m_device.toStdString().c_str(),
                                    65535, 1, 100, errbuf);
    if (!handle) {
        m_running.store(false);
        emit errorOccurred(QStringLiteral("打开网卡失败: %1").arg(QString::fromLatin1(errbuf)));
        return;
    }

    // BPF 内核捕获过滤器
    if (!m_bpfFilter.isEmpty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, m_bpfFilter.toStdString().c_str(),
                         1, PCAP_NETMASK_UNKNOWN) == -1) {
            const QString err = QString::fromLatin1(pcap_geterr(handle));
            pcap_close(handle);
            m_running.store(false);
            emit errorOccurred(QStringLiteral("BPF 过滤表达式编译失败: %1").arg(err));
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            const QString err = QString::fromLatin1(pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            m_running.store(false);
            emit errorOccurred(QStringLiteral("设置 BPF 过滤器失败: %1").arg(err));
            return;
        }
        pcap_freecode(&fp);
    }

    m_handle.store(handle);
    emit captureStarted();

    struct pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;

    while (m_running.load()) {
        const int res = pcap_next_ex(handle, &header, &data);
        if (res == 0)            // 超时，无报文
            continue;
        if (res < 0) {           // 错误或被 breakloop
            if (m_running.load())
                emit errorOccurred(QStringLiteral("捕获错误: %1").arg(QString::fromLatin1(pcap_geterr(handle))));
            break;
        }
        // 拿到原始 const u_char* 以太网帧，解析后经信号槽传给 UI 线程
        PacketInfo pkt;
        pkt.timestampUs = qint64(header->ts.tv_sec) * 1000000 + header->ts.tv_usec;
        Parser::parse(data, int(header->caplen), pkt);
        emit packetCaptured(pkt);
    }

    m_handle.store(nullptr);
    pcap_close(handle);
    m_running.store(false);
    emit captureStopped();
}
