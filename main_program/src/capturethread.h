#pragma once
#include <QThread>
#include <QList>
#include <QPair>
#include <QString>
#include <atomic>
#include "packetinfo.h"

struct pcap;

// NPS 原始数据包捕获线程：pcap_loop / pcap_next_ex 必须在子线程中运行，
// 禁止子线程直接操作 Qt UI，通过信号槽把 PacketInfo 传给主线程。
class CaptureThread : public QThread
{
    Q_OBJECT
public:
    explicit CaptureThread(QObject* parent = nullptr);
    ~CaptureThread() override;

    // 枚举网卡：返回 (设备名, 描述) 列表
    static QList<QPair<QString, QString>> enumerateDevices(QString* errorMsg);

    void startCapture(const QString& deviceName, const QString& bpfFilter);
    void stopCapture();

signals:
    void packetCaptured(const PacketInfo& pkt);
    void captureStarted();
    void captureStopped();
    void errorOccurred(const QString& msg);

protected:
    void run() override;

private:
    QString m_device;
    QString m_bpfFilter;
    std::atomic<bool> m_running{false};
    std::atomic<pcap*> m_handle{nullptr};   // 供 GUI 线程调用 pcap_breakloop
};
