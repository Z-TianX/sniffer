#pragma once
#include <QMainWindow>
#include <QVector>
#include "capturethread.h"
#include "packetinfo.h"
#include "processmapper.h"
#include "tcpstreamtable.h"

class QComboBox;
class QLineEdit;
class QLabel;
class QPushButton;
class QTableWidget;
class QTreeWidget;
class QPlainTextEdit;

// Qt6 三栏 GUI：上=报文列表，中=协议详情树，下=十六进制视图
class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

    // 自动演示模式（用于录屏/截图）：自动开始抓包→自动选中首个 TCP 载荷报文→自动弹出 Follow TCP Stream
    void enableAutoDemo(bool on, const QString& bpfFilter = QString(),
                        const QString& displayFilter = QString(),
                        const QString& procDemo = QString(),
                        const QString& shotsDir = QString());

protected:
    void closeEvent(QCloseEvent* e) override;

private slots:
    void refreshDevices();
    void backfillProcessInfo();   // 连接表刷新后回填历史报文的 PID/进程名
    void refreshProcessCombo();   // 刷新“进程筛选”下拉框（PID + 进程名）
    void onProcessFilterChanged();// 下拉框选中 → 生成 tcp && pid == N 表达式
    void onStart();
    void onStop();
    void onPacket(const PacketInfo& pkt);
    void onCaptureError(const QString& msg);
    void onSelectionChanged();
    void onDisplayFilterChanged();
    void onFollowStream();
    void onClear();
    void showContextMenu(const QPoint& pos);

private:
    void setupUi();
    void addPacketRow(int pktIndex);
    void buildTree(const PacketInfo& pkt);
    void showHex(const PacketInfo& pkt);
    void applyDisplayFilter();
    int  currentPacketIndex() const;

    QComboBox*      m_devCombo = nullptr;
    QComboBox*      m_procCombo = nullptr;     // 进程筛选：只看某进程产生的 TCP 流
    QLineEdit*      m_bpfEdit = nullptr;       // 输入框 A：BPF 内核捕获过滤器
    QLineEdit*      m_displayEdit = nullptr;   // 输入框 B：用户态显示过滤器
    QPushButton*    m_btnStart = nullptr;
    QPushButton*    m_btnStop = nullptr;
    QPushButton*    m_btnStream = nullptr;
    QTableWidget*   m_table = nullptr;
    QTreeWidget*    m_tree = nullptr;
    QPlainTextEdit* m_hexView = nullptr;
    QLabel*         m_status = nullptr;

    CaptureThread   m_capture;
    ProcessMapper*  m_processMapper = nullptr;
    TcpStreamTable  m_streams;
    QVector<PacketInfo> m_packets;    // 全部报文保存在内存，显示过滤仅隐藏界面条目
    QVector<int>    m_rowToPacket;
    QString         m_procComboSig;   // 进程下拉框内容签名（避免重复重建）
    quint64         m_packetCounter = 0;
};
