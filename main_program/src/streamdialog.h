#pragma once
#include <QDialog>
class QTextBrowser;

// Follow TCP Stream 结果弹窗（显式加分 1 的 GUI 交互）
class StreamDialog : public QDialog
{
    Q_OBJECT
public:
    StreamDialog(const QString& html, const QString& title, QWidget* parent = nullptr);

private slots:
    void saveToFile();

private:
    QTextBrowser* m_view = nullptr;
};
