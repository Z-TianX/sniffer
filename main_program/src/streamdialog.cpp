#include "streamdialog.h"
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QTextBrowser>
#include <QVBoxLayout>

StreamDialog::StreamDialog(const QString& html, const QString& title, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(title);
    resize(860, 560);

    auto* layout = new QVBoxLayout(this);
    m_view = new QTextBrowser(this);
    m_view->setOpenExternalLinks(false);
    m_view->setHtml(html);
    layout->addWidget(m_view);

    auto* btnSave = new QPushButton(QStringLiteral("另存为文本..."), this);
    connect(btnSave, &QPushButton::clicked, this, &StreamDialog::saveToFile);
    layout->addWidget(btnSave, 0, Qt::AlignRight);
}

void StreamDialog::saveToFile()
{
    const QString file = QFileDialog::getSaveFileName(
        this, QStringLiteral("保存 TCP 流内容"), QString(),
        QStringLiteral("文本文件 (*.txt)"));
    if (file.isEmpty())
        return;
    QFile f(file);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, QStringLiteral("保存失败"), f.errorString());
        return;
    }
    f.write(m_view->toPlainText().toUtf8());
}
