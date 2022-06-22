#ifndef PCAPREADER_H
#define PCAPREADER_H

#include <QScopedPointer>
#include <QList>
#include <QHostAddress>

struct IpPacket {
    QString macSrc;
    QString macDst;
    QHostAddress ipSrc;
    QHostAddress ipDst;
    bool isTcp;
};

class PcapReader
{
public:
    PcapReader(const QString &fileName);
    ~PcapReader();
    QList<IpPacket> parse();
private:
    struct PImpl;
    QScopedPointer<PImpl> m_pimpl;
};

#endif // PCAPREADER_H
