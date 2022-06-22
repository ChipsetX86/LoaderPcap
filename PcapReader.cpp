#include "PcapReader.h"

#include <QDebug>

#include <WS2tcpip.h>
#include <pcap/pcap.h>

const int ETHER_ADDR_LEN = 6;

enum PacketType: quint16 {
    IPV4 = 0x0008,
    IPV6 = 0xDD86
};

typedef quint8 EthernetAddress[ETHER_ADDR_LEN];

struct EthernetHeader
{
  EthernetAddress dst;
  EthernetAddress src;
  PacketType type;
};

struct IPv4Header {
        quint8  verisonAndLength;
        quint8  typeOfService;
        quint16 fullLength;
        quint16 id;
        quint16 flagsAndOffet;
        quint8  ttl;
        quint8  protocol;
        quint16 checksum;
        quint32 src;
        quint32 dst;
};

struct IPv6Header {
        quint32 ipVersionTrafficClassLabel;
        quint16 payloadLength;
        quint8 nextHeader;
        quint8 hopLimit;
        quint8 ipSrc[16];
        quint8 ipDst[16];
};

struct PcapReader::PImpl
{
    QString fileName;
    QList<IpPacket> listPacket;
    bool parsePacket(const struct pcap_pkthdr *header, const u_char *rawData, IpPacket &packet);
    QString getMac(const EthernetAddress addr);
    bool isTcp(quint8 protocol) const;
};

PcapReader::PcapReader(const QString &fileName):
    m_pimpl(new PImpl)
{
    m_pimpl->fileName = fileName;
}

PcapReader::~PcapReader()
{

}

bool PcapReader::PImpl::parsePacket(const pcap_pkthdr *header, const u_char *rawData, IpPacket &packet)
{
    if (!header || !rawData) {
        return false;
    }

    if (header->caplen < sizeof(EthernetHeader)) {
        qDebug() << "Packet length less than ethernet header length";
        return false;
    }

    auto ethHeader = reinterpret_cast<const EthernetHeader *>(rawData);
    packet.macSrc = getMac(ethHeader->src);
    packet.macDst = getMac(ethHeader->dst);

    switch (ethHeader->type) {
        case IPV4: {
            if (header->caplen < sizeof(EthernetHeader) + sizeof(IPv4Header)) {
                qDebug() << "IPv4 packet less than expected";
                return false;
            }
            auto ip4 = reinterpret_cast<const IPv4Header *>(rawData + sizeof(EthernetHeader));
            packet.ipSrc = QHostAddress(htonl(ip4->src));
            packet.ipDst = QHostAddress(htonl(ip4->dst));
            packet.isTcp = isTcp(ip4->protocol);
            break;
        }
        case IPV6: {
            if (header->caplen < sizeof(EthernetHeader) + sizeof(IPv6Header)) {
                qDebug() << "IPv6 packet less than expected";
                return false;
            }
            auto ip6 = reinterpret_cast<const IPv6Header *>(rawData + sizeof(EthernetHeader));
            packet.ipSrc = QHostAddress(ip6->ipSrc);
            packet.ipDst = QHostAddress(ip6->ipDst);
            packet.isTcp = isTcp(ip6->nextHeader);
            break;
        }
        default:
            qDebug() << QString("Unknown type = %1 packet").arg(ethHeader->type);
            return false;
    }

    return true;
}

QString PcapReader::PImpl::getMac(const EthernetAddress addr)
{
    QStringList list;
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        char buf[17];
        _itoa_s(addr[i], buf, 16);
        list.append((addr[i] < 9 ? QStringLiteral("0") : "") + QString(buf));
    }
    return list.join(":");
}

bool PcapReader::PImpl::isTcp(quint8 protocol) const
{
    return  protocol == IPPROTO_TCP;
}

QList<IpPacket> PcapReader::parse()
{
    if (!m_pimpl->listPacket.isEmpty()) {
        return m_pimpl->listPacket;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(m_pimpl->fileName.toStdString().c_str(), errbuf);
    if (!handle) {
        qDebug() << errbuf;
        return QList<IpPacket>();
    }

    pcap_pkthdr *packetHeader = nullptr;
    const u_char *packetData = nullptr;
    int status;
    while ((status = pcap_next_ex(handle, &packetHeader, &packetData)) && status != PCAP_ERROR_BREAK) {
        if (status == PCAP_ERROR) {
            qDebug() << "Found error" <<  pcap_geterr(handle);
            continue;
        }
        IpPacket packet;
        m_pimpl->parsePacket(packetHeader, packetData, packet);
        m_pimpl->listPacket.append(packet);
    }
    pcap_close(handle);

    return m_pimpl->listPacket;
}
