#include <QDebug>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>

#include "PcapReader.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        qDebug() << "Not set .pcap file";
        return 1;
    }

    auto db = QSqlDatabase::addDatabase("QPSQL");
    db.setDatabaseName("medical_base_volna"); //db_network
    db.setUserName("postgres");
    db.setPassword("2300"); //12345678
    db.setHostName("localhost");
    db.setPort(5432);
    if (!db.open()) {
        qDebug() << "Database open error:" << db.lastError().text();
        return 1;
    }

    PcapReader reader((QString(argv[1])));
    const QList<IpPacket> listPackets = reader.parse();

    if (!db.transaction()) {
        qDebug() << "Database start transaction error:" << db.lastError().text();
        return 1;
    }

    QSqlQuery q(db);

    for (const auto &packet: listPackets) {
        if (packet.ipSrc.isNull() || packet.ipDst.isNull()) {
            continue;
        }

        q.prepare("INSERT INTO communications VALUES (:macSrc, :masDst, :ipSrc, :ipDst, :isTcp)");
        q.bindValue(":macSrc", packet.macSrc);
        q.bindValue(":masDst", packet.macDst);
        q.bindValue(":ipSrc", packet.ipSrc.toString());
        q.bindValue(":ipDst", packet.ipDst.toString());
        q.bindValue(":isTcp", packet.isTcp);
        if (!q.exec()) {
            qDebug() << "Database error:" << q.lastError().text();
            db.rollback();
            return 1;
        }
    }

    if (!db.commit()) {
        qDebug() << "Database end transaction error:" << db.lastError().text();
        return 1;
    }

    return 0;
}
