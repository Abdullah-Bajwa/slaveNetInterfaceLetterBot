#ifndef NETWORKINTERFACE_H
#define NETWORKINTERFACE_H

#include "qabstractsocket.h"
#include "qdebug.h"
#include "qnamespace.h"
#include "qobject.h"
#include "qudpsocket.h"
#include "qvector.h"
#include <QUdpSocket>
#include <QTcpSocket>
#include <QTcpServer>
#include <QHostAddress>
#include <QNetworkInterface>
#include <QTimer>
#include <QMap>
#include <QString>
#include <QVector>
#include <QList>

#include <QObject>

#define MAKE16INT(v1,v2) (uint16_t)((((uint16_t)(v1))<<8)+(v2));
#define PI_ID 2

typedef struct clientPi {
    uint16_t id = PI_ID;
    QString ipAddress = "";

} clientPi;

typedef struct Server {
    QString ipAddress="";
    QHostAddress ipv4;
    bool tcpready=0; // in case concurrent connections are required
} Server;

class networkinterface : public QObject
{
    Q_OBJECT
public:
    networkinterface(QObject* parent =  nullptr);

    const int udpPortDest = 5454;
    const int udpPortListen = 5454;
    const int tcpPortDest = 5464;

    QVector<clientPi> clientsVector;

    clientPi CPi;
    Server server;

    QUdpSocket* udpSocket;
    QTcpSocket* tcpSocket;
    bool tcpready=0;

    /**
     * @brief PACKET mode
     * 
     */
    enum MODE:uint8_t
    {
        ID_Request      = 1,
        Acknowledge     = 2,
    };

    void parseUDP(const QByteArray &packet, const QHostAddress &senderAddress);
    void packUDP(uint8_t mode ,const QHostAddress &senderAddress);
    
    /** Sends a character array on the tcp connection **/
    //void TCP_SEND(QString Data);
    //void TCP_RECEIVE();


signals:
    void receiveDataSignal(const QByteArray &data);
    void networkDiscoveryCompleteSignal();

private slots:
    void OnTCPDisconnect();

public slots:
    //void sendDataSlot(const QString &data);
    void transmitUdpData(const QString &data, const QHostAddress &destinationAddress, quint16 destinationPort);
    void receiveUdpPackage();
    void Send_TCP();
    //datasend();
    //idupdate;
    //void startDiscoverySlot();
    //void onDisconnected();
    //void incomingConnection(qintptr socketDescriptor);
};

#endif // NETWORKINTERFACE_H
