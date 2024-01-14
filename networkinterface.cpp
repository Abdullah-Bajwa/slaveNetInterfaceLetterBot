#include "networkinterface.h"


networkinterface::networkinterface(QObject *parent)
    : QObject{parent}
{
    udpSocket = new QUdpSocket(this);

    qDebug() << udpSocket->bind(udpPortListen);

    connect(udpSocket, &QUdpSocket::readyRead, this, &networkinterface::receiveUdpPackage);


    tcpSocket= new QTcpSocket(this);

    bool tcpSuccess = tcpSocket->bind(5465);
    tcpSuccess ? 
        qDebug() << "TCP Bind Successful." 
        :
        qDebug() << "TCP Bind Failed." << tcpSocket->errorString();

}

void networkinterface::receiveUdpPackage()
{
    qDebug()<<"receoved_updapackage";
    static QMap<QString, QByteArray> incompletePackets;

    while (udpSocket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(udpSocket->pendingDatagramSize());
        QHostAddress senderHostAddress;
        QString senderAddress;
        quint16 senderPort;

        // Receive the datagram
        udpSocket->readDatagram(datagram.data(), datagram.size(), &senderHostAddress, &senderPort);
        senderAddress = senderHostAddress.toString();

        // Process the received data
        qDebug() << "Received datagram from" << senderAddress << "on port" << senderPort;

        // Check for the start delimiters
        if (datagram.startsWith('\xEB') && datagram.at(1) == '\x90') {
            // New packet started, clear incomplete packet and put in the new packet
            incompletePackets[senderAddress] = datagram;
        } else {
            // If incomplete packet is empty, discard incoming data
            if (!incompletePackets.contains(senderAddress)) {
                qDebug() << "Discarding incoming data as it doesn't start with EB 90 and no incomplete packet for IP:" << senderAddress;
            } else {
                // Append the data to the existing incomplete packet for this IP
                incompletePackets[senderAddress] += datagram;
            }
        }

        // Check if the packet is complete based on the length
        while (incompletePackets.contains(senderAddress) && !incompletePackets[senderAddress].isEmpty() &&
               incompletePackets[senderAddress].size() >= 4) {
            quint16 packetLength = (static_cast<quint16>(incompletePackets[senderAddress].at(2)) << 8) |
                                   static_cast<quint16>(incompletePackets[senderAddress].at(3));
            if (incompletePackets[senderAddress].size() >= (4 + packetLength)) {
                // Complete packet received, call parseUDP
                QByteArray completePacket = incompletePackets[senderAddress].left(packetLength +4);
                parseUDP(completePacket, senderHostAddress);
                incompletePackets[senderAddress].remove(0, 4 + packetLength);  // Remove processed packet from the buffer
            } else {
                // Incomplete packet, break the loop
                break;
            }
        }
    }
}

/**
 * @brief UDP syntax check, data extraction and response dispatching
 * 
 * @param packet 
 * @param senderAddress 
 */
void networkinterface::parseUDP(const QByteArray &packet, const QHostAddress &senderAddress)
{
    qDebug() << "Parsing...\t"
             << packet;
    qDebug() << "Request from: " 
             << senderAddress;

    if(packet.size() >= 4) //EB 90 00 00 atleast
    {
        //check size of packet matches received packet
        uint16_t packet_size=0;
        packet_size = MAKE16INT(packet.at(2),packet.at(3));

        qDebug() << "Packet Size: " << packet_size;
        qDebug() << "Received Packet Size: " << packet.size()+1;
        if( packet_size == packet.size()-4)
        {
            uint8_t service = packet.at(4);
            
            switch(service)
            {
                case ID_Request:
                {
                    server.ipv4 = senderAddress;
                    server.ipAddress = senderAddress.toString();
                    qDebug() << "IP ADDRESS: " << server.ipAddress;
                    packUDP(ID_Request, senderAddress);
                    tcpready=1;
                    

                }break;

                case Acknowledge:
                {
                    if(tcpready)
                    {
                        // move to tcp connection
                        //TCP_SEND("Pi testing");
                        tcpSocket->connectToHost(server.ipv4,tcpPortDest);
                        Send_TCP();
                        
                    }else {
                        qDebug() <<"Missing Initializing";
                    }
                    
                }break;

                default:
                {
                    qDebug() << "Unknown service";
                }break;
            }
        }
        else 
        {
            qDebug() << "Malformed Packet: Packet size doesn't match";
        }
    }
    else {qDebug() << "Malformed Packet."; }
}

/**
 * @brief checks mode and dispatches udp packet
 * 
 * @param mode 
 * @param senderAddress 
 */
void networkinterface:: packUDP(uint8_t mode ,const QHostAddress &senderAddress)
{
    if( server.ipv4.isEqual(senderAddress) )
    {
        switch(mode)
        {
            case ID_Request:
            {
                transmitUdpData("\x01\x01", senderAddress, udpPortDest);
            }break;

            case Acknowledge:
                //nothing
                break;

            default:
                qDebug() << "Unknown ID";
            break;
        }
    }
    else
    {
        qDebug() << "IP addresses do not match";
    }
}

/**
 * @brief sends UDP data
 * 
 * @param data 
 * @param destinationAddress 
 * @param destinationPort 
 */
void networkinterface::transmitUdpData(const QString &data, const QHostAddress &destinationAddress, quint16 destinationPort)
{
    QByteArray message;
    QByteArray startDelimiters;
    QByteArray lengthBytes;

    // Append start delimiters (§ and ¦)
    startDelimiters.append('\xEB');
    startDelimiters.append('\x90');

    // Convert the length of the data to two bytes
    quint16 dataLength = static_cast<quint16>(data.size());
    lengthBytes.append((dataLength >> 8) & 0xFF);
    lengthBytes.append(dataLength & 0xFF);

    // Append start delimiters and length bytes to the message
    message.append(startDelimiters);
    message.append(lengthBytes);

    // Append the actual data
    message.append(data.toUtf8());
    qDebug()<<message;

    qint64 bytesSent = udpSocket->writeDatagram(message, destinationAddress, destinationPort);

    if (bytesSent == -1) {
        qDebug() << "Error sending message:" << udpSocket->errorString();
    } else {
        qDebug() << "Message sent successfully!";
    }
}

/**
 * @brief Sends tcp packet upon button press
 * 
 */
void networkinterface::Send_TCP()
{
    if(tcpSocket->isOpen())
    {
        tcpSocket->write("TCP PI: HELLO");
    }
    else
    {
        qDebug() << "TCP Connection not established";
    }
}