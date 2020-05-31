#include "easi.h"

extern WioLTE wio;

bool udpInit(UDPComm *udp, char *host, int port);
int udpSend(UDPComm *udp, uint8 *buf, int len);
int udpRecv(UDPComm *udp, uint8 *buf, int len, uint16 timeout);
void udpClearBuffer(UDPComm *udp);

bool udpInit(UDPComm *udp, char *host, int port){
    int sock = wio.SocketOpen(host, port, WIOLTE_UDP);
    if (sock >= 0){
        udp->sock = sock;
        strcpy(udp->host, host);
        udp->port = port;
        return true;
    } else {
        return false;
    }
}

int udpSend(UDPComm *udp, uint8 *buf, int len){
    bool ret = wio.SocketSend(udp->sock, buf, len);
    if (ret) {
        return len;
    } else {
        return 0;
    }
}

int udpRecv(UDPComm *udp, uint8 *buf, int len, uint16 timeout){
    int recvLen = wio.SocketReceive(udp->sock, buf, len, timeout);
    return recvLen;
}

void udpClearBuffer(UDPComm *udp){
    char buf[UDP_RECV_BUF_LENGTH];
    while (udpRecv(udp, (uint8 *)buf, sizeof(buf), 1000) > 0) { };
}
