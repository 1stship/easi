#include "easi.h"

extern WioLTE wio;

void udpInit(UDP *udp, char *host, int port);
void udpSend(UDP *udp, uint8 *buf, int len);
int udpRecv(UDP *udp, uint8 *buf, int len, uint16 timeout);

void udpInit(UDP *udp, char *host, int port){
    udp->sock = wio.SocketOpen(host, port, WIOLTE_UDP);
}

void udpSend(UDP *udp, uint8 *buf, int len){
    wio.SocketSend(udp->sock, buf, len);
}

int udpRecv(UDP *udp, uint8 *buf, int len, uint16 timeout){
    int recvLen = wio.SocketReceive(udp->sock, buf, len, timeout);
    return recvLen;
}
