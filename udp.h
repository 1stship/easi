#ifndef _UDP_H
#define _UDP_H

#include <WioLTEforArduino.h>
#include "type.h"

typedef struct {
  int sock;
  char host[64];
  int port;
} UDPComm;

bool udpInit(UDPComm *udp, char *host, int port);
int udpSend(UDPComm *udp, uint8 *buf, int len);
int udpRecv(UDPComm *udp, uint8 *buf, int len, uint16 timeout);

#endif
