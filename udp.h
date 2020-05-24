#ifndef _UDP_H
#define _UDP_H

#include <WioLTEforArduino.h>
#include "type.h"

typedef struct {
  int sock;
} UDP;

void udpInit(UDP *udp, char *host, int port);
void udpSend(UDP *udp, uint8 *buf, int len);
int udpRecv(UDP *udp, uint8 *buf, int len, uint16 timeout);

#endif
