#ifndef _DTLS_H
#define _DTLS_H

#include "type.h"
#include "udp.h"

typedef struct {
    uint16 messageLen;
    uint16 serverSequence;
    uint16 clientSequence;
    uint8 identity[64];
    uint8 cookie[32];
    uint8 session[64];
    uint8 clientRandom[64];
    uint8 serverRandom[64];
    uint8 preMasterSecret[64];
    uint8 masterSecret[64];
    uint8 messages[1024];
} DtlsHandshake;

typedef struct {
    DtlsHandshake handshake;
    UDPComm udp;
    uint16 serverEpoch;
    uint16 clientEpoch;
    uint64 serverSequence;
    uint64 clientSequence;
    uint8 serverWriteKey[16];
    uint8 clientWriteKey[16];
    uint8 serverIV[4];
    uint8 clientIV[4];
    bool clientEncrypt;
    bool serverEncrypt;
    bool verified;
} Dtls;

bool startHandshake(Dtls *dtls, char *identity, uint8 *psk);
bool dtlsSendPacket(Dtls *dtls, uint8 *data, uint16 len);
int dtlsRecvPacket(Dtls *dtls, uint8 *output, uint16 timeout);

#endif
