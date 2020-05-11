#ifndef _LWM2M_H
#define _LWM2M_H

#include "type.h"
#include "dtls.h"
#include "coap.h"

typedef struct {
    Dtls dtls;
    char identity[32];
    uint8 psk[16];
    Coap coap;
    UDP bootstrapUdp;
    uint8 endpoint[64];
    uint32 updatedTimestamp;
    uint8 location[16];
    bool registered;
    bool bootstraped;
} Lwm2m;

void lwm2mInit(Lwm2m *lwm2m, char *endpoint);
bool lwm2mBootstrap(Lwm2m *lwm2m);
void lwm2mSetSecurityParam(Lwm2m *lwm2m, char *identity, uint8 *psk);
void lwm2mPrepare(Lwm2m *lwm2m);
bool lwm2mCheckEvent(Lwm2m *lwm2m);

#endif
