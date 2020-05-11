#ifndef _LWM2M_RESOURCE_H
#define _LWM2M_RESOURCE_H

#include "type.h"
#include "lwm2mTLV.h"

typedef struct {
    uint16 id;
    uint8 operation;
    enum Lwm2mResourceType type;
    void (*read)(Lwm2mTLV *tlv);
    void (*write)(Lwm2mTLV *tlv);
    void (*execute)(Lwm2mTLV *tlv);
} Lwm2mResource;

typedef struct {
    uint16 objectID;
    uint16 instanceID;
    Lwm2mResource *resources;
    int resourceLen;
} Lwm2mInstance;

typedef struct Lwm2mInstanceList{
    Lwm2mInstance *instance;
    struct Lwm2mInstanceList *next;
} Lwm2mInstanceList;

typedef struct {
    uint16 objectID;
    const Lwm2mResource *resources;
    int size;
} Lwm2mObjectTemplate;

void initInstance();
bool addInstance(uint16 objectID, uint16 instanceID);
int createRegisterContent(uint8 *output);
int readInstanceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *output);
int readResourceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *output);
int writeInstanceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *input, uint16 len);
int writeResourceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len);
int executeResourceOperation(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len);
bool setReadResourceOperation(uint16 objectID, uint16 instanceID, uint16 resourceID, void (*func)(Lwm2mTLV *tlv));
bool setWriteResourceOperation(uint16 objectID, uint16 instanceID, uint16 resourceID, void (*func)(Lwm2mTLV *tlv));
bool setExecuteResourceOperation(uint16 objectID, uint16 instanceID, uint16 resourceID, void (*func)(Lwm2mTLV *tlv));

#endif
