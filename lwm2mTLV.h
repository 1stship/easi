#ifndef _LWM2M_TLV_H
#define _LWM2M_TLV_H

#include "type.h"

enum Lwm2mTypeOfID {
    Lwm2mTLVTypeObjectInstance  = 0,
    Lwm2mTLVTypeResouceInstance,
    Lwm2mTLVTypeMultipleResouce,
    Lwm2mTLVTypeResouce
};

enum Lwm2mResourceType {
    Lwm2mResourceTypeString  = 0,
    Lwm2mResourceTypeInteger,
    Lwm2mResourceTypeFloat,
    Lwm2mResourceTypeBoolean,
    Lwm2mResourceTypeOpaque,
    Lwm2mResourceTypeTime,
    Lwm2mResourceTypeObjlnk,
    Lwm2mResourceTypeNone
};

typedef struct {
    enum Lwm2mTypeOfID typeOfId;
    enum Lwm2mResourceType resourceType;
    uint16 id;
    int64 intValue; // Integer, Time, Boolean
    float64 floatValue; // Float
    uint16 ObjectLinkValue; // objlnk
    uint16 InstanceLinkValue; // objlnk
    uint8 bytesValue[4096]; // String, Opaque
    int bytesLen; // string, Opaque
} Lwm2mTLV;

void lwm2mTLVInit(Lwm2mTLV *tlv, enum Lwm2mTypeOfID typeOfId, enum Lwm2mResourceType type, uint16 id);
int lwm2mTLVSerialize(Lwm2mTLV *tlv, uint8 *output);
uint16 lwm2mTLVGetID(uint8 *input);
int lwm2mTLVDeserialize(Lwm2mTLV *tlv, uint8 *input);

#endif
