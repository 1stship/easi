#include "easi.h"

void lwm2mTLVInit(Lwm2mTLV *tlv, enum Lwm2mTypeOfID typeOfId, enum Lwm2mResourceType type, uint16 id);
int lwm2mTLVSerialize(Lwm2mTLV *tlv, uint8 *output);
uint16 lwm2mTLVGetID(uint8 *input);
int lwm2mTLVDeserialize(Lwm2mTLV *tlv, uint8 *input);

void lwm2mTLVInit(Lwm2mTLV *tlv, enum Lwm2mTypeOfID typeOfId, enum Lwm2mResourceType type, uint16 id){
    tlv->typeOfId = typeOfId;
    tlv->resourceType = type;
    tlv->id = id;
    tlv->intValue = 0;
    tlv->floatValue = 0;
    memset(tlv->bytesValue, 0, sizeof(tlv->bytesValue));
    tlv->bytesLen = 0;
    tlv->ObjectLinkValue = 0;
    tlv->InstanceLinkValue = 0;
}

// outputにTLVシリアライズ結果を格納してサイズを返す
int lwm2mTLVSerialize(Lwm2mTLV *tlv, uint8 *output){
    uint8 value[4096];
    uint32 len = 0;

    switch (tlv->resourceType){
        case Lwm2mResourceTypeInteger:
        case Lwm2mResourceTypeTime:
            if ( tlv->intValue <= 127 && tlv->intValue >= -128) {
                value[len++] = (uint8)(tlv->intValue);
            } else if (tlv->intValue <= 32767 && tlv->intValue >= -32768) {
                len += putUint16ToBytes((uint16)(tlv->intValue), &value[len]);
            } else if (tlv->intValue <= 2147483647L && tlv->intValue >= -2147483648L) {
                len += putUint32ToBytes((uint32)(tlv->intValue), &value[len]);
            } else {
                len += putUint64ToBytes((uint64)(tlv->intValue), &value[len]);
            }
            break;
        case Lwm2mResourceTypeFloat:
            len += putFloat64ToBytes((float64)(tlv->floatValue), &value[len]);
            break;
        case Lwm2mResourceTypeBoolean:
            value[len++] = (uint8)(tlv->intValue);
            break;
        case Lwm2mResourceTypeObjlnk:
            len += putUint16ToBytes((uint16)(tlv->ObjectLinkValue), &value[len]);
            len += putUint16ToBytes((uint16)(tlv->InstanceLinkValue), &value[len]);
            break;
        case Lwm2mResourceTypeString:
            strcpy((char *)&value[0], (char *)&tlv->bytesValue[0]);
            len = strlen((char *)&value[0]);
            break;
        case Lwm2mResourceTypeOpaque:
        case Lwm2mResourceTypeNone:
            if (tlv->bytesLen > 0){
                memcpy(value, &tlv->bytesValue[0], tlv->bytesLen);
            }
            len = tlv->bytesLen;
            break;
        default:
            break;
    }

    int index = 0;
    output[0] = tlv->typeOfId << 6;
    index++;
    
    if (tlv->id <= 0xff){
        output[index++] = (uint8)(tlv->id);
    } else {
        output[0] += (1 << 5);
        index += putUint16ToBytes(tlv->id, &output[index]);
    }

    if (len <= 0x07){
        output[0] += (uint8)(len);
    } else if (len <= 0xff){
        output[0] += (1 << 3);
        output[index++] = (uint8)(len);
    } else if (len <= 0xffff){
        output[0] += (2 << 3);
        index += putUint16ToBytes((uint16)len, &output[index]);
    } else {
        output[0] += (3 << 3);
        index += putUint24ToBytes((uint32)len, &output[index]);
    }
  
    if (len > 0){
        memcpy(&output[index], &value[0], len);
        index += len;
    }
    
    return index;
}

uint16 lwm2mTLVGetID(uint8 *input){
    if ((input[0] & 0x20) == 0) {
        return (uint16)input[1];
    } else {
        return getUint16FromBytes(&input[1]);
    }
}

int lwm2mTLVDeserialize(Lwm2mTLV *tlv, uint8 *input){
    uint16 index = 0;
    tlv->typeOfId = (enum Lwm2mTypeOfID)(input[0] >> 6);
    index++;
    if ((input[0] & 0x20) == 0) {
        tlv->id = (uint16)input[index++];
    } else {
        tlv->id = getUint16FromBytes(&input[index]);
        index += 2;
    }

    uint32 len;
    uint8 lenOfLen = (input[0] >> 3) & 0x03;
    if (lenOfLen == 0) {
        len = input[0] & 0x07;
    } else if (lenOfLen == 1) {
        len = input[index++];
    } else if (lenOfLen == 2) {
        len = getUint16FromBytes(&input[index++]);
        index += 2;
    } else if (lenOfLen == 3) {
        len = getUint24FromBytes(&input[index++]);
        index += 3;
    }

    switch (tlv->resourceType){
        case Lwm2mResourceTypeInteger:
        case Lwm2mResourceTypeTime:
            if (len == 1){
                tlv->intValue = (int8)(input[index]);
            } else if (len == 2){
                tlv->intValue = (int16)(getUint16FromBytes(&input[index]));
            } else if (len == 4){
                tlv->intValue = (int32)(getUint32FromBytes(&input[index]));
            } else if (len == 8){
                tlv->intValue = (int64)(getUint64FromBytes(&input[index]));
            }
            break;
        case Lwm2mResourceTypeFloat:
            tlv->floatValue = (float64)(getFloat64FromBytes(&input[index]));
            break;
        case Lwm2mResourceTypeBoolean:
            tlv->intValue = input[index];
            break;
        case Lwm2mResourceTypeObjlnk:
            tlv->ObjectLinkValue = (uint16)(getUint16FromBytes(&input[index]));
            tlv->InstanceLinkValue = (uint16)(getUint16FromBytes(&input[index + 2]));
            break;
        case Lwm2mResourceTypeString:
            memcpy(&tlv->bytesValue[0], &input[index], len);
            tlv->bytesValue[len] = 0;
            break;
        case Lwm2mResourceTypeOpaque:
        case Lwm2mResourceTypeNone:
            if (len > 0){
                memcpy(&tlv->bytesValue[0], &input[index], len);
            }
            tlv->bytesLen = len;
            break;
        default:
            break;
    }

    index += len;
    
    return index;
}
