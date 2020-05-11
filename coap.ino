#include "easi.h"

const uint8 CoapVersion = 1;
const uint8 CoapTokenLength = 8;
const uint8 CoapOptCodeByte = 13;
const uint8 CoapOptCodeWord = 14;
const uint16 CoapOptByteBase = 13;
const uint16 CoapOptWordBase = 269;
const uint8 CoapOptionEnd = 0xff;

void coapPrepare(Coap *coap);
int coapCreateRequestHeader(Coap *coap, enum CoapType type, enum CoapCode code, uint8 *output);
int coapCreateResponseHeader(Coap *coap, enum CoapType type, enum CoapCode code, uint8 *output);
void coapInitOptions(CoapOptions *options);
uint16 coapSetOptions(CoapOptions *options, uint8 *output);
int coapParseOptions(uint8 *input, int len, CoapOptions *options);

uint16 coapSetOption(uint16 delta, uint8 *value, uint16 valueLen, uint8 *output);

void coapPrepare(Coap *coap){
    coap->nextMessageID = (uint16)rand();
    coap->ackMessageID = 0;
    memset(&coap->ackToken[0], 0, sizeof(coap->ackToken));
}

int coapCreateRequestHeader(Coap *coap, enum CoapType type, enum CoapCode code, uint8 *output){
    int index = 0;
    uint8 token[8];
    for(int i = 0; i < 8; i++){
        token[i] = (uint8)(rand());
    }

    output[index++] = (CoapVersion << 6) // Version = 1
        + (type << 4)
        + CoapTokenLength; // Token length = 8
    output[index++] = code;
    index += putUint16ToBytes(coap->nextMessageID++, &output[index]);
    memcpy(&output[4], token, CoapTokenLength);
    index += CoapTokenLength;
    
    return index;
}

int coapCreateResponseHeader(Coap *coap, enum CoapType type, enum CoapCode code, uint8 *output){
    int index = 0;

    output[index++] = (CoapVersion << 6) // Version = 1
        + (type << 4)
        + CoapTokenLength; // Token length = 8
    output[index++] = code;
    index += putUint16ToBytes(coap->ackMessageID, &output[index]);
    memcpy(&output[4], &coap->ackToken[0], CoapTokenLength);
    index += CoapTokenLength;
    
    return index;
}

void coapInitOptions(CoapOptions *options){
    options->format = 0;
    options->pathLen = 0;
    for (int i = 0; i < 3; i++){
        memset(&options->paths[i][0], 0, 16);
    }
    options->locationLen = 0;
    for (int i = 0; i < 2; i++){
        memset(&options->locations[i][0], 0, 16);
    }
    options->queryLen = 0;
    for (int i = 0; i < 4; i++){
        memset(&options->queryKey[i][0], 0, 16);
        memset(&options->queryValue[i][0], 0, 64);
    }
}

uint16 coapSetOptions(CoapOptions *options, uint8 *output){
    uint16 index = 0;
    uint16 optionNo = 0;
    for (int i = 0; i < options->pathLen; i++){
        index += coapSetOption(CoapOptionNoURIPath - optionNo, (uint8 *)&options->paths[i][0], strlen((char *)&options->paths[i][0]), &output[index]);
        optionNo = CoapOptionNoURIPath;
    }

    if (options->format != 0){
        if (options->format < 255){
            uint8 format[1];
            format[0] = (uint8)(options->format);
            index += coapSetOption(CoapOptionNoContentFormat - optionNo, format, 1, &output[index]);
        } else {
            uint8 format[2];
            putUint16ToBytes(options->format, &format[0]);
            index += coapSetOption(CoapOptionNoContentFormat - optionNo, format, 2, &output[index]);
        }
        optionNo = CoapOptionNoContentFormat;
    }

    for (int i = 0; i < options->queryLen; i++){
        char query[128];
        sprintf(query, "%s=%s", (char *)options->queryKey[i], (char *)options->queryValue[i]);
        index += coapSetOption(CoapOptionNoURIQuery - optionNo, (uint8 *)query, strlen(query), &output[index]);
        optionNo = CoapOptionNoURIQuery;
    }

    return index;
}

int coapParseOptions(uint8 *input, int len, CoapOptions *options){
    int index = 0;
    int optionNo = 0;
    options->pathLen = 0;
    options->locationLen = 0;
    while (index < len && input[index] != CoapOptionEnd){
        int delta = (uint8)((input[index] >> 4) & 0x0f);
        int len = (uint8)(input[index] & 0x0f);
        index++;
        if (delta == CoapOptCodeByte){
            delta = input[index++] + CoapOptByteBase;
        } else if (delta == CoapOptCodeWord){
            delta = getUint16FromBytes(&input[index]) + CoapOptWordBase;
            index += 2;
        }
        optionNo += delta;

        if (len == CoapOptCodeByte){
            len = input[index++] + CoapOptByteBase;
        } else if (len == CoapOptCodeWord){
            len = getUint16FromBytes(&input[index]) + CoapOptWordBase;
            index += 2;
        }

        uint8 value[len];
        memcpy(value, &input[index], len);
        index += len;

        if (optionNo == CoapOptionNoLocationPath){
            memcpy(&options->locations[options->locationLen][0], &value[0], len);
            options->locations[options->locationLen][len] = 0;
            options->locationLen++;
        }

        if (optionNo == CoapOptionNoURIPath){
            memcpy(&options->paths[options->pathLen][0], &value[0], len);
            options->paths[options->pathLen][len] = 0;
            options->pathLen++;
        }
    }

    if (input[index] == CoapOptionEnd){
        index++;
    }

    return index;
}

uint16 coapSetOption(uint16 delta, uint8 *value, uint16 valueLen, uint8 *output){
    int index = 0;
    output[0] = 0;
    index++;
  if (delta < CoapOptByteBase) {
    output[0] += (uint8)(delta << 4);
  } else if (delta < CoapOptWordBase) {
    output[0] += (uint8)(CoapOptCodeByte << 4);
        output[index++] = (uint8)(delta - CoapOptByteBase);
  } else {
        output[0] += (uint8)(CoapOptCodeWord << 4);
        index += putUint16ToBytes(delta - CoapOptWordBase, &output[index]);
  }

    if (valueLen < CoapOptByteBase) {
    output[0] += (uint8)(valueLen);
  } else if (valueLen < CoapOptWordBase) {
    output[0] += CoapOptCodeByte;
        output[index++] = (uint8)(valueLen - CoapOptByteBase);
  } else {
        output[0] += CoapOptCodeWord;
        index += putUint16ToBytes(valueLen - CoapOptWordBase, &output[index]);
  }

  memcpy(&output[index], value, valueLen);
    index += valueLen;

  return index;
}
