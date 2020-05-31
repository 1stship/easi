#include "easi.h"

void lwm2mInit(Lwm2m *lwm2m, char *endpoint);
bool lwm2mBootstrap(Lwm2m *lwm2m);
void lwm2mSetSecurityParam(Lwm2m *lwm2m, char *identity, uint8 *psk);
void lwm2mPrepare(Lwm2m *lwm2m);
bool lwm2mCheckEvent(Lwm2m *lwm2m);
bool lwm2mRegister(Lwm2m *lwm2m);
bool lwm2mUpdate(Lwm2m *lwm2m);
void lwm2mReadObject(Lwm2m *lwm2m, uint16 objectID);
void lwm2mReadInstance(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID);
void lwm2mReadResource(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID);
void lwm2mWriteInstance(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *input, uint16 len);
void lwm2mWriteResource(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len);
void lwm2mExecuteResource(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len);
void lwm2mParsePacket(Lwm2m *lwm2m, uint8 *buf, int len);
void lwm2mReceivePacketWithTimeoutError(Lwm2m *lwm2m, uint16 timeout);
void lwm2mReadRequest(Lwm2m *lwm2m, uint8 *buf, int len);
void lwm2mWriteRequest(Lwm2m *lwm2m, uint8 *buf, int len);
void lwm2mExecuteRequest(Lwm2m *lwm2m, uint8 *buf, int len);
void lwm2mSendBootstrapResponse(Lwm2m *lwm2m, enum CoapCode code);
void lwm2mDeleteRequest(Lwm2m *lwm2m, uint8 *buf, int len);
void lwm2mBootstrapFinishRequest(Lwm2m *lwm2m, uint8 *buf, int len);
void lwm2mClearBuffer();

void lwm2mInit(Lwm2m *lwm2m, char *endpoint){
    randomSeed(analogRead(0));
    strncpy((char *)&lwm2m->endpoint[0], endpoint, sizeof(lwm2m->endpoint));
    lwm2m->registered = false;
    lwm2m->bootstraped = false;
    lwm2m->dtls.verified = false;
    initInstance();
}

bool lwm2mBootstrap(Lwm2m *lwm2m){
    uint8 buf[1024];
    int index = 0;
    coapPrepare(&lwm2m->coap);
    udpClearBuffer(&lwm2m->bootstrapUdp);
    index += coapCreateRequestHeader(&lwm2m->coap, CoapTypeConfirmable, CoapCodePost, &buf[index]);

    CoapOptions options;
    coapInitOptions(&options);
    strcpy(options.paths[0], "bs");
    options.pathLen = 1;
    strcpy(options.queryKey[0], "ep");
    strcpy(options.queryValue[0], (char *)lwm2m->endpoint);
    options.queryLen = 1;
    index += coapSetOptions(&options, &buf[index]);

    udpSend(&lwm2m->bootstrapUdp, buf, index);

    while (!lwm2m->bootstraped) {
        uint8 recvBuf[UDP_RECV_BUF_LENGTH];
        int readLen = udpRecv(&lwm2m->bootstrapUdp, recvBuf, sizeof(recvBuf), 5000);
        if (readLen == 0){
            return false;
        } else {
            lwm2mParsePacket(lwm2m, recvBuf, readLen);
        }
    }

    return true;
}

void lwm2mSetSecurityParam(Lwm2m *lwm2m, char *identity, uint8 *psk){
    strcpy(&lwm2m->identity[0], identity);
    memcpy(&lwm2m->psk[0], psk, 16);
    lwm2m->bootstraped = true;
}

void lwm2mPrepare(Lwm2m *lwm2m){
    coapPrepare(&lwm2m->coap);
    lwm2m->updatedTimestamp = 0;
    memset(&lwm2m->location[0], 0, sizeof(lwm2m->location));
    lwm2m->registered = false;
}

bool lwm2mCheckEvent(Lwm2m *lwm2m){
    if (!lwm2m->dtls.verified){
        if (startHandshake(&lwm2m->dtls, lwm2m->identity, lwm2m->psk)){
            lwm2mPrepare(lwm2m);
        }
        return true;
    }

    if (!lwm2m->registered){
        logText("Register");
        lwm2mRegister(lwm2m);
        return true;
    }

    if (getNowMilliseconds() - lwm2m->updatedTimestamp > 54000UL){
        logText("Update");
        lwm2mUpdate(lwm2m);
        return true;
    }

    uint8 recvBuf[UDP_RECV_BUF_LENGTH];
    int recvLen = dtlsRecvPacket(&lwm2m->dtls, recvBuf, 1000);
    if (recvLen < 0){
        logText("Receive invalid packet");
        lwm2m->dtls.verified = false;
        lwm2m->registered = false;
        return true;
    } else if (recvLen > 0){
        lwm2mParsePacket(lwm2m, recvBuf, recvLen);
        return true;
    }

    // logText("No event");
    return false;
}

void lwm2mReadRequest(Lwm2m *lwm2m, uint8 *buf, int len){
    CoapOptions options;
    int index = 0;
    index += coapParseOptions(&buf[index], len - index, &options);

    if (options.pathLen == 1){
        lwm2mReadObject(lwm2m, atoi(options.paths[0]));
    } else if (options.pathLen == 2){
        lwm2mReadInstance(lwm2m, atoi(options.paths[0]), atoi(options.paths[1]));
    } else if (options.pathLen == 3){
        lwm2mReadResource(lwm2m, atoi(options.paths[0]), atoi(options.paths[1]), atoi(options.paths[2]));
    }
}

void lwm2mWriteRequest(Lwm2m *lwm2m, uint8 *buf, int len){
    CoapOptions options;
    int index = 0;
    index += coapParseOptions(&buf[index], len - index, &options);

    if (options.pathLen == 2){
        lwm2mWriteInstance(lwm2m, atoi(options.paths[0]), atoi(options.paths[1]), &buf[index], len - index);
    } else if (options.pathLen == 3){
        lwm2mWriteResource(lwm2m, atoi(options.paths[0]), atoi(options.paths[1]), atoi(options.paths[2]), &buf[index], len - index);
    }
}

void lwm2mExecuteRequest(Lwm2m *lwm2m, uint8 *buf, int len){
    CoapOptions options;
    int index = 0;
    index += coapParseOptions(&buf[index], len - index, &options);

    if (options.pathLen == 3){
        lwm2mExecuteResource(lwm2m, atoi(options.paths[0]), atoi(options.paths[1]), atoi(options.paths[2]), &buf[index], len - index);
    }
}

void lwm2mSendBootstrapResponse(Lwm2m *lwm2m, enum CoapCode code){
    uint8 buf[1024];
    int index = 0;
    index += coapCreateResponseHeader(&lwm2m->coap, CoapTypeAcknowledgement, code, &buf[index]);
    udpSend(&lwm2m->bootstrapUdp, buf, index);
}

void lwm2mDeleteRequest(Lwm2m *lwm2m, uint8 *buf, int len){
    CoapOptions options;
    int index = 0;
    index += coapParseOptions(&buf[index], len - index, &options);

    if (!lwm2m->bootstraped){
        lwm2mSendBootstrapResponse(lwm2m, CoapCodeDeleted);
    }
}

void lwm2mBootstrapFinishRequest(Lwm2m *lwm2m, uint8 *buf, int len){
    CoapOptions options;
    int index = 0;
    index += coapParseOptions(&buf[index], len - index, &options);
    lwm2mSendBootstrapResponse(lwm2m, CoapCodeChanged);
    lwm2m->bootstraped = true;
}

bool lwm2mRegister(Lwm2m *lwm2m){
    uint8 buf[1024];
    int index = 0;
    index += coapCreateRequestHeader(&lwm2m->coap, CoapTypeConfirmable, CoapCodePost, &buf[index]);

    CoapOptions options;
    coapInitOptions(&options);
    strcpy(options.paths[0], "rd");
    options.pathLen = 1;
    options.format = 0x28;
    strcpy(options.queryKey[0], "lwm2m");
    strcpy(options.queryValue[0], "1.0");
    strcpy(options.queryKey[1], "ep");
    strcpy(options.queryValue[1], (char *)lwm2m->endpoint);
    strcpy(options.queryKey[2], "b");
    strcpy(options.queryValue[2], "U");
    strcpy(options.queryKey[3], "lt");
    strcpy(options.queryValue[3], "60");
    options.queryLen = 4;
    index += coapSetOptions(&options, &buf[index]);

    buf[index++] = 0xff;

    index += createRegisterContent(&buf[index]);

    dtlsSendPacket(&lwm2m->dtls, buf, index);
    lwm2m->coap.nextMessageID++;

    lwm2mReceivePacketWithTimeoutError(lwm2m, 1000);

    return lwm2m->registered;
}

bool lwm2mUpdate(Lwm2m *lwm2m){
    uint8 buf[1024];
    int index = 0;
    index += coapCreateRequestHeader(&lwm2m->coap, CoapTypeConfirmable, CoapCodePost, &buf[index]);

    CoapOptions options;
    coapInitOptions(&options);
    strcpy(options.paths[0], "rd");
    strcpy(options.paths[1], (char *)lwm2m->location);
    options.pathLen = 2;
    index += coapSetOptions(&options, &buf[index]);

    dtlsSendPacket(&lwm2m->dtls, buf, index);

    lwm2mReceivePacketWithTimeoutError(lwm2m, 1000);

    return lwm2m->registered;
}

void lwm2mReadObject(Lwm2m *lwm2m, uint16 objectID){
    char text[64];
    sprintf(text, "READ /%u", objectID);
    logText(text);
}

void lwm2mReadInstance(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID){
    char text[64];
    sprintf(text, "READ /%u/%u", objectID, instanceID);
    logText(text);

    uint8 buf[1024];
    int index = 0;
    index += coapCreateResponseHeader(&lwm2m->coap, CoapTypeAcknowledgement, CoapCodeContent, &buf[index]);

    CoapOptions options;
    coapInitOptions(&options);
    options.format = 0x2d16;
    index += coapSetOptions(&options, &buf[index]);

    buf[index++] = 0xff;

    int result = readInstanceOperation(lwm2m, objectID, instanceID, &buf[index]);
    if (result >= 0){
        index += result;
    } else {
        // エラーが発生した場合はCoapCodeを上書きする
        buf[1] = (uint8)(-result);
        buf[--index] = 0;
    }

    dtlsSendPacket(&lwm2m->dtls, buf, index);
}

void lwm2mReadResource(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID){
    char text[64];
    sprintf(text, "READ /%u/%u/%u", objectID, instanceID, resourceID);
    logText(text);

    uint8 buf[1024];
    int index = 0;
    index += coapCreateResponseHeader(&lwm2m->coap, CoapTypeAcknowledgement, CoapCodeContent, &buf[index]);

    CoapOptions options;
    coapInitOptions(&options);
    options.format = 0x2d16;
    index += coapSetOptions(&options, &buf[index]);

    buf[index++] = 0xff;

    int result = readResourceOperation(lwm2m, objectID, instanceID, resourceID, &buf[index]);
    if (result >= 0){
        index += result;
    } else {
        // エラーが発生した場合はCoapCodeを上書きする
        buf[1] = (uint8)(-result);
        buf[--index] = 0;
    }

    dtlsSendPacket(&lwm2m->dtls, buf, index);
}

void lwm2mWriteInstance(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint8 *input, uint16 len){
    char text[64];
    sprintf(text, "WRITE /%u/%u", objectID, instanceID);
    logText(text);

    uint8 buf[1024];
    int index = 0;
    index += coapCreateResponseHeader(&lwm2m->coap, CoapTypeAcknowledgement, CoapCodeChanged, &buf[index]);

    int result = writeInstanceOperation(lwm2m, objectID, instanceID, input, len);
    if (result < 0){
        // エラーが発生した場合はCoapCodeを上書きする
        buf[1] = (uint8)(-result);
    }

    if (lwm2m->bootstraped){
        dtlsSendPacket(&lwm2m->dtls, buf, index);
    } else {
        udpSend(&lwm2m->bootstrapUdp, buf, index);
    }
}

void lwm2mWriteResource(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len){
    char text[64];
    sprintf(text, "WRITE /%u/%u/%u", objectID, instanceID, resourceID);
    logText(text);

    uint8 buf[1024];
    int index = 0;
    index += coapCreateResponseHeader(&lwm2m->coap, CoapTypeAcknowledgement, CoapCodeChanged, &buf[index]);

    int result = writeResourceOperation(lwm2m, objectID, instanceID, resourceID, input, len);
    if (result < 0){
        // エラーが発生した場合はCoapCodeを上書きする
        buf[1] = (uint8)(-result);
    }

    dtlsSendPacket(&lwm2m->dtls, buf, index);
}

void lwm2mExecuteResource(Lwm2m *lwm2m, uint16 objectID, uint16 instanceID, uint16 resourceID, uint8 *input, uint16 len){
    char text[64];
    sprintf(text, "EXECUTE /%u/%u/%u", objectID, instanceID, resourceID);
    logText(text);

    uint8 buf[1024];
    int index = 0;
    index += coapCreateResponseHeader(&lwm2m->coap, CoapTypeAcknowledgement, CoapCodeChanged, &buf[index]);
    
    int result = executeResourceOperation(lwm2m, objectID, instanceID, resourceID, input, len);
    if (result < 0){
        // エラーが発生した場合はCoapCodeを上書きする
        buf[1] = (uint8)(-result);
    }

    dtlsSendPacket(&lwm2m->dtls, buf, index);
}

void lwm2mParsePacket(Lwm2m *lwm2m, uint8 *buf, int len){
    int index = 0;
    uint8 type = (buf[index++] >> 4) & 0x03;
    uint8 code = buf[index++];
    if (type == CoapTypeAcknowledgement){
        index += 10;
        if (code == CoapCodeCreated){
            // Registered
            CoapOptions options;
            index += coapParseOptions(&buf[index], len - index, &options);
            strcpy((char *)lwm2m->location, &options.locations[1][0]);
            char text[64];
            sprintf(text, "Registerd location is %s", (char *)lwm2m->location);
            logText(text);
            lwm2m->registered = true;
            lwm2m->updatedTimestamp = getNowMilliseconds();
        } else if (code == CoapCodeChanged) {
            // Updated
            if (lwm2m->bootstraped){
                logText("Updated");
                lwm2m->updatedTimestamp = getNowMilliseconds();
            } else {
                // bootstrap Request ACK
            }
        } else if (code == CoapCodeNotFound) {
            logText("Not Found");
            lwm2m->registered = false;
        }
    } else if (type == CoapTypeConfirmable) {
        lwm2m->coap.ackMessageID = getUint16FromBytes(&buf[index]);
        index += 2;
        memcpy(&lwm2m->coap.ackToken[0], &buf[index], 8);
        index += 8;
        if (code == CoapCodeGet){
            // READ
            lwm2mReadRequest(lwm2m, &buf[index], len - index);
        } else if (code == CoapCodePut){
            // WRITE
            lwm2mWriteRequest(lwm2m, &buf[index], len - index);
        } else if (code == CoapCodePost) {
            if (lwm2m->bootstraped){
                // EXECUTE
                lwm2mExecuteRequest(lwm2m, &buf[index], len - index);
            } else {
                lwm2mBootstrapFinishRequest(lwm2m, &buf[index], len - index);
            }
        } else if (code == CoapCodeDelete) {
            // DELETE
            lwm2mDeleteRequest(lwm2m, &buf[index], len - index);
        }
    } else if (type == CoapTypeReset) {
        // RESET
    }
}

// 一定時間内に受信が無ければエラーとする受信
void lwm2mReceivePacketWithTimeoutError(Lwm2m *lwm2m, uint16 timeout){
    uint8 recvBuf[UDP_RECV_BUF_LENGTH];
    int recvLen = dtlsRecvPacket(&lwm2m->dtls, recvBuf, 1000);
    if (recvLen < 0){
        lwm2m->registered = false;
    } else if (recvLen == 0) {
        logText("Timeout");
        lwm2m->dtls.verified = false;
        lwm2m->registered = false;
    } else {
        lwm2mParsePacket(lwm2m, recvBuf, recvLen);
    }
}
