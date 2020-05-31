#include "easi.h"

bool startHandshake(Dtls *dtls, char *identity, uint8 *psk);
bool dtlsSendPacket(Dtls *dtls, uint8 *data, uint16 len);
int dtlsRecvPacket(Dtls *dtls, uint8 *output, uint16 timeout);
void initDtls(Dtls *dtls, char *identity, uint8 *psk);
void setClientRandom(DtlsHandshake *handshake);
void dtlsPrf(uint8 *secret, int secretLen, uint8 *label, int labelLen, uint8 *seed, int seedLen, uint8 *output, int outputLen);
int generateHandshakeHeader(Dtls *dtls, uint8 type, uint16 len, uint8 *packet);
int generateDTLSHeader(Dtls *dtls, uint8 type, uint16 len, uint8 *packet);
void generateSecurityParams(Dtls *dtls);
void generateAad(uint8 *epochSequence, uint8 type, uint16 len, uint8 *aad);
void generateMAC(uint8 *key, uint8 *nonce, uint8 *epochSequence, uint8 type, uint8 *paddedData, uint16 len, uint16 paddedLen, uint8 *mac);
void dtlsEncrypt(Dtls *dtls, uint8 *plain, uint16 plainLen, uint8 type, uint8 *output);
bool dtlsDecrypt(Dtls *dtls, uint8 *encrypted, uint16 encryptedLen, uint8 type, uint8 *output);
bool sendFinished(Dtls *dtls);
bool sendChangeCipherSpec(Dtls *dtls);
bool sendClientKeyExchange(Dtls *dtls);
bool getSession(Dtls *dtls);
bool getCookie(Dtls *dtls);

const static uint16 DTLSVersion12 = 0xfefd;
const static uint16 CipherSuiteCCM8 = 0xc0a8;
const static uint8 DTLSCompressNone = 0x00;

const static int DTLSHeaderLength = 13;
const static int HandshakeHeaderLength = 12;

const static uint8 ContentTypeChangeCipherSpec = 20;
const static uint8 ContentTypeHandshake = 22;
const static uint8 ContentTypeApplicationData = 23;

const static uint8 HandshakeTypeClientHello = 1;
const static uint8 HandshakeTypeClientKeyExchange = 16;
const static uint8 HandshakeTypeFinished = 20;

const static char MasterSecretLabel[] = "master secret";
const static char KeyExpansionLabel[] = "key expansion";
const static char ClientFinishedLabel[] = "client finished";
const static char ServerFinishedLabel[] = "server finished";

void initDtls(Dtls *dtls, char *identity, uint8 *psk){
  dtls->serverEpoch = 0;
  dtls->clientEpoch = 0;
  dtls->serverSequence = 0;
  dtls->clientSequence = 0;
  memset(dtls->serverWriteKey, 0, 16);
  memset(dtls->clientWriteKey, 0, 16);
  memset(dtls->serverIV, 0, 4);
  memset(dtls->clientIV, 0, 4);
  dtls->clientEncrypt = 0;
  dtls->serverEncrypt = 0;
  
  dtls->handshake.messageLen = 0;
  dtls->handshake.serverSequence = 0;
  dtls->handshake.clientSequence = 0;
  memset(dtls->handshake.identity, 0, 64);
  memcpy(dtls->handshake.identity, identity, 22);
  memset(dtls->handshake.cookie, 0, 32);
  memset(dtls->handshake.session, 0, 64);
  memset(dtls->handshake.clientRandom, 0, 64);
  memset(dtls->handshake.serverRandom, 0, 64);
  memset(dtls->handshake.preMasterSecret, 0, 64);
  dtls->handshake.preMasterSecret[0] = 0;
  dtls->handshake.preMasterSecret[1] = 16;

  memset(&dtls->handshake.preMasterSecret[2], 0, 16);
  dtls->handshake.preMasterSecret[18] = 0;
  dtls->handshake.preMasterSecret[19] = 16;
  memcpy(&dtls->handshake.preMasterSecret[20], psk, 16);

  memset(dtls->handshake.masterSecret, 0, 64);
  memset(dtls->handshake.messages, 0, 1024);
  dtls->verified = false;

  udpInit(&dtls->udp, "jp.inventory.soracom.io", 5684);
}

void setClientRandom(DtlsHandshake *handshake){
    memset(handshake->clientRandom, 0, 4);
    for (int i = 4; i < 32; i++){
        handshake->clientRandom[i] = (uint8)random(255);
    }
}

void dtlsPrf(uint8 *secret, int secretLen, uint8 *label, int labelLen, uint8 *seed, int seedLen, uint8 *output, int outputLen) {
    int labelSeedLen = labelLen + seedLen;
    uint8 labelSeed[labelSeedLen];
    memcpy(&labelSeed[0], label, labelLen);
    memcpy(&labelSeed[labelLen], seed, seedLen);

    uint8 a[256];
    memcpy(&a[0], &labelSeed[0], labelSeedLen);
    int hashLen = labelSeedLen;
    uint8 message[32 + labelSeedLen];
    int index = 0;

    while (index < outputLen){
        hmacSha256(secret, secretLen, a, hashLen, a);
        hashLen = 32;
        memcpy(&message[0], a, 32);
        memcpy(&message[32], labelSeed, labelSeedLen);
        hmacSha256(secret, secretLen, message, 32 + labelSeedLen, message);
        if (index + 32 >= outputLen){
            memcpy(&output[index], message, outputLen - index);
            index = outputLen;
            break;
        }
        memcpy(&output[index], message, 32);
        index += 32;
    }
}

void generateSecurityParams(Dtls *dtls){
    unsigned char masterSecretSeed[64];
    memcpy(&masterSecretSeed[0], dtls->handshake.clientRandom, 32);
    memcpy(&masterSecretSeed[32], dtls->handshake.serverRandom, 32);
    dtlsPrf(
        dtls->handshake.preMasterSecret, 36,
        (uint8 *)MasterSecretLabel, strlen(MasterSecretLabel),
        masterSecretSeed, 64,
        dtls->handshake.masterSecret, 48);
    
    unsigned char keyExpansionSeed[64];
    memcpy(&keyExpansionSeed[0], dtls->handshake.serverRandom, 32);
    memcpy(&keyExpansionSeed[32], dtls->handshake.clientRandom, 32);
    unsigned char keyBlock[40];
    dtlsPrf(
        dtls->handshake.masterSecret, 48,
        (uint8 *)KeyExpansionLabel, strlen(KeyExpansionLabel),
        keyExpansionSeed, 64,
        keyBlock, 40);
    
    memcpy(dtls->clientWriteKey, &keyBlock[0], 16);
    memcpy(dtls->serverWriteKey, &keyBlock[16], 16);
    memcpy(dtls->clientIV, &keyBlock[32], 4);
    memcpy(dtls->serverIV, &keyBlock[36], 4);
}

void generateAad(uint8 *epochSequence, uint8 type, uint16 len, uint8 *aad){
    memcpy(&aad[0], &epochSequence[0], 8);
    aad[8] = type;
    putUint16ToBytes(DTLSVersion12, &aad[9]); // Version = DTLS1.2(0xfefd)
    putUint16ToBytes(len, &aad[11]);
}

void generateMAC(uint8 *key, uint8 *nonce, uint8 *epochSequence, uint8 type, uint8 *paddedData, uint16 len, uint16 paddedLen, uint8 *mac){
    uint8 aad[13];
    generateAad(epochSequence, type, len, aad);

    uint8 flag = 90; // (1 << 6) + (((dtlsAesCcmMACLength)-2)/2)<<3 + ((dtlsAesCCMLength) - 1) 
    uint8 blockForMAC[32 + paddedLen];
    memset(blockForMAC, 0, 32);
    blockForMAC[0] = flag;
    memcpy(&blockForMAC[1], nonce, 12);
    putUint24ToBytes((uint32)len, &blockForMAC[13]);
    putUint16ToBytes(13, &blockForMAC[16]); // aad length = 13
    memcpy(&blockForMAC[18], aad, 13);
    memcpy(&blockForMAC[32], paddedData, paddedLen);
    cbcMAC(key, blockForMAC, paddedLen, mac);
}

void dtlsEncrypt(Dtls *dtls, uint8 *plain, uint16 plainLen, uint8 type, uint8 *output){
    uint8 epochSequence[8];
    putUint16ToBytes(dtls->clientEpoch, &epochSequence[0]);
    putUint48ToBytes(dtls->clientSequence, &epochSequence[2]);

    uint8 nonce[12];
    memcpy(&nonce[0], dtls->clientIV, 4);
    memcpy(&nonce[4], epochSequence, 8);

    uint8 paddingLength = 0;
    if ((plainLen & 0x000F) > 0){
        paddingLength = 16 - (plainLen & 0x000F);
    }
    uint8 paddedData[plainLen + paddingLength];
    memcpy(&paddedData[0], plain, plainLen);
    if (paddingLength > 0){
        memset(&paddedData[plainLen], 0, paddingLength);
    }
    uint16 paddedLen = plainLen + paddingLength;

    uint8 plainMAC[16];
    generateMAC(dtls->clientWriteKey, nonce, epochSequence, type, paddedData, plainLen, paddedLen, plainMAC);
    uint8 plainText[16 + paddedLen];
    memcpy(&plainText[0], plainMAC, 16);
    memcpy(&plainText[16], paddedData, paddedLen);

    uint8 cipherText[16 + paddedLen];
    ctrEncrypt(dtls->clientWriteKey, nonce, paddedLen, plainText, cipherText);

    memcpy(&output[0], epochSequence, 8);
    memcpy(&output[8], &cipherText[16], plainLen);
    memcpy(&output[8 + plainLen], &cipherText[0], 8);
}

bool dtlsDecrypt(Dtls *dtls, uint8 *encrypted, uint16 encryptedLen, uint8 type, uint8 *output){
    uint8 epochSequence[8];
    memcpy(epochSequence, &encrypted[0], 8);
    uint16 encryptedDataLen = encryptedLen - 16;
    uint8 encryptedData[encryptedDataLen];
    memcpy(encryptedData, &encrypted[8], encryptedDataLen);
    uint encryptedMAC[8];
    memcpy(encryptedMAC, &encrypted[encryptedLen - 8], 8);

    uint8 paddingLength = 0;
    if ((encryptedDataLen & 0x000F) > 0){
        paddingLength = 16 - (encryptedDataLen & 0x000F);
    }
    uint16 paddedLen = encryptedDataLen + paddingLength;
    uint8 paddedData[paddedLen];
    memcpy(&paddedData[0], encryptedData, encryptedDataLen);
    if (paddingLength > 0){
        memset(&paddedData[encryptedDataLen], 0, paddingLength);
    }

    uint8 nonce[12];
    memcpy(&nonce[0], dtls->serverIV, 4);
    memcpy(&nonce[4], epochSequence, 8);

    uint8 cipherText[16 + encryptedDataLen + paddingLength];
    memcpy(&cipherText[0], &encryptedMAC[0], 8);
    memset(&cipherText[8], 0, 8);
    memcpy(&cipherText[16], &paddedData[0], encryptedDataLen + paddingLength);

    uint8 plainText[16 + paddedLen];
    ctrEncrypt(dtls->serverWriteKey, nonce, paddedLen, cipherText, plainText);

    uint8 plainMAC[8];
    memcpy(&plainMAC[0], &plainText[0], 8);

    uint8 calculatedMAC[16];
    uint8 plain[paddedLen];
    memcpy(&plain[0], &plainText[16], encryptedDataLen);
    if (paddingLength > 0){
        memset(&plain[encryptedDataLen], 0, paddingLength);
    }
    generateMAC(dtls->serverWriteKey, nonce, epochSequence, type, plain, encryptedDataLen, paddedLen, calculatedMAC);
    
    if (memcmp(&plainMAC[0], &calculatedMAC[0], 8) == 0){
        memcpy(&output[0], &plain[0], encryptedDataLen);
        return 1;
    } else {
        return 0;
    }
}

int generateDTLSHeader(Dtls *dtls, uint8 type, uint16 len, uint8 *packet){
    uint16 index = 0;
    packet[index++] = type;
    index += putUint16ToBytes(DTLSVersion12, &packet[index]); // Version = DTLS1.2(0xfefd)
    index += putUint16ToBytes(dtls->clientEpoch, &packet[index]);
    index += putUint48ToBytes(dtls->clientSequence, &packet[index]);
    index += putUint16ToBytes(len, &packet[index]);
    return index;
}

int generateHandshakeHeader(Dtls *dtls, uint8 type, uint16 len, uint8 *packet){
    uint16 index = 0;
    packet[index++] = type;
    index += putUint24ToBytes(len, &packet[index]); // fragment length
    index += putUint16ToBytes(dtls->handshake.clientSequence, &packet[index]);
    index += putUint24ToBytes(0, &packet[index]); // fragment offset = 0
    index += putUint24ToBytes(len, &packet[index]); // fragment length
    return index;
}

bool getCookie(Dtls *dtls){
    uint8 packet[67];
    uint16 index = 0;

    index += generateDTLSHeader(dtls, ContentTypeHandshake, 54, &packet[index]);
    index += generateHandshakeHeader(dtls, HandshakeTypeClientHello, 42, &packet[index]);

    // Client Hello Content
    index += putUint16ToBytes(DTLSVersion12, &packet[index]); // Version = DTLS1.2(0xfefd)
    memcpy(&packet[index], dtls->handshake.clientRandom, 32);
    index += 32;
    packet[index++] = 0; // Session length = 0
    packet[index++] = 0; // Cookie length = 0
    index += putUint16ToBytes(2, &packet[index]); // CipherSuite length = 2
    index += putUint16ToBytes(CipherSuiteCCM8, &packet[index]); // CipherSuite is TLS_PSK_WITH_AES_128_CCM_8(0xc0a8)
    packet[index++] = 1; // Compress length = 1
    packet[index++] = DTLSCompressNone; // Compress is None(0)

    // Send Client Hello without cookie
    udpSend(&dtls->udp, packet, index);
    dtls->clientSequence++;
    dtls->handshake.clientSequence++;

    // Receive Hello Verify Request
    uint8 readBuf[UDP_RECV_BUF_LENGTH];
    int readLen = udpRecv(&dtls->udp, readBuf, sizeof(readBuf), 1000);
    if (readLen == 0){ // Timeout
        return false;
    } else {
        // Parse Hello Verify Request
        memcpy(dtls->handshake.cookie, &readBuf[DTLSHeaderLength + HandshakeHeaderLength + 3], 32);
        return true;
    }
}

bool getSession(Dtls *dtls){
    uint8 packet[99];
    uint16 index = 0;

    index += generateDTLSHeader(dtls, ContentTypeHandshake, 86, &packet[index]);
    index += generateHandshakeHeader(dtls, HandshakeTypeClientHello, 74, &packet[index]);

    // Client Hello Content
    index += putUint16ToBytes(DTLSVersion12, &packet[index]); // Version = DTLS1.2(0xfefd)
    memcpy(&packet[index], dtls->handshake.clientRandom, 32);
    index += 32;
    packet[index++] = 0; // Session length = 0
    packet[index++] = 32; // Cookie length = 32
    memcpy(&packet[index], dtls->handshake.cookie, 32);
    index += 32;
    index += putUint16ToBytes(2, &packet[index]); // CipherSuite length = 2
    index += putUint16ToBytes(CipherSuiteCCM8, &packet[index]); // CipherSuite is TLS_PSK_WITH_AES_128_CCM_8(0xc0a8)
    packet[index++] = 1; // Compress length = 1
    packet[index++] = DTLSCompressNone; // Compress is None(0)

    // Send Client Hello with cookie
    udpSend(&dtls->udp, packet, index);
    memcpy(&dtls->handshake.messages[dtls->handshake.messageLen], &packet[DTLSHeaderLength], 86);
    dtls->handshake.messageLen += 86;
    dtls->clientSequence++;
    dtls->handshake.clientSequence++;

    // Receive Server Hello, Server Hello Done
    uint8 readBuf[UDP_RECV_BUF_LENGTH];
    int readLen = udpRecv(&dtls->udp, readBuf, sizeof(readBuf), 1000);
    if (readLen == 0){ // Timeout
        return false;
    } else {
        // Parse Server Hello
        memcpy(dtls->handshake.serverRandom, &readBuf[27], 32);
        memcpy(dtls->handshake.session, &readBuf[60], 32);
        uint16 packetLenServerHello = getUint16FromBytes(&readBuf[11]);
        memcpy(&dtls->handshake.messages[dtls->handshake.messageLen], &readBuf[13], packetLenServerHello);
        dtls->handshake.messageLen += packetLenServerHello;

        // Parse Server Hello Done
        uint16 packetLenServerHelloDone = getUint16FromBytes(&readBuf[13 + packetLenServerHello + 11]);
        memcpy(&dtls->handshake.messages[dtls->handshake.messageLen], &readBuf[13 + packetLenServerHello + 13], packetLenServerHelloDone);
        dtls->handshake.messageLen += packetLenServerHelloDone;
        return true;
    }
}

bool sendClientKeyExchange(Dtls *dtls){
    uint8 packet[49];
    uint16 index = 0;

    index += generateDTLSHeader(dtls, ContentTypeHandshake, 36, &packet[index]);
    index += generateHandshakeHeader(dtls, HandshakeTypeClientKeyExchange, 24, &packet[index]);

    // Client Key Exchange Content
    index += putUint16ToBytes(22, &packet[index]); // Identity length = 22
    memcpy(&packet[index], dtls->handshake.identity, 22);
    index += 22;

    // Send Client Key Exchange
    udpSend(&dtls->udp, packet, index);
    memcpy(&dtls->handshake.messages[dtls->handshake.messageLen], &packet[13], 36);
    dtls->handshake.messageLen += 36;
    dtls->clientSequence++;
    dtls->handshake.clientSequence++;

  return true;
}

bool sendChangeCipherSpec(Dtls *dtls){
    uint8 packet[14];
    uint16 index = 0;

    index += generateDTLSHeader(dtls, ContentTypeChangeCipherSpec, 1, &packet[index]);

    // Change Cipher Spec Content
    packet[index++] = 1; // Change CipherSpec Message = 1

    // Send Change Cipher Spec
    udpSend(&dtls->udp, packet, index);
    dtls->clientEpoch++;
    dtls->clientSequence = 0;
    dtls->clientEncrypt = 1;

  return true;
}

bool sendFinished(Dtls *dtls){
    uint8 packet[53];
    uint16 index = 0;
    index += generateDTLSHeader(dtls, ContentTypeHandshake, 40, &packet[index]);

    uint8 plain[24];
    uint16 plainIndex = 0;
    plainIndex += generateHandshakeHeader(dtls, HandshakeTypeFinished, 12, &plain[plainIndex]);

    // Finished Content
    uint8 messageHash[32];
    sha256(dtls->handshake.messages, dtls->handshake.messageLen, messageHash);
    dtlsPrf(
        dtls->handshake.masterSecret, 48,
        (uint8 *)ClientFinishedLabel, strlen(ClientFinishedLabel),
        messageHash, 32,
        &plain[12], 12);
    plainIndex += 12;

    // encrypt Finished
    dtlsEncrypt(dtls, plain, 24, 22, &packet[index]);
    index += plainIndex + 16;

    // Send encrypted Finished
    udpSend(&dtls->udp, packet, index);
    memcpy(&dtls->handshake.messages[dtls->handshake.messageLen], &plain[0], 24);
    dtls->handshake.messageLen += 24;
    dtls->clientSequence++;
    dtls->handshake.clientSequence++;

    // Receive Change Cipher Spec, encrypted Finished
    uint8 readBuf[UDP_RECV_BUF_LENGTH];
    int readLen = udpRecv(&dtls->udp, readBuf, sizeof(readBuf), 1000);
    if (readLen == 0){ // Timeout
        return false;
    }

    // Parse Change Cipher Spec
    uint16 packetLenChangeCipherSpec = getUint16FromBytes(&readBuf[11]);
    dtls->serverEncrypt = 1;

    // Parse encrypted Finished
    uint16 packetLenServerVerified = getUint16FromBytes(&readBuf[13 + packetLenChangeCipherSpec + 11]);
    uint8 encryptedVerified[packetLenServerVerified];
    memcpy(&encryptedVerified[0], &readBuf[13 + packetLenChangeCipherSpec + 13], packetLenServerVerified);
    uint8 verifiedPacket[packetLenServerVerified - 16];

    // Verify Data
    if (dtlsDecrypt(dtls, &encryptedVerified[0], packetLenServerVerified, 22, &verifiedPacket[0])){
        uint8 serverVerify[12];
        uint8 serverMessageHash[32];
        sha256(dtls->handshake.messages, dtls->handshake.messageLen, serverMessageHash);
        dtlsPrf(
            dtls->handshake.masterSecret, 48,
            (uint8 *)ServerFinishedLabel, strlen(ServerFinishedLabel),
            serverMessageHash, 32,
            &serverVerify[0], 12);
        if (memcmp(&verifiedPacket[12], &serverVerify[0], 12) == 0){
            // VERIFY OK
            return true;
        } else {
            // VERIFY NG
            return false;
        }
    } else {
        // DECRYPT NG
        return false;
    }
}

bool startHandshake(Dtls *dtls, char *identity, uint8 *psk){
    initDtls(dtls, identity, psk);
    setClientRandom(&dtls->handshake);
    udpClearBuffer(&dtls->udp);
    if (!getCookie(dtls)){
        dtls->verified = false;
        return false;
    }
    if (!getSession(dtls)){
        dtls->verified = false;
        return false;
    }
    sendClientKeyExchange(dtls);
    sendChangeCipherSpec(dtls);
    generateSecurityParams(dtls);
    if (sendFinished(dtls)){
        logText("Handshake VERIFIED");
        dtls->verified = true;
        return true;
    } else {
        logText("Handshake INVALID");
        dtls->verified = false;
        return false;
    }
}

bool dtlsSendPacket(Dtls *dtls, uint8 *data, uint16 len){
    uint16 encryptedLen = len + 16;
    uint16 packetLen = encryptedLen + DTLSHeaderLength;
    uint8 packet[packetLen];
    uint16 index = 0;
    index += generateDTLSHeader(dtls, ContentTypeApplicationData, encryptedLen, &packet[index]);
    dtlsEncrypt(dtls, data, len, 23, &packet[index]);
    udpSend(&dtls->udp, packet, encryptedLen + DTLSHeaderLength);
    dtls->clientSequence++;
    return true;
}

int dtlsRecvPacket(Dtls *dtls, uint8 *output, uint16 timeout){
    uint8 buf[UDP_RECV_BUF_LENGTH];
    int readLen = udpRecv(&dtls->udp, buf, sizeof(buf), timeout);
    if (readLen == 0){
        // timeout
        return 0;
    }

    if (dtlsDecrypt(dtls, &buf[13], readLen - 13, 23, output)){
        return readLen - 13 - 16;
    } else {
        logText("INVALID Packet!");
        dtls->verified = false;
        return -1;
    }
}
