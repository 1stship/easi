#include "easi.h"

#ifdef EASI_WIO_LTE
extern WioLTE wio;
#endif
#ifdef EASI_M5_STACK
extern TinyGsm modem;
#endif

bool udpInit(UDPComm *udp, char *host, int port);
int udpSend(UDPComm *udp, uint8 *buf, int len);
int udpRecv(UDPComm *udp, uint8 *buf, int len, uint16 timeout);
void udpClearBuffer(UDPComm *udp);
#ifdef EASI_M5_STACK
bool skipUntil(const char c, const uint32_t timeout_ms);
int16_t getIntBefore(char lastChar);
#endif

bool udpInit(UDPComm *udp, char *host, int port){
#ifdef EASI_WIO_LTE
    int sock = wio.SocketOpen(host, port, WIOLTE_UDP);
#endif
#ifdef EASI_M5_STACK
    modem.sendAT(GF("+USOCR=17"));
    if (modem.waitResponse(GF(GSM_NL "+USOCR:")) != 1) {
      return false;
    }
    int sock = getIntBefore('\n');
#endif

    if (sock >= 0){
        udp->sock = sock;
        strcpy(udp->host, host);
        udp->port = port;
#ifdef EASI_M5_STACK
        modem.waitResponse();
#endif
        return true;
    } else {
        return false;
    }
}

int udpSend(UDPComm *udp, uint8 *buf, int len){
#ifdef EASI_WIO_LTE
    bool ret = wio.SocketSend(udp->sock, buf, len);
    if (ret) {
        return len;
    } else {
        return 0;
    }
#endif
#ifdef EASI_M5_STACK
    modem.sendAT(GF("+USOST="), udp->sock, ",\"", udp->host, "\",", udp->port, ",", len);
    if (modem.waitResponse(GF("@")) != 1) { return 0; }
    delay(50);
    modem.stream.write(reinterpret_cast<const uint8_t*>(buf), len);
    modem.stream.flush();
    if (modem.waitResponse(GF(GSM_NL "+USOST:")) != 1) { return 0; }
    skipUntil(',', 1000);
    int16_t sent = getIntBefore('\n');
    modem.waitResponse();
    return sent;
#endif
}

int udpRecv(UDPComm *udp, uint8 *buf, int len, uint16 timeout){
#ifdef EASI_WIO_LTE
    int recvLen = wio.SocketReceive(udp->sock, buf, len, timeout);
    return recvLen;
#endif
#ifdef EASI_M5_STACK
    uint32 start = getNowMilliseconds();

    while (true){
      modem.sendAT(GF("+USORF="), udp->sock, ",", 1024);
      if (modem.waitResponse(GF(GSM_NL "+USORF:")) != 1) { return 0; }
      skipUntil(',', 1000); // skip sock
      int ret = modem.stream.read();
      if (ret == '0'){
        modem.waitResponse();
        delay(100);
        if (getNowMilliseconds() - start > timeout){
          return 0;
        }
      } else {
        break;
      }
    }

    skipUntil(',', 1000); // skip IP
    skipUntil(',', 1000); // skip port
    int16_t dataLen = getIntBefore(',');
    skipUntil('\"', 1000);
    if (len > 0){
      int readLen = modem.stream.readBytes(buf, dataLen);
    }
    skipUntil('\"', 1000);
    modem.waitResponse();

    return dataLen;
#endif
}

void udpClearBuffer(UDPComm *udp){
    char buf[UDP_RECV_BUF_LENGTH];
    while (udpRecv(udp, (uint8 *)buf, sizeof(buf), 1000) > 0) { };
}

#ifdef EASI_M5_STACK
bool skipUntil(const char c, const uint32_t timeout_ms) {
  uint32_t startMillis = millis();
  while (millis() - startMillis < timeout_ms) {
    while (millis() - startMillis < timeout_ms &&
      !modem.stream.available()) {
      TINY_GSM_YIELD();
    }
    if (modem.stream.read() == c) { return true; }
  }
  return false;
}

int16_t getIntBefore(char lastChar) {
  char   buf[7];
  size_t bytesRead = modem.stream.readBytesUntil(
      lastChar, buf, static_cast<size_t>(7));
  if (bytesRead && bytesRead < 7) {
    buf[bytesRead] = '\0';
    int16_t res    = atoi(buf);
    return res;
  } else {
    return -1;
  }
}
#endif