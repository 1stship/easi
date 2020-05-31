#include "easi.h"

void logText(char *log);
uint32 getNowMilliseconds();

uint32 getNowMilliseconds(){
    return millis();
}

void logText(char *log){
#ifdef EASI_WIO_LTE
    SerialUSB.println(log);
#endif
#ifdef EASI_M5_STACK
    Serial.println(log);
#endif
}
