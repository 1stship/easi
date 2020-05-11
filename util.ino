#include "easi.h"

void logText(char *log);
uint32 getNowMilliseconds();

uint32 getNowMilliseconds(){
    return millis();
}

void logText(char *log){
    SerialUSB.println(log);
}
