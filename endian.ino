#include "easi.h"

int putUint16ToBytes(uint16 input, uint8 *output);
int putUint24ToBytes(uint32 input, uint8 *output);
int putUint32ToBytes(uint32 input, uint8 *output);
int putUint48ToBytes(uint64 input, uint8 *output);
int putUint64ToBytes(uint64 input, uint8 *output);
int putFloat64ToBytes(float64 input, uint8 *output);
uint16 getUint16FromBytes(const uint8 *input);
uint32 getUint24FromBytes(const uint8 *input);
uint32 getUint32FromBytes(const uint8 *input);
uint64 getUint48FromBytes(const uint8 *input);
uint64 getUint64FromBytes(const uint8 *input);
float64 getFloat64FromBytes(const uint8 *input);
uint32 getReverseUint32(uint32 input);
uint64 getReverseUint64(uint64 input);

int putUint16ToBytes(uint16 input, uint8 *output){
    output[0] = (uint8)(input >> 8);
    output[1] = (uint8)(input >> 0);
    return 2;
}

int putUint24ToBytes(uint32 input, uint8 *output){
    output[0] = (uint8)(input >> 16);
    output[1] = (uint8)(input >> 8);
    output[2] = (uint8)(input >> 0);
    return 3;
}

int putUint32ToBytes(uint32 input, uint8 *output){
    output[0] = (uint8)(input >> 24);
    output[1] = (uint8)(input >> 16);
    output[2] = (uint8)(input >> 8);
    output[3] = (uint8)(input >> 0);
    return 4;
}

int putUint48ToBytes(uint64 input, uint8 *output){
    output[0] = (uint8)(input >> 40);
    output[1] = (uint8)(input >> 32);
    output[2] = (uint8)(input >> 24);
    output[3] = (uint8)(input >> 16);
    output[4] = (uint8)(input >> 8);
    output[5] = (uint8)(input >> 0);
    return 6;
}

int putUint64ToBytes(uint64 input, uint8 *output){
    output[0] = (uint8)(input >> 56);
    output[1] = (uint8)(input >> 48);
    output[2] = (uint8)(input >> 40);
    output[3] = (uint8)(input >> 32);
    output[4] = (uint8)(input >> 24);
    output[5] = (uint8)(input >> 16);
    output[6] = (uint8)(input >> 8);
    output[7] = (uint8)(input >> 0);
    return 8;
}

int putFloat64ToBytes(float64 input, uint8 *output){
    uint8 temp[8];
    memcpy(temp, &input, 8);
    for (int i = 0; i < 8; i++){
      output[i] = temp[7 - i];
    }
    return 8;
}

uint16 getUint16FromBytes(const uint8 *input){
    uint16 ret = 0;
    ret += ((uint16)input[0]) << 8;
    ret += ((uint16)input[1]) << 0;
    return ret;
}

uint32 getUint24FromBytes(const uint8 *input){
    uint32 ret = 0;
    ret += ((uint32)input[0]) << 16;
    ret += ((uint32)input[1]) << 8;
    ret += ((uint32)input[2]) << 0;
    return ret;
}

uint32 getUint32FromBytes(const uint8 *input){
    uint32 ret = 0;
    ret += ((uint32)input[0]) << 24;
    ret += ((uint32)input[1]) << 16;
    ret += ((uint32)input[2]) << 8;
    ret += ((uint32)input[3]) << 0;
    return ret;
}

uint64 getUint48FromBytes(const uint8 *input){
    uint64 ret = 0;
    ret += ((uint64)input[0]) << 40;
    ret += ((uint64)input[1]) << 32;
    ret += ((uint64)input[2]) << 24;
    ret += ((uint64)input[3]) << 16;
    ret += ((uint64)input[4]) << 8;
    ret += ((uint64)input[5]) << 0;
    return ret;
}

uint64 getUint64FromBytes(const uint8 *input){
    uint64 ret = 0;
    ret += ((uint64)input[0]) << 56;
    ret += ((uint64)input[1]) << 48;
    ret += ((uint64)input[2]) << 40;
    ret += ((uint64)input[3]) << 32;
    ret += ((uint64)input[4]) << 24;
    ret += ((uint64)input[5]) << 16;
    ret += ((uint64)input[6]) << 8;
    ret += ((uint64)input[7]) << 0;
    return ret;
}

float64 getFloat64FromBytes(const uint8 *input){
    float64 ret = 0.0;
    uint8 temp[8];
    for (int i = 0; i < 8; i++){
      temp[i] = input[7 - i];
    }
    memcpy(&ret, temp, 8);
    return ret;
}

uint32 getReverseUint32(uint32 input){
    uint8 bytes[4];
    putUint32ToBytes(input, bytes);
    uint32 ret = 0;
    for (int i = 3; i >= 0; i--){
        ret = (ret << 8) + bytes[i];
    }
    return ret;
}

uint64 getReverseUint64(uint64 input){
    uint8 bytes[8];
    putUint64ToBytes(input, bytes);
    uint64 ret = 0;
    for (int i = 7; i >= 0; i--){
        ret = (ret << 8) + bytes[i];
    }
    return ret;
}
