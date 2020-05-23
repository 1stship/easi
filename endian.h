#ifndef _ENDIAN_H
#define _ENDIAN_H

#include "type.h"

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

#endif
