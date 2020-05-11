#ifndef _AES_H
#define _AES_H

#include "type.h"

void aesEncrypt(const uint8 key[16], const uint8 input[16], uint8 output[16]);
void ctrEncrypt(uint8 *key, uint8 *nonce, uint16 len, uint8 *cipherText, uint8 *plainText);
void cbcMAC(uint8 *key, uint8 *input, uint16 len, uint8 *mac);

#endif
