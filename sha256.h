#ifndef _SHA256_H
#define _SHA256_H

#include "type.h"

void sha256(const uint8 *input, size_t len, const uint8 *output);
void hmacSha256(const uint8 *secret, int secretLen, const uint8 *message, int messageLen, const uint8 *output);

#endif
