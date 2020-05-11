#include "easi.h"

void sha256(const uint8 *input, size_t len, const uint8 *output);
void hmacSha256(const uint8 *secret, int secretLen, const uint8 *message, int messageLen, const uint8 *output);
void sha256Transform(const uint32 *data);
void sha256End(const uint8 digest[32]);
void sha256Update(const uint8 *data, size_t len);
void sha256(const uint8 *input, size_t len, const uint8 *output);

const static uint32 K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

const static uint32 initialValue[8] = {
    0x6a09e667UL,
    0xbb67ae85UL,
    0x3c6ef372UL,
    0xa54ff53aUL,
    0x510e527fUL,
    0x9b05688cUL,
    0x1f83d9abUL,
    0x5be0cd19UL
};

const static int BLOCK_LENGTH = 64;
const static int DIGEST_LENGTH = 32;
const static int SHORT_BLOCK_LENGTH = BLOCK_LENGTH - 8;
static uint32 state[8];
static uint64 bitcount;
static uint8 buffer[BLOCK_LENGTH];

void sha256Init(){
    memcpy(state, initialValue, 32);
    memset(buffer, 0, BLOCK_LENGTH);
    bitcount = 0;
}

void sha256Transform(const uint32 *data) {
    uint32 calc[8];
    uint32 s0, s1;
    uint32 T1, T2, *W256;

    W256 = (uint32 *)buffer;
    memcpy(calc, state, 32);

    for (int i = 0; i < 16; i++) {
        W256[i] = getReverseUint32(*data++);
        T1 = calc[7]
            + (((calc[4] >> 6) | (calc[4] << (32 - 6))) ^ ((calc[4] >> 11) | (calc[4] << (32 - 11))) ^ ((calc[4] >> 25) | (calc[4] << (32 - 25))))
            + ((calc[4] & calc[5]) ^ (~calc[4] & calc[6]))
            + K256[i]
            + W256[i];

        T2 = (((calc[0] >> 2) | (calc[0] << (32 - 2))) ^ ((calc[0] >> 13) | (calc[0] << (32 - 13))) ^ ((calc[0] >> 22) | (calc[0] << (32 - 22))))
            + ((calc[0] & calc[1]) ^ (calc[0] & calc[2]) ^ (calc[1] & calc[2]));

        memmove(&calc[1], &calc[0], 28);
        calc[4] += T1;
        calc[0] = T1 + T2;
    }

    for (int i = 16; i < 64; i++) {
        s0 = W256[(i + 1) & 0x0f];
        s0 = ((s0 >> 7) | (s0 << (32 - 7))) ^ ((s0 >> 18) | (s0 << (32 - 18))) ^ (s0 >> 3);
        s1 = W256[(i + 14) & 0x0f]; 
        s1 = ((s1 >> 17) | (s1 << (32 - 17))) ^ ((s1 >> 19) | (s1 << (32 - 19))) ^ (s1 >> 10);
        W256[i & 0x0f] += s1 + W256[(i + 9) & 0x0f] + s0;

        T1 = calc[7]
            + (((calc[4] >> 6) | (calc[4] << (32 - 6))) ^ ((calc[4] >> 11) | (calc[4] << (32 - 11))) ^ ((calc[4] >> 25) | (calc[4] << (32 - 25))))
            + ((calc[4] & calc[5]) ^ (~calc[4] & calc[6]))
            + K256[i]
            + W256[i & 0x0f];

        T2 = (((calc[0] >> 2) | (calc[0] << (32 - 2))) ^ ((calc[0] >> 13) | (calc[0] << (32 - 13))) ^ ((calc[0] >> 22) | (calc[0] << (32 - 22))))
            + ((calc[0] & calc[1]) ^ (calc[0] & calc[2]) ^ (calc[1] & calc[2]));
                memmove(&calc[1], &calc[0], 28);

        calc[4] += T1;
        calc[0] = T1 + T2;
    }

    for (int i = 0; i < 8; i++){
        state[i] += calc[i];
    }
}

void sha256Update(const uint8 *data, size_t len){
    uint32 freespace, usedspace;
    usedspace = (bitcount >> 3) % BLOCK_LENGTH;
    if (usedspace > 0) {
        freespace = BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            memcpy((void *)&buffer[usedspace], data, freespace);
            bitcount += freespace << 3;
            len -= freespace;
            data += freespace;
            sha256Transform((uint32 *)buffer);
        } else {
            memcpy((void *)&buffer[usedspace], data, len);
            bitcount += len << 3;
            return;
        }
    }

    while (len >= BLOCK_LENGTH) {
        sha256Transform((uint32 *)data);
        bitcount += BLOCK_LENGTH << 3;
        len -= BLOCK_LENGTH;
        data += BLOCK_LENGTH;
    }

    if (len > 0) {
        memcpy(buffer, data, len);
        bitcount += len << 3;
    }
}

void sha256End(const uint8 digest[32]) {
    uint32 *d = (uint32 *)digest;
    uint32 usedspace;

    if (digest != (uint8 *)0) {
        usedspace = (bitcount >> 3) % BLOCK_LENGTH;
        bitcount = getReverseUint64(bitcount);

        if (usedspace > 0) {
            buffer[usedspace++] = 0x80;

            if (usedspace <= SHORT_BLOCK_LENGTH) {
                memset(&buffer[usedspace], 0, SHORT_BLOCK_LENGTH - usedspace);
            } else {
                if (usedspace < BLOCK_LENGTH) {
                    memset((void *)&buffer[usedspace], 0, BLOCK_LENGTH - usedspace);
                }
                sha256Transform((uint32 *)buffer);
                memset(buffer, 0, SHORT_BLOCK_LENGTH);
            }
        } else {
            memset(buffer, 0, SHORT_BLOCK_LENGTH);
            *buffer = 0x80;
        }
        *(uint64 *)&buffer[SHORT_BLOCK_LENGTH] = bitcount;

        sha256Transform((uint32 *)buffer);

        for (int i = 0; i < 8; i++) {
            state[i] = getReverseUint32(state[i]);
            *d++ = state[i];
        }
    }
}

void sha256(const uint8 *input, size_t len, const uint8 *output){
    sha256Init();
    sha256Update(input, len);
    sha256End(output);
}

void hmacSha256(const uint8 *secret, int secretLen, const uint8 *message, int messageLen, const uint8 *output){
    uint8 secretBuf[64];
    memset(secretBuf, 0, 64);
    memcpy(secretBuf, secret, secretLen);
    uint8 secretIPad[64];
    uint8 secretOPad[64];
    for (int i = 0; i < 64; i++){
        secretIPad[i] = secretBuf[i] ^ 0x36;
        secretOPad[i] = secretBuf[i] ^ 0x5c;
    }
    uint8 secretMessage[64 + messageLen];
    memcpy(secretMessage, secretIPad, 64);
    memcpy(&secretMessage[64], message, messageLen);
    uint8 secretIPadHash[32];
    sha256(secretMessage, 64 + messageLen, secretIPadHash);
    uint8 secretJoined[96];
    memcpy(secretJoined, secretOPad, 64);
    memcpy(&secretJoined[64], secretIPadHash, 32);
    sha256(secretJoined, 96, output);
}
