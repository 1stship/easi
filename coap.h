#ifndef _COAP_H
#define _COAP_H

#include "type.h"

// RFC7252 3. Message Format Type(T)参照
enum CoapType {
    CoapTypeConfirmable = 0,
    CoapTypeNonConfirmable,
    CoapTypeAcknowledgement,
    CoapTypeReset
};

// RFC7252 12.1.1 Method Codes, 12.1.2 Response Codes参照
enum CoapCode {
    CoapCodeEmpty = 0,
    CoapCodeGet,
    CoapCodePost,
    CoapCodePut,
    CoapCodeDelete,
    CoapCodeOK = 64,          // 2.00 OK
    CoapCodeCreated,          // 2.01 Created
    CoapCodeDeleted,          // 2.02 Deleted
    CoapCodeValid,            // 2.03 Valid
    CoapCodeChanged,          // 2.04 Changed
    CoapCodeContent,          // 2.05 Content
    CoapCodeBadRequest = 128, // 4.00 Bad Request
    CoapCodeUnauthorized,     // 4.01 Unauthorized
    CoapCodeBadOption,        // 4.02 Bad Option
    CoapCodeForbidden,        // 4.03 Forbidden
    CoapCodeNotFound,         // 4.04 Not Found
    CoapCodeMethodNotAllowed, // 4.05 Method Not Allowed
    CoapCodeNotAcceptable,    // 4.06 Not Acceptable
};

enum CoapOptionNo {
    CoapOptionNoObserve = 6,
    CoapOptionNoLocationPath = 8,
    CoapOptionNoURIPath = 11,
    CoapOptionNoContentFormat = 12,
    CoapOptionNoURIQuery = 15
};

typedef struct {
    uint16 nextMessageID;
    uint16 ackMessageID;
    uint8 ackToken[8];
} Coap;

typedef struct {
    char paths[3][16];
    int pathLen;
    char locations[2][16];
    int locationLen;
    uint16 format;
    char queryKey[4][16];
    char queryValue[4][64];
    int queryLen;
} CoapOptions;

void coapPrepare(Coap *coap);
int coapCreateRequestHeader(Coap *coap, enum CoapType type, enum CoapCode code, uint8 *output);
int coapCreateResponseHeader(Coap *coap, enum CoapType type, enum CoapCode code, uint8 *output);
void coapInitOptions(CoapOptions *options);
uint16 coapSetOptions(CoapOptions *options, uint8 *output);
int coapParseOptions(uint8 *input, int len, CoapOptions *options);

#endif
