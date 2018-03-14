#ifndef AUTHENTICATOR_H_
#define AUTHENTICATOR_H_

#include "constants.h"
#include "errno.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t cname[PRINCIPAL_NAME_LENGTH];
    uint64_t ctime;
} Authenticator;

errno_t encodeAuthenticator(Authenticator* authenticator,
                            uint8_t* cname,
                            size_t cnameLength,
                            uint64_t ctime);

errno_t getEncodedAuthenticator(Authenticator* authenticator,
                                uint8_t** encodedOutput,
                                size_t* encodedLength);

errno_t setEncodedAuthenticator(Authenticator* authenticator,
                                uint8_t* encodedInput,
                                size_t encodedLength,
                                size_t* offset);

errno_t decodeAuthenticator(Authenticator* authenticator,
                            uint8_t** cname,
                            size_t* cnameLength,
                            uint64_t* ctime);

uint8_t initAuthenticator(Authenticator *authenticator);

uint8_t eraseAuthenticator(Authenticator *authenticator);

errno_t copyAuthenticator(Authenticator *src, Authenticator *dst);

#endif /* AUTHENTICATOR_H_ */
