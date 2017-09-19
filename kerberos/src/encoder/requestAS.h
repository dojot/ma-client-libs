#ifndef REQUEST_AS_
#define REQUEST_AS_

#include "constants.h"
#include "errno.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define REQUEST_AS_CODE	0x0a

/* Represents a request to AS */
/* Simplified model presented in HAC, Chapter 12 */

typedef struct {
	uint8_t cname[PRINCIPAL_NAME_LENGTH];
	uint8_t sname[PRINCIPAL_NAME_LENGTH];
	uint8_t nonce[NONCE_LENGTH];
} RequestAS;

errno_t encodeRequestAS(RequestAS* /* requestAs */, uint8_t* /* cname */, size_t /* cnameLength */, uint8_t* /* sname */, size_t /* snameLength */, uint8_t* /* nonce */, size_t /* nonceLength */);

errno_t getEncodedRequestAS(RequestAS* /* requestAS */, uint8_t ** /* encodedOutput */, size_t* /* encodedLength */);

errno_t setEncodedRequestAS(RequestAS* /* requestAS */, uint8_t* /* encodedInput */, size_t /* encodedLength*/, size_t* /* offset */);

errno_t decodeRequestAS(RequestAS* /* requestAs */, uint8_t** /* cname */, size_t* /* cnameLength */, uint8_t** /* sname */, size_t* /* snameLength */, uint8_t** /* nonce */, size_t* /* nonceLength */);

errno_t checkRequestAS(RequestAS* /* requestAs */);

errno_t eraseRequestAS(RequestAS* /* requestAs */);
#endif /* REQUEST_AS_ */
