#ifndef ERROR_
#define ERROR_

#include "constants.h"
#include "errno.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ERROR_CODE	0x1e

/* Code errors */

#define KDC_ERR_C_PRINCIPAL_UNKNOWN 6
#define KDC_ERR_S_PRINCIPAL_UNKNOWN 7
#define KRB_AP_ERR_BAD_INTEGRITY 31
#define KRB_AP_ERR_TKT_EXPIRED 32
#define KRB_AP_ERR_REPEAT 34
#define KRB_AP_ERR_BADMATCH 36
#define KRB_AP_ERR_SKEW 37
#define KRB_ERR_GENERIC 60

/* Represents an error message */
typedef struct {
	uint8_t errorCode;
} Error;

errno_t encodeError(Error* /* error */, uint8_t /* errorCode */);

errno_t getEncodedError(Error* /* error */, uint8_t** /* encodedOutput */, size_t* /* encodedLength */);

errno_t setEncodedError(Error* /* error */, uint8_t* /* encodedInput */, size_t /* encodedLength*/, size_t* /* offset */);

errno_t decodeError(Error* /* error */, uint8_t* /* errorCode */);

errno_t checkError(Error* /* error */);

errno_t eraseError(Error* /* error */);

#endif /* REQUEST_AS_ */