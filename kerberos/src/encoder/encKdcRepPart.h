#ifndef ENC_KDC_PART_
#define ENC_KDC_PART_

#include "errno.h"
#include "constants.h"
#include "sessionKey.h"

#include <stdio.h>
#include <stdint.h>

typedef struct {
        SessionKeys sk;
        uint8_t sname[PRINCIPAL_NAME_LENGTH];
		uint8_t nonce[NONCE_LENGTH];
        uint8_t authtime[TIME_LENGTH];
        uint8_t endtime[TIME_LENGTH];
} EncKdcPart;

errno_t encodeEncKdcPart(EncKdcPart* /* encKdcPart */, SessionKeys* /* sk */, uint8_t* /* sname */, size_t /* snameLength */, 
			uint8_t* /* nonce */, size_t /* nonceLength */,	uint8_t* /* authtime */, size_t /* authtimeLength */, 
			uint8_t* /* endtime */, size_t /* endtimeLength */);

errno_t getEncodedEncKdcPart(EncKdcPart* /* encKdcPart */, uint8_t** /* encodedOutput */, size_t* /* encodedLength */);
errno_t setEncodedEncKdcPart(EncKdcPart* /* encKdcPart */, uint8_t* /* encodedInput */, size_t /* encodedLength */, size_t* /* offset */);

errno_t decodeEncKdcPart(EncKdcPart* /* encKdcPart */, SessionKeys* /* sk */, uint8_t** /* sname */, size_t* /* snameLength */,
			uint8_t** /* nonce */, size_t* /* nonceLength */, uint8_t** /* authtime */, size_t* /* authtimeLength */, 
			uint8_t** /* endtime */, size_t* /* endtimeLength */);

errno_t checkEncKdcPart(EncKdcPart* /* encKdcPart */);

errno_t eraseEncKdcPart(EncKdcPart* /* encKdcPart */);

#endif /* ENC_KDC_PART */
