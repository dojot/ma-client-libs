#ifndef ENC_KDC_PART_
#define ENC_KDC_PART_

#include <stdint.h>

#include "constants.h"
#include "sessionKey.h"

typedef struct {
        SessionKeys sk;
        uint8_t sname[PRINCIPAL_NAME_LENGTH];
		uint8_t nonce[NONCE_LENGTH];
        uint64_t authtime;
        uint64_t endtime;
} EncKdcPart;

uint8_t initEncKdcPart(EncKdcPart* encKdcPart);

uint8_t eraseEncKdcPart(EncKdcPart* encKdcPart);

uint8_t setEncodedEncKdcPart(EncKdcPart* encKdcPart,
							 uint8_t* encodedInput,
							 size_t encodedLength,
							 size_t* offset);

void dumpEncKdcPart(EncKdcPart* encKdcPart, uint8_t indent);

#endif /* ENC_KDC_PART */
