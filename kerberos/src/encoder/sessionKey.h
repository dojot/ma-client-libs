#ifndef SESSION_KEY_
#define SESSION_KEY_

#include "constants.h"
#include "errno.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	uint8_t keyLength;
	uint8_t ivLength;
	uint8_t *keyCS;
	uint8_t *ivCS;
	uint8_t *keySC;
	uint8_t *ivSC;
} SessionKeys;

errno_t encodeSessionKeys(SessionKeys* /* sk */, uint8_t* /* keyCS */, uint8_t* /* ivCS */, uint8_t* /* keySC */, uint8_t* /* ivSC */,
				uint8_t /* keyLength */, uint8_t /* ivLength */);

errno_t getEncodedSessionKeys(SessionKeys* /* sk */, uint8_t** /* encodedOutput */, size_t* /* encodedLength */);

errno_t setEncodedSessionKeys(SessionKeys* /* sk */, uint8_t* /* encodedInput */, size_t /* encodedLength */, size_t* /* offset */);

errno_t decodeSessionKeys(SessionKeys* /* sk */, uint8_t** /* keyCS */, uint8_t** /* ivCS */, uint8_t** /* keySC */, uint8_t** /* ivSC */, 					uint8_t* /* keyLength */, uint8_t* /* ivLength */);

errno_t checkSessionKeys(SessionKeys* /* sk */);

errno_t eraseSessionKeys(SessionKeys* /* sk */);

errno_t copySessionKeys(SessionKeys* /* src */, SessionKeys* /* dst */);
#endif /* SESSION_KEY_ */
