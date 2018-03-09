#ifndef ENCRYPTED_DATA_
#define ENCRYPTED_DATA_

#include "constants.h"
#include "errno.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t ivLength;
    uint8_t ciphertextLength;
    uint8_t *iv;
    uint8_t *ciphertext;
} EncryptedData;

errno_t encodeEncData(EncryptedData* /* encryptedData */, uint8_t* /* iv */, size_t /* ivLength */, 
                uint8_t* /* ciphertext */, size_t /* ciphertextLength */);

uint8_t copyIVOnEncData(EncryptedData* encryptedData, uint8_t* iv, size_t ivLength);

errno_t getEncodedEncData(EncryptedData* /* encryptedData */, uint8_t** /* encodedOutput */, size_t* /* encodedLength */);

errno_t setEncodedEncData(EncryptedData* /* encryptedData */, uint8_t* /* encodedInput */, size_t /* encodedLength */, size_t* /* offset */);

errno_t decodeEncData(EncryptedData* /* encryptedData */, uint8_t** /* iv */, uint8_t* /* ivLength */,
                uint8_t** /* ciphertext */, uint8_t* /* ciphertextLength */);

errno_t getEncodedLengthEncData(EncryptedData* /* encryptedData */, size_t* /* encodedLength */);

errno_t checkEncData(EncryptedData* /* encryptedData */);

uint8_t eraseEncData(EncryptedData* encryptedData);

errno_t copyEncData(EncryptedData* /* src */, EncryptedData* /* dst */);

uint8_t initEncryptedData(EncryptedData *encryptedData);

void dumpEncryptedData(EncryptedData *encryptedData, uint8_t indent);
#endif /* ENCRYPTED_DATA_ */
