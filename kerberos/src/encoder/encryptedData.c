#include "encryptedData.h"

#include "ma_comm_error_codes.h"
#include "logger/logger.h"

/* Fills the request */
errno_t encodeEncData(EncryptedData* encryptedData, uint8_t* iv, size_t ivLength, uint8_t* ciphertext, size_t ciphertextLength)
{
    errno_t result;

    /* Input validation */
    if(encryptedData == NULL || iv == NULL || ciphertext == NULL) {
        result = INVALID_PARAMETER;
        goto FAIL;
    }

    if(ivLength > IV_LENGTH || ciphertextLength == 0) {
        result = INVALID_PARAMETER;
        goto FAIL;
    }

    /* Ensure structure is clean */
    result = memset_s(encryptedData, sizeof(EncryptedData), 0, sizeof(EncryptedData));
    if(result != SUCCESSFULL_OPERATION) {
        goto FAIL;
    }

    /* Initialize the structure with the data */
    encryptedData->ivLength = ivLength;
    encryptedData->ciphertextLength = ciphertextLength;

    encryptedData->iv = (uint8_t*) malloc(sizeof(uint8_t) * ivLength);
    encryptedData->ciphertext = (uint8_t*) malloc(sizeof(uint8_t) * ciphertextLength);

    if(encryptedData->iv == NULL || encryptedData->ciphertext == NULL) {
        free(encryptedData->iv);
        free(encryptedData->ciphertext);
        result = INVALID_STATE;
        goto FAIL;
    }
    memcpy(encryptedData->iv, iv, ivLength);
    memcpy(encryptedData->ciphertext, ciphertext, ciphertextLength);

    result = checkEncData(encryptedData);
FAIL:
    return result;
}

uint8_t copyIVOnEncData(EncryptedData* encryptedData, uint8_t* iv, size_t ivLength) {

    // Input validation
    if (!encryptedData ||
        !iv ||
        encryptedData->iv ||
        encryptedData->ivLength != 0 ||
        ivLength != IV_LENGTH) {
        return MA_COMM_INVALID_PARAMETER;
    }

    encryptedData->iv = (uint8_t*) malloc(ivLength);
    if(!encryptedData->iv) {
        return MA_COMM_INVALID_STATE;
    }
    memcpy(encryptedData->iv, iv, ivLength);
    encryptedData->ivLength = ivLength;

    return MA_COMM_SUCCESS;
}


uint8_t getEncodedEncDataOnBuffer(EncryptedData* encryptedData,
                                  size_t bufferLength,
                                  uint8_t* buffer,
                                  size_t* offset) {

    uint8_t result = MA_COMM_SUCCESS;

    // Input validation
    if ( (!buffer) || (!offset) ) {
        return MA_COMM_INVALID_PARAMETER;
    }
    result = checkEncData(encryptedData);
    if(result != MA_COMM_SUCCESS) {
        return MA_COMM_INVALID_PARAMETER;
    }

    //buffer size validation
    size_t encodedLength = 0;
    result = getEncodedLengthEncData(encryptedData, &encodedLength);
    if(result != MA_COMM_SUCCESS) {
        return MA_COMM_INVALID_PARAMETER;
    }
    if (encodedLength > bufferLength) {
        return MA_COMM_INVALID_PARAMETER;
    }

    *offset = 0;
    memcpy(buffer + *offset, &encryptedData->ivLength, sizeof(encryptedData->ivLength));
    *offset += sizeof(encryptedData->ivLength);
    memcpy(buffer + *offset, &encryptedData->ciphertextLength, sizeof(encryptedData->ciphertextLength));
    *offset += sizeof(encryptedData->ciphertextLength);
    memcpy(buffer + *offset, encryptedData->iv, encryptedData->ivLength);
    *offset += encryptedData->ivLength;
    memcpy(buffer + *offset, encryptedData->ciphertext, encryptedData->ciphertextLength);
    *offset += encryptedData->ciphertextLength;

    return MA_COMM_SUCCESS;
}
/* Generate byte array from request */
errno_t getEncodedEncData(EncryptedData* encryptedData, uint8_t** encodedOutput, size_t* encodedLength)
{
    errno_t result;
    size_t offset, encDataLength;

    /* Input validation */
    result = checkEncData(encryptedData);
    if(result != SUCCESSFULL_OPERATION) {
        result = INVALID_PARAMETER;
        goto FAIL;
    }

    if(encodedOutput == NULL || encodedLength == NULL) {
        result = INVALID_PARAMETER;
        goto FAIL;
    }


    /* Calculate size */
    result = getEncodedLengthEncData(encryptedData, &encDataLength);
    if(result != SUCCESSFULL_OPERATION) {
        goto FAIL;
    }

    /* Allocate space to encoded output */
    *encodedOutput = (uint8_t*) malloc(encDataLength);
    if(*encodedOutput == NULL) {
        result = INVALID_STATE;
        goto FAIL;
    }

    /* Serializes data to encodedOutput */
    offset = 0;
    memcpy(*encodedOutput + offset, &encryptedData->ivLength, sizeof(encryptedData->ivLength));
    offset += sizeof(encryptedData->ivLength);
    memcpy(*encodedOutput + offset, &encryptedData->ciphertextLength, sizeof(encryptedData->ciphertextLength));
    offset += sizeof(encryptedData->ciphertextLength);
    memcpy(*encodedOutput + offset, encryptedData->iv, sizeof(uint8_t) * encryptedData->ivLength);
    offset += sizeof(uint8_t) * encryptedData->ivLength;
    memcpy(*encodedOutput + offset, encryptedData->ciphertext, sizeof(uint8_t) * encryptedData->ciphertextLength);
    offset += sizeof(uint8_t) * encryptedData->ciphertextLength;
    *encodedLength = offset;
    result = SUCCESSFULL_OPERATION;
FAIL:
    return result;
}

/* Generate EncryptedData from encodedInput received */
uint8_t setEncodedEncData(EncryptedData* encryptedData,
                          uint8_t* encodedInput,
                          size_t encodedLength,
                          size_t* offset) {
    errno_t result;
    size_t encodedOffset;

    /* Input validation */
    if(!encryptedData || !encodedInput || !offset) {
        return MA_COMM_INVALID_PARAMETER;
    }

    /*
     * Check if the length fields are valid:
     * encodedInput[0] == IVLength
     * encodedInput[1] == CiphertextLength
     * So IVLen + CiphertextLen == encodedLength + 2
     */
    if( (encodedLength < 2) || (encodedLength < 2 + encodedInput[0] + encodedInput[1]) ) {
        return MA_COMM_INVALID_PARAMETER;
    }

    // initialize the structure
    result = initEncryptedData(encryptedData);
    if(result != MA_COMM_SUCCESS) {
        return MA_COMM_INVALID_PARAMETER;
    }

    // Unserialization
    encodedOffset = 0;
    //iv length
    memcpy(&encryptedData->ivLength, encodedInput, sizeof(encryptedData->ivLength));
    encodedOffset += sizeof(encryptedData->ivLength);

    // cipher length
    memcpy(&encryptedData->ciphertextLength, encodedInput + encodedOffset, sizeof(encryptedData->ciphertextLength));
    encodedOffset += sizeof(encryptedData->ciphertextLength);

    // iv
    encryptedData->iv = (uint8_t*) malloc(sizeof(uint8_t) * encryptedData->ivLength);
    if(!encryptedData->iv) {
        return MA_COMM_INVALID_STATE;
    }
    memcpy(encryptedData->iv, encodedInput + encodedOffset, sizeof(uint8_t) * encryptedData->ivLength);
    encodedOffset += sizeof(uint8_t) * encryptedData->ivLength;

    // cipher text
    encryptedData->ciphertext = (uint8_t*) malloc(sizeof(uint8_t) * encryptedData->ciphertextLength);
    if(!encryptedData->ciphertext) {
        eraseEncData(encryptedData);
        return MA_COMM_INVALID_STATE;
    }
    memcpy(encryptedData->ciphertext, encodedInput + encodedOffset, sizeof(uint8_t) * encryptedData->ciphertextLength);
    encodedOffset += sizeof(uint8_t) * encryptedData->ciphertextLength;

    *offset = encodedOffset;

    return MA_COMM_SUCCESS;
}

/* Get individual fields from EncryptedData */
uint8_t decodeEncData(EncryptedData* encryptedData,
                      uint8_t** iv,
                      uint8_t* ivLength,
                      uint8_t** ciphertext,
                      uint8_t* ciphertextLength) {
    uint8_t result = MA_COMM_SUCCESS;

    // Input validation
    result = checkEncData(encryptedData);
    if(result != MA_COMM_SUCCESS) {
        return MA_COMM_INVALID_PARAMETER;
    }

    if(!iv || !ciphertext || !ivLength || !ciphertextLength) {
        return MA_COMM_INVALID_PARAMETER;
    }

    *iv = (uint8_t*) malloc(encryptedData->ivLength);
    if(!*iv) {
        return MA_COMM_OUT_OF_MEMORY;
    }
    *ciphertext = (uint8_t*) malloc(encryptedData->ciphertextLength);
    if(!*ciphertext) {
        free(*iv);
        *iv = NULL;
        return MA_COMM_OUT_OF_MEMORY;
    }
    *ivLength = encryptedData->ivLength;
    *ciphertextLength = encryptedData->ciphertextLength;

    memcpy(*iv, encryptedData->iv, encryptedData->ivLength);
    memcpy(*ciphertext, encryptedData->ciphertext, encryptedData->ciphertextLength);

    return MA_COMM_SUCCESS;
}

uint8_t checkEncData(EncryptedData *encryptedData) {

    if ( (!encryptedData) ||
         (encryptedData->ivLength != IV_LENGTH) ||
         (encryptedData->ciphertextLength == 0) ||
         (!encryptedData->iv) ||
         (!encryptedData->ciphertext)) {
        return MA_COMM_INVALID_PARAMETER;
    }

    return MA_COMM_SUCCESS;
}

uint8_t getEncodedLengthEncData(EncryptedData *encryptedData,
                               size_t* encodedLength) {
    uint8_t result = MA_COMM_SUCCESS;

    // Input validation
    result = checkEncData(encryptedData);
    if(result != MA_COMM_SUCCESS) {
        return MA_COMM_INVALID_PARAMETER;
    }

    if(!encodedLength) {
        return MA_COMM_INVALID_PARAMETER;
    }

    // Size calculation
    *encodedLength = (2 + encryptedData->ivLength + encryptedData->ciphertextLength);

    return MA_COMM_SUCCESS;
}

uint8_t eraseEncData(EncryptedData *encData) {

    /* Input validation */
    if(!encData) {
        return MA_COMM_INVALID_PARAMETER;
    }

    /* Secure erase */
    if(encData->iv) {
        memset_s(encData->iv, encData->ivLength, 0, encData->ivLength);
        free(encData->iv);
        encData->iv = NULL;
    }
    encData->ivLength = 0;

    if(encData->ciphertext) {
        memset_s(encData->ciphertext, encData->ciphertextLength, 0, encData->ciphertextLength);
        free(encData->ciphertext);
        encData->ciphertext = NULL;
    }
    encData->ciphertextLength = 0;

    return MA_COMM_SUCCESS;
}

uint8_t copyEncData(EncryptedData* src, EncryptedData* dst) {
    uint8_t result = MA_COMM_SUCCESS;

    if (!src || !dst) {
        return MA_COMM_INVALID_PARAMETER;
    }

    initEncryptedData(dst);

    result = decodeEncData(src,
                           &dst->iv,
                           &dst->ivLength,
                           &dst->ciphertext,
                           &dst->ciphertextLength);

    return result;
}

uint8_t initEncryptedData(EncryptedData *encryptedData) {
    if (!encryptedData) {
        return MA_COMM_INVALID_PARAMETER;
    }
    encryptedData->ciphertext = NULL;
    encryptedData->iv = NULL;
    encryptedData->ciphertextLength = 0;
    encryptedData->ivLength = 0;

    return MA_COMM_SUCCESS;
}

void dumpEncryptedData(EncryptedData *encryptedData, uint8_t indent) {
    if ( (!encryptedData) || (!logger_is_log_enabled()) ) {
        return;
    }

    uint8_t i = 0;
    LOG("%*sEncrytedData:\n", indent, "");
    LOG("%*sivLength: %u\n", indent + 1, "", encryptedData->ivLength);
    LOG("%*siv: ", indent + 1, "");
    for(i = 0; i < encryptedData->ivLength; ++i) {
        LOG("%02x", encryptedData->iv[i]);
    }
    LOG("\n");
    LOG("%*scipherLength: %u\n", indent + 1, "", encryptedData->ciphertextLength);
    LOG("%*scipherText: ", indent + 1, "");
    for(i = 0; i < encryptedData->ciphertextLength; ++i) {
        LOG("%02x", encryptedData->ciphertext[i]);
    }
    LOG("\n");
}
