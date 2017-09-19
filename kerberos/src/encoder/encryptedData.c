#include "encryptedData.h"

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
errno_t setEncodedEncData(EncryptedData* encryptedData, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
	errno_t result;
	size_t encodedOffset;

	/* Input validation */	
	if(encryptedData == NULL || encodedInput == NULL || offset == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* 
	 * Check if the length fields are valid:
	 * encodedInput[0] == IVLength
	 * encodedInput[1] == CiphertextLength
         * So IVLen + CiphertextLen == encodedLength - 2
	 */
	if(encodedLength < 2 || encodedLength < 2 + encodedInput[0] + encodedInput[1]) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Secure remove of any previous information */
        result = memset_s(encryptedData, sizeof(EncryptedData), 0, sizeof(EncryptedData));
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL;
        }
	/* Unserialization */
        encodedOffset = 0;
        memcpy(&encryptedData->ivLength, encodedInput, sizeof(encryptedData->ivLength));
        encodedOffset += sizeof(encryptedData->ivLength);
        memcpy(&encryptedData->ciphertextLength, encodedInput + encodedOffset, sizeof(encryptedData->ciphertextLength));
        encodedOffset += sizeof(encryptedData->ciphertextLength);
	encryptedData->iv = (uint8_t*) malloc(sizeof(uint8_t) * encryptedData->ivLength);
        if(encryptedData->iv == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}
	memcpy(encryptedData->iv, encodedInput + encodedOffset, sizeof(uint8_t) * encryptedData->ivLength);
        encodedOffset += sizeof(uint8_t) * encryptedData->ivLength;
	
	encryptedData->ciphertext = (uint8_t*) malloc(sizeof(uint8_t) * encryptedData->ciphertextLength);
	if(encryptedData->ciphertext == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}
	memcpy(encryptedData->ciphertext, encodedInput + encodedOffset, sizeof(uint8_t) * encryptedData->ciphertextLength);
	encodedOffset += sizeof(uint8_t) * encryptedData->ciphertextLength;
	

	result = checkEncData(encryptedData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	*offset = encodedOffset;
FAIL:
	return result;
}

/* Get individual fields from EncryptedData */
errno_t decodeEncData(EncryptedData* encryptedData, uint8_t** iv, uint8_t* ivLength, uint8_t** ciphertext, uint8_t* ciphertextLength)
{
	errno_t result;

	/* Input validation */
	result = checkEncData(encryptedData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	if(iv == NULL || ciphertext == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(ivLength == NULL || ciphertextLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*iv = (uint8_t*) malloc(sizeof(uint8_t) * encryptedData->ivLength);
	*ciphertext = (uint8_t*) malloc(sizeof(uint8_t) * encryptedData->ciphertextLength);
	if(*iv == NULL || *ciphertext == NULL) {
		/* Resources must be freed only if an error occurs */
		free(*iv);
		free(*ciphertext);
		result = INVALID_STATE;
		goto FAIL;
	}
	*ivLength = encryptedData->ivLength;
	*ciphertextLength = encryptedData->ciphertextLength;
	
	memcpy(*iv, encryptedData->iv, sizeof(uint8_t) * encryptedData->ivLength);
	memcpy(*ciphertext, encryptedData->ciphertext, sizeof(uint8_t) * encryptedData->ciphertextLength);
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t checkEncData(EncryptedData *encryptedData)
{
	errno_t result;

	if(encryptedData == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(encryptedData->ivLength == 0 || encryptedData->ivLength > IV_LENGTH) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(encryptedData->ciphertextLength == 0) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	if(encryptedData->iv == NULL || encryptedData->ciphertext == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t getEncodedLengthEncData(EncryptedData *encryptedData, size_t* encodedLength)
{
	errno_t result;

	/* Input validation */
	result = checkEncData(encryptedData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(encodedLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Size calculation */
	*encodedLength = (2 + encryptedData->ivLength + encryptedData->ciphertextLength);
	result = SUCCESSFULL_OPERATION;

FAIL:
	return result;
	
}

errno_t eraseEncData(EncryptedData *encData) 
{
	errno_t result;

	/* Input validation */
	result = checkEncData(encData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Secure erase */
	result = memset_s(encData->iv, sizeof(uint8_t) * encData->ivLength, 0, sizeof(uint8_t) * encData->ivLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = memset_s(encData->ciphertext, sizeof(uint8_t) * encData->ciphertextLength, 0, sizeof(uint8_t) * encData->ciphertextLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = memset_s(encData, sizeof(EncryptedData), 0, sizeof(EncryptedData));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
FAIL:
	return result;
}

errno_t copyEncData(EncryptedData* src, EncryptedData* dst)
{
	errno_t result;

	result = decodeEncData(src, &dst->iv, &dst->ivLength, &dst->ciphertext, &dst->ciphertextLength);

	return result;
}	
