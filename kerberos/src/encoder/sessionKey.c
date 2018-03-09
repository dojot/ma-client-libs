#include "sessionKey.h"

#include "ma_comm_error_codes.h"
#include "logger/logger.h"

errno_t encodeSessionKeys(SessionKeys* sessionKeys, uint8_t* keyCS, uint8_t* ivCS, uint8_t* keySC, uint8_t* ivSC, uint8_t keyLength, uint8_t ivLength)
{
	errno_t result;

	/* Input validation */
	if(sessionKeys == NULL || keyCS == NULL || ivCS == NULL || keySC == NULL || ivSC == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	if(keyLength == 0 || ivLength == 0) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Implicit restriction: Security level must be the same in both directions */

	/* Initialize the structure with the data */
        result = memset_s(sessionKeys, sizeof(SessionKeys), 0, sizeof(SessionKeys));
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL;
        }

	/* Fills sectionKeys structure */
	sessionKeys->keyLength = keyLength;
	sessionKeys->ivLength = ivLength;
	
	sessionKeys->keyCS = (uint8_t*) malloc(sizeof(uint8_t) * keyLength);
	sessionKeys->keySC = (uint8_t*) malloc(sizeof(uint8_t) * keyLength);
	sessionKeys->ivCS = (uint8_t*) malloc(sizeof(uint8_t) * ivLength);
	sessionKeys->ivSC = (uint8_t*) malloc(sizeof(uint8_t) * ivLength);

	if(sessionKeys->keyCS == NULL || sessionKeys->keySC == NULL || sessionKeys->ivCS == NULL ||
		sessionKeys->ivSC == NULL) {
		free(sessionKeys->keyCS);
		free(sessionKeys->keySC);
		free(sessionKeys->ivCS);
		free(sessionKeys->ivSC);
		result = INVALID_STATE;
		goto FAIL;
	}

	memcpy(sessionKeys->keyCS, keyCS, sizeof(uint8_t) * keyLength);
	memcpy(sessionKeys->keySC, keySC, sizeof(uint8_t) * keyLength);
	memcpy(sessionKeys->ivCS, ivCS, sizeof(uint8_t) * ivLength);
	memcpy(sessionKeys->ivSC, ivSC, sizeof(uint8_t) * ivLength);
	
	result = SUCCESSFULL_OPERATION;

FAIL:
	return result;
	
}

errno_t getEncodedSessionKeys(SessionKeys* sessionKeys, uint8_t** encodedOutput, size_t* encodedLength) 
{
	errno_t result;
	size_t offset;

	/* Input Validation */
	result = checkSessionKeys(sessionKeys);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	if(encodedOutput == NULL || encodedLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*encodedOutput = (uint8_t*) malloc(sizeof(uint8_t) * (2 * sessionKeys->ivLength + 2 * sessionKeys->keyLength + 2 * sizeof(uint8_t)));
	if(*encodedOutput == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}


	/* Serializes data to encodedOutput */
	offset = 0;
	memcpy(*encodedOutput + offset, &sessionKeys->keyLength, sizeof(uint8_t));
	offset += sizeof(uint8_t);
	memcpy(*encodedOutput + offset, &sessionKeys->ivLength, sizeof(uint8_t));
	offset += sizeof(uint8_t);

	/* Client to Server communication parameters */
	memcpy(*encodedOutput + offset, sessionKeys->keyCS, sizeof(uint8_t) * sessionKeys->keyLength);
	offset += sizeof(uint8_t) * sessionKeys->keyLength;
	memcpy(*encodedOutput + offset, sessionKeys->ivCS, sizeof(uint8_t) * sessionKeys->ivLength);
	offset += sizeof(uint8_t) * sessionKeys->ivLength;	
	
	/* Server to Client communication parameters */
	memcpy(*encodedOutput + offset, sessionKeys->keySC, sizeof(uint8_t) * sessionKeys->keyLength);
	offset += sizeof(uint8_t) * sessionKeys->keyLength;
	memcpy(*encodedOutput + offset, sessionKeys->ivSC, sizeof(uint8_t) * sessionKeys->ivLength);
	offset += sizeof(uint8_t) * sessionKeys->ivLength;	

FAIL:
	return result;
}


errno_t setEncodedSessionKeys(SessionKeys* sessionKeys, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
	errno_t result;
	size_t encOffset;

	/* Input validation */
	if(sessionKeys == NULL || encodedInput == NULL || offset == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(encodedLength == 0) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Secure remove any previous information */
	result = memset_s(sessionKeys, sizeof(SessionKeys), 0, sizeof(SessionKeys));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Unserialization */
    encOffset = 0;
	memcpy(&sessionKeys->keyLength, encodedInput + encOffset, sizeof(uint8_t));
	encOffset += sizeof(uint8_t);
	memcpy(&sessionKeys->ivLength, encodedInput + encOffset, sizeof(uint8_t));
	encOffset += sizeof(uint8_t);
	

	/* Check if specified key and iv sizes are correct */ 
	if(2 * sizeof(uint8_t) + 2 * sessionKeys->keyLength + 2 * sessionKeys->ivLength > encodedLength) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	sessionKeys->keyCS = (uint8_t*) malloc(sizeof(uint8_t) * sessionKeys->keyLength);
	sessionKeys->keySC = (uint8_t*) malloc(sizeof(uint8_t) * sessionKeys->keyLength);
	sessionKeys->ivCS = (uint8_t*) malloc(sizeof(uint8_t) * sessionKeys->ivLength);
	sessionKeys->ivSC = (uint8_t*) malloc(sizeof(uint8_t) * sessionKeys->ivLength);

	if(sessionKeys->keyCS == NULL || sessionKeys->keySC == NULL || sessionKeys->ivCS == NULL ||
		sessionKeys->ivSC == NULL) {
		free(sessionKeys->keyCS);
		free(sessionKeys->keySC);
		free(sessionKeys->ivCS);
		free(sessionKeys->ivSC);
		result = INVALID_STATE;
		goto FAIL;
	}
	
	/* Client to Server communication parameters */
	memcpy(sessionKeys->keyCS, encodedInput + encOffset, sizeof(uint8_t) * sessionKeys->keyLength);
    encOffset += sizeof(uint8_t) * sessionKeys->keyLength;
    memcpy(sessionKeys->ivCS, encodedInput + encOffset, sizeof(uint8_t) * sessionKeys->ivLength);
    encOffset += sizeof(uint8_t) * sessionKeys->ivLength;
	
	/* Server to Client communication parameters */
	memcpy(sessionKeys->keySC, encodedInput + encOffset, sizeof(uint8_t) * sessionKeys->keyLength);
	encOffset += sizeof(uint8_t) * sessionKeys->keyLength;
	memcpy(sessionKeys->ivSC, encodedInput + encOffset, sizeof(uint8_t) * sessionKeys->ivLength);
	encOffset += sizeof(uint8_t) * sessionKeys->ivLength;	
	*offset = encOffset;
	result = checkSessionKeys(sessionKeys);
FAIL:
	return result;
}

errno_t decodeSessionKeys(SessionKeys* sessionKeys, uint8_t** keyCS, uint8_t** ivCS, uint8_t** keySC, uint8_t** ivSC, uint8_t* keyLength, uint8_t* ivLength)
{
	errno_t result;
	
	/* Input validation */
	result = checkSessionKeys(sessionKeys);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(keyCS == NULL || ivCS == NULL || keySC == NULL || ivSC == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(keyLength == NULL || ivLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*keyCS = (uint8_t*) malloc(sizeof(uint8_t) * sessionKeys->keyLength);
	*keySC = (uint8_t*) malloc(sizeof(uint8_t) * sessionKeys->keyLength);
	*ivCS = (uint8_t*) malloc(sizeof(uint8_t) * sessionKeys->ivLength);
	*ivSC = (uint8_t*) malloc(sizeof(uint8_t) * sessionKeys->ivLength);

	if(*keyCS == NULL || *keySC == NULL || *ivCS == NULL || *ivSC == NULL) {
		/* Resources must be freed only if an error occurs */
		free(*keyCS);
		free(*keySC);
		free(*ivCS);
		free(*ivSC);
		result = INVALID_STATE;
		goto FAIL;
	}

	*keyLength = sessionKeys->keyLength;
	*ivLength = sessionKeys->ivLength;

	/* Client to Server communication parameters */
	memcpy(*keyCS, sessionKeys->keyCS, sizeof(uint8_t) * sessionKeys->keyLength);
	memcpy(*ivCS, sessionKeys->ivCS, sizeof(uint8_t) * sessionKeys->ivLength);
	
	/* Server to Client communication parameters */
	memcpy(*keySC, sessionKeys->keySC, sizeof(uint8_t) * sessionKeys->keyLength);
	memcpy(*ivSC, sessionKeys->ivSC, sizeof(uint8_t) * sessionKeys->ivLength);
	result = SUCCESSFULL_OPERATION;

FAIL:
	return result;
}

errno_t checkSessionKeys(SessionKeys* sessionKeys) 
{
	errno_t result;

	/* Input validation */
	if(sessionKeys == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(sessionKeys->keyLength == 0 || sessionKeys->ivLength == 0) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(sessionKeys->keyCS == NULL || sessionKeys->keySC == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(sessionKeys->ivCS == NULL || sessionKeys->ivSC == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

uint8_t eraseSessionKeys(SessionKeys* sessionKeys) {
	errno_t result;

	// Input validation
	if(!sessionKeys) {
		return MA_COMM_INVALID_PARAMETER;
	}

	/* Secure erase key and ivs */
	if (sessionKeys->ivCS) {
		memset_s(sessionKeys->ivCS, sessionKeys->ivLength, 0, sessionKeys->ivLength);
		free(sessionKeys->ivCS);
		sessionKeys->ivCS = NULL;
	}

	if (sessionKeys->ivSC) {
		memset_s(sessionKeys->ivSC, sessionKeys->ivLength, 0, sessionKeys->ivLength);
		free(sessionKeys->ivSC);
		sessionKeys->ivSC = NULL;
	}

	sessionKeys->ivLength = 0;

	if (sessionKeys->keyCS) {
		memset_s(sessionKeys->keyCS, sessionKeys->keyLength, 0, sessionKeys->keyLength);
		free(sessionKeys->keyCS);
		sessionKeys->keyCS = NULL;
	}

	if (sessionKeys->keySC) {
		memset_s(sessionKeys->keySC, sessionKeys->keyLength, 0, sessionKeys->keyLength);
		free(sessionKeys->keySC);
		sessionKeys->keySC = NULL;
	}

	sessionKeys->keyLength = 0;


	return MA_COMM_SUCCESS;
}

uint8_t copySessionKeys(SessionKeys* src, SessionKeys* dst) {

	if(!dst || !src) {
		return MA_COMM_INVALID_PARAMETER;
	}

	initSessionKeys(dst);

	dst->keyLength = src->keyLength;
	dst->ivLength = src->ivLength;
	dst->keyCS = (uint8_t*) malloc(sizeof(uint8_t) * src->keyLength); 
	dst->keySC = (uint8_t*) malloc(sizeof(uint8_t) * src->keyLength); 
	dst->ivCS = (uint8_t*) malloc(sizeof(uint8_t) * src->ivLength); 
	dst->ivSC = (uint8_t*) malloc(sizeof(uint8_t) * src->ivLength); 
	if(!dst->keyCS || !dst->keySC || !dst->ivCS || !dst->ivSC) {
		eraseSessionKeys(dst);
		return MA_COMM_INVALID_STATE;
	}

	// Copy individual fields
	memcpy(dst->keyCS, src->keyCS, src->keyLength);
	memcpy(dst->keySC, src->keySC, src->keyLength);
	memcpy(dst->ivCS, src->ivCS, src->ivLength);
	memcpy(dst->ivSC, src->ivSC, src->ivLength);

	return MA_COMM_SUCCESS;
}

uint8_t initSessionKeys(SessionKeys* sessionKeys) {

	if (!sessionKeys) {
		return MA_COMM_INVALID_PARAMETER;
	}

	sessionKeys->ivLength = 0;
	sessionKeys->keyLength = 0;
	sessionKeys->ivCS = NULL;
	sessionKeys->ivSC = NULL;
	sessionKeys->keyCS = NULL;
	sessionKeys->keySC = NULL;

	return MA_COMM_SUCCESS;
}

void dumpSessionKeys(SessionKeys* sessionKeys, uint8_t indent) {
	if ( (!sessionKeys) || (!logger_is_log_enabled()) ) {
		return;
	}

	uint8_t i = 0;
	LOG("%*sSessionKeys:\n", indent, "");
	LOG("%*sivLength: %u\n", indent + 1, "", sessionKeys->ivLength);
	LOG("%*sivCS: ", indent + 1, "");
	for(i = 0; i < sessionKeys->ivLength; ++i) {
	    LOG("%02x", sessionKeys->ivCS[i]);
	}
	LOG("\n");
	LOG("%*sivSC: ", indent + 1, "");
	for(i = 0; i < sessionKeys->ivLength; ++i) {
	    LOG("%02x", sessionKeys->ivSC[i]);
	}
	LOG("\n");
	LOG("%*skeyLength: %u\n", indent + 1, "", sessionKeys->keyLength);
	LOG("%*skeyCS: ", indent + 1, "");
	for(i = 0; i < sessionKeys->keyLength; ++i) {
	    LOG("%02x", sessionKeys->keyCS[i]);
	}
	LOG("\n");
	LOG("%*skeySC: ", indent + 1, "");
	for(i = 0; i < sessionKeys->keyLength; ++i) {
	    LOG("%02x", sessionKeys->keySC[i]);
	}
	LOG("\n");
}
