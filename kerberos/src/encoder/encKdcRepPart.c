#include "encKdcRepPart.h"

errno_t encodeEncKdcPart(EncKdcPart* encKdcPart, SessionKeys* sk, uint8_t* sname, size_t snameLength,
			uint8_t* nonce, size_t nonceLength, uint8_t* authtime, size_t authtimeLength, 
			uint8_t* endtime, size_t endtimeLength)
{
	errno_t result;

	/* Input validation */
	if(encKdcPart == NULL || sname == NULL || nonce == NULL || authtime == NULL || endtime == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	result = checkSessionKeys(sk);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(snameLength != PRINCIPAL_NAME_LENGTH || nonceLength != NONCE_LENGTH || authtimeLength != TIME_LENGTH 
		|| endtimeLength != TIME_LENGTH) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Copy individual fields */
	memcpy(encKdcPart->sname, sname, PRINCIPAL_NAME_LENGTH);
	memcpy(encKdcPart->nonce, nonce, NONCE_LENGTH);
	memcpy(encKdcPart->authtime, authtime, TIME_LENGTH);
	memcpy(encKdcPart->endtime, endtime, TIME_LENGTH);
	result = copySessionKeys(sk, &encKdcPart->sk);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = checkEncKdcPart(encKdcPart);

FAIL:
	return result;
}

errno_t getEncodedEncKdcPart(EncKdcPart* encKdcPart, uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;
	uint8_t* encodedSessionKeys;
	size_t offset, encodedSessionKeysLength;

	/* Input validation */
	result = checkEncKdcPart(encKdcPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(encodedOutput == NULL || encodedLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Encode individual fields */
	result = getEncodedSessionKeys(&encKdcPart->sk, &encodedSessionKeys, &encodedSessionKeysLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	*encodedOutput = (uint8_t*) malloc(sizeof(uint8_t) * 
				(encodedSessionKeysLength + 2 * TIME_LENGTH + PRINCIPAL_NAME_LENGTH + NONCE_LENGTH));
	if(*encodedOutput == NULL) {
		result = INVALID_STATE;
		goto FAIL_ALLOC;
	}

	offset = 0;
	memcpy(*encodedOutput + offset, encodedSessionKeys, encodedSessionKeysLength);
	offset += encodedSessionKeysLength;
	memcpy(*encodedOutput + offset, encKdcPart->sname, PRINCIPAL_NAME_LENGTH);
	offset += PRINCIPAL_NAME_LENGTH;
	memcpy(*encodedOutput + offset, encKdcPart->nonce, NONCE_LENGTH);
	offset += NONCE_LENGTH;
	memcpy(*encodedOutput + offset, encKdcPart->authtime, TIME_LENGTH);
	offset += TIME_LENGTH;
	memcpy(*encodedOutput + offset, encKdcPart->endtime, TIME_LENGTH);
	offset += TIME_LENGTH;
	
	*encodedLength = offset;
FAIL_ALLOC:
	result |= memset_s(&encodedSessionKeys, encodedSessionKeysLength, 0, encodedSessionKeysLength);
	free(encodedSessionKeys);
FAIL:
	return result;
}

errno_t setEncodedEncKdcPart(EncKdcPart* encKdcPart, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
	errno_t result;
	size_t encOffset, sessionKeyOffset;

	/* Input validation */
	if(encKdcPart == NULL || encodedInput == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Check if encoded data has at least enough size to store the sname, times and lengths of session keys */
	if(encodedLength < PRINCIPAL_NAME_LENGTH + 2 * TIME_LENGTH + 2 * sizeof(uint8_t)) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}	

	/* Secure remove any previous information */
	result = memset_s(encKdcPart, sizeof(EncKdcPart), 0, sizeof(EncKdcPart));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	/* Unserialization */
	encOffset = 0;
	result = setEncodedSessionKeys(&encKdcPart->sk, encodedInput, encodedLength, &sessionKeyOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	encOffset += sessionKeyOffset;
	
	/* Check if encoded input has the correct size */
	size_t totalLength = encOffset + 2 * TIME_LENGTH + PRINCIPAL_NAME_LENGTH + NONCE_LENGTH;
	if(totalLength != encodedLength) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	memcpy(encKdcPart->sname, encodedInput + encOffset, PRINCIPAL_NAME_LENGTH);
	encOffset += PRINCIPAL_NAME_LENGTH;
	memcpy(encKdcPart->nonce, encodedInput + encOffset, NONCE_LENGTH);
	encOffset += NONCE_LENGTH;
	memcpy(encKdcPart->authtime, encodedInput + encOffset, TIME_LENGTH);
	encOffset += TIME_LENGTH;
	memcpy(encKdcPart->endtime, encodedInput + encOffset, TIME_LENGTH);
	encOffset += TIME_LENGTH;
	result = SUCCESSFULL_OPERATION;	
FAIL:
	return result;
}


errno_t decodeEncKdcPart(EncKdcPart* encKdcPart, SessionKeys* sk, uint8_t** sname, size_t* snameLength,
			uint8_t** nonce, size_t* nonceLength, uint8_t** authtime, size_t* authtimeLength, 
			uint8_t** endtime, size_t* endtimeLength)
{
	errno_t result;

	/* Input validation */
	result = checkEncKdcPart(encKdcPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(sk == NULL || sname == NULL || nonce == NULL || authtime == NULL || endtime == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	if(snameLength == NULL || nonceLength == NULL || authtimeLength == NULL || endtimeLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Copy individual fields */
	result = copySessionKeys(&encKdcPart->sk, sk);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	*sname = (uint8_t*) malloc(sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH);
	*nonce = (uint8_t*) malloc(sizeof(uint8_t) * NONCE_LENGTH);
	*authtime = (uint8_t*) malloc(sizeof(uint8_t) * TIME_LENGTH);
	*endtime = (uint8_t*) malloc(sizeof(uint8_t) * TIME_LENGTH);
	if(*sname == NULL || *nonce == NULL || *authtime == NULL || *endtime == NULL) {
		/* It only makes sense to free memory here */
		free(*sname);
		free(*nonce);
		free(*authtime);
		free(*endtime);
		result = INVALID_STATE;
		goto FAIL;
	}

	memcpy(*sname, encKdcPart->sname, sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH);
	*snameLength = PRINCIPAL_NAME_LENGTH;
	memcpy(*nonce, encKdcPart->nonce, sizeof(uint8_t) * NONCE_LENGTH);
	*nonceLength = NONCE_LENGTH;
	memcpy(*authtime, encKdcPart->authtime, sizeof(uint8_t) * TIME_LENGTH);
	*authtimeLength = TIME_LENGTH;
	memcpy(*endtime, encKdcPart->endtime, sizeof(uint8_t) * TIME_LENGTH);
	*endtimeLength = TIME_LENGTH;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}


errno_t checkEncKdcPart(EncKdcPart* encKdcPart)
{
	errno_t result;

	/* Input validation */
	if(encKdcPart == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkSessionKeys(&encKdcPart->sk);
FAIL:
	return result;
}


errno_t eraseEncKdcPart(EncKdcPart* encKdcPart)
{
	errno_t result;

	/* Input validation */
	result = checkEncKdcPart(encKdcPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Secure erase individual fields */
	result = eraseSessionKeys(&encKdcPart->sk);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = memset_s(encKdcPart, sizeof(EncKdcPart), 0, sizeof(EncKdcPart));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
FAIL:
	return result;
}


