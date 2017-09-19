#include "encTicketPart.h"

errno_t encodeEncTicketPart(EncTicketPart* encTicketPart, SessionKeys* sk, uint8_t* cname, size_t cnameLength,
				uint8_t* authtime, size_t authtimeLength, uint8_t* endtime, size_t endtimeLength)
{
	errno_t result;

	/* Input validation */
	if(encTicketPart == NULL || cname == NULL || authtime == NULL || endtime == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	result = checkSessionKeys(sk);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(cnameLength != PRINCIPAL_NAME_LENGTH || authtimeLength != TIME_LENGTH || endtimeLength != TIME_LENGTH) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Copy individual fields */
	memcpy(encTicketPart->cname, cname, PRINCIPAL_NAME_LENGTH);
	memcpy(encTicketPart->authtime, authtime, TIME_LENGTH);
	memcpy(encTicketPart->endtime, endtime, TIME_LENGTH);
	result = copySessionKeys(sk, &encTicketPart->sk);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = checkEncTicketPart(encTicketPart);

FAIL:
	return result;
}

errno_t getEncodedEncTicketPart(EncTicketPart* encTicketPart, uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;
	uint8_t* encodedSessionKeys;
	size_t offset, encodedSessionKeysLength = 0;

	/* Input validation */
	result = checkEncTicketPart(encTicketPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(encodedOutput == NULL || encodedLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Encode individual fields */
	result = getEncodedSessionKeys(&encTicketPart->sk, &encodedSessionKeys, &encodedSessionKeysLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	*encodedOutput = (uint8_t*) malloc(sizeof(uint8_t) * (encodedSessionKeysLength + 2 * TIME_LENGTH + PRINCIPAL_NAME_LENGTH));
	if(*encodedOutput == NULL) {
		result = INVALID_STATE;
		goto FAIL_ALLOC;
	}

	offset = 0;
	memcpy(*encodedOutput + offset, encodedSessionKeys, encodedSessionKeysLength);
	offset += encodedSessionKeysLength;
	memcpy(*encodedOutput + offset, encTicketPart->cname, PRINCIPAL_NAME_LENGTH);
	offset += PRINCIPAL_NAME_LENGTH;
	memcpy(*encodedOutput + offset, encTicketPart->authtime, TIME_LENGTH);
	offset += TIME_LENGTH;
	memcpy(*encodedOutput + offset, encTicketPart->endtime, TIME_LENGTH);
	offset += TIME_LENGTH;
	
	*encodedLength = offset;
FAIL_ALLOC:
	result |= memset_s(&encodedSessionKeys, encodedSessionKeysLength, 0, encodedSessionKeysLength);
	free(encodedSessionKeys);
FAIL:
	return result;
}

errno_t setEncodedEncTicketPart(EncTicketPart* encTicketPart, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
	errno_t result;
	size_t encOffset, sessionKeyOffset;

	/* Input validation */
	if(encTicketPart == NULL || encodedInput == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Check if encoded data has at least enough size to store the cname, times and lengths of session keys */
	if(encodedLength < PRINCIPAL_NAME_LENGTH + 2 * TIME_LENGTH + 2 * sizeof(uint8_t)) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}	

	/* Secure remove any previous information */
	result = memset_s(encTicketPart, sizeof(EncTicketPart), 0, sizeof(EncTicketPart));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Unserialization */
	encOffset = 0;
	result = setEncodedSessionKeys(&encTicketPart->sk, encodedInput, encodedLength, &sessionKeyOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	encOffset += sessionKeyOffset;
	
	/* Check if encoded input has the correct size */
	if(encOffset + 2 * TIME_LENGTH + PRINCIPAL_NAME_LENGTH != encodedLength) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	memcpy(encTicketPart->cname, encodedInput + encOffset, PRINCIPAL_NAME_LENGTH);
	encOffset += PRINCIPAL_NAME_LENGTH;
	memcpy(encTicketPart->authtime, encodedInput + encOffset, TIME_LENGTH);
	encOffset += TIME_LENGTH;
	memcpy(encTicketPart->endtime, encodedInput + encOffset, TIME_LENGTH);
	encOffset += TIME_LENGTH;
	result = SUCCESSFULL_OPERATION;	
FAIL:
	return result;
}


errno_t decodeEncTicketPart(EncTicketPart* encTicketPart, SessionKeys* sk, uint8_t** cname, uint8_t* cnameLength,
			uint8_t** authtime, size_t* authtimeLength, uint8_t** endtime, size_t* endtimeLength)
{
	errno_t result;

	/* Input validation */
	result = checkEncTicketPart(encTicketPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(sk == NULL || cname == NULL || authtime == NULL || endtime == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	if(cnameLength == NULL || authtimeLength == NULL || endtimeLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Copy individual fields */
	result = copySessionKeys(&encTicketPart->sk, sk);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	*cname = (uint8_t*) malloc(sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH);
	*authtime = (uint8_t*) malloc(sizeof(uint8_t) * TIME_LENGTH);
	*endtime = (uint8_t*) malloc(sizeof(uint8_t) * TIME_LENGTH);
	if(*cname == NULL || *authtime == NULL || *endtime == NULL) {
		/* It only makes sense to free memory here */
		free(*cname);
		free(*authtime);
		free(*endtime);
		result = INVALID_STATE;
		goto FAIL;
	}

	memcpy(*cname, encTicketPart->cname, sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH);
	memcpy(*authtime, encTicketPart->authtime, sizeof(uint8_t) * TIME_LENGTH);
	memcpy(*endtime, encTicketPart->endtime, sizeof(uint8_t) * TIME_LENGTH);
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}


errno_t checkEncTicketPart(EncTicketPart* encTicketPart)
{
	errno_t result;

	/* Input validation */
	if(encTicketPart == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkSessionKeys(&encTicketPart->sk);
FAIL:
	return result;
}


errno_t eraseEncTicketPart(EncTicketPart* encTicketPart)
{
	errno_t result;

	/* Input validation */
	result = checkEncTicketPart(encTicketPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Secure erase individual fields */
	result = eraseSessionKeys(&encTicketPart->sk);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = memset_s(encTicketPart, sizeof(EncTicketPart), 0, sizeof(EncTicketPart));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
FAIL:
	return result;
}


