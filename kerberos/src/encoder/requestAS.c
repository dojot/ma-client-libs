#include "requestAS.h"
#include <stdint.h>

/* Fills the request */
errno_t encodeRequestAS(RequestAS* requestAs, uint8_t* cname, size_t cnameLength, uint8_t* sname, size_t snameLength, uint8_t* nonce, size_t nonceLength)
{
	errno_t result;

	/* Input parameters validation */
	if(requestAs == NULL || cname == NULL || sname == NULL || nonce == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(cnameLength != PRINCIPAL_NAME_LENGTH || snameLength != PRINCIPAL_NAME_LENGTH) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Ensure structure is clean */
	result = memset_s(requestAs, sizeof(RequestAS), 0, sizeof(RequestAS));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	memcpy(requestAs->cname, cname, sizeof(uint8_t) * cnameLength);
	memcpy(requestAs->sname, sname, sizeof(uint8_t) * snameLength);
	memcpy(requestAs->nonce, nonce, sizeof(uint8_t) * nonceLength);
	result = checkRequestAS(requestAs);
FAIL:
	return result;
}

/* Generate byte array encodedOutput from requestAS */
errno_t getEncodedRequestAS(RequestAS* requestAS, uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;
	size_t encOffset;
	
	/* Input parameters validation */
	result = checkRequestAS(requestAS);
	if(result != SUCCESSFULL_OPERATION) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(encodedOutput == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*encodedOutput = (uint8_t*) malloc(MESSAGE_CODE_LENGTH + sizeof(requestAS->cname) + sizeof(requestAS->sname) + sizeof(requestAS->nonce));

	if(*encodedOutput == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}

	/* Serializes data to encodedOutput */
	encOffset = 0;
	**encodedOutput = REQUEST_AS_CODE;
	encOffset += MESSAGE_CODE_LENGTH;
	memcpy(*encodedOutput + encOffset, requestAS->cname, sizeof(requestAS->cname));
	encOffset += sizeof(requestAS->cname);
	memcpy(*encodedOutput + encOffset, requestAS->sname, sizeof(requestAS->sname));
	encOffset += sizeof(requestAS->sname);
	memcpy(*encodedOutput + encOffset, requestAS->nonce, sizeof(requestAS->nonce));
	encOffset += sizeof(requestAS->nonce);
	*encodedLength = encOffset;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
} 

/* Generate requestAS from byte array encodedInput */
errno_t setEncodedRequestAS(RequestAS* requestAS, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
	errno_t result;
	size_t encOffset;

	/* Input parameters validation */
	if(requestAS == NULL || encodedInput == NULL || offset == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Check if encoded data has the correct size */
	if(encodedLength != (MESSAGE_CODE_LENGTH + sizeof(requestAS->cname) + sizeof(requestAS->sname) + sizeof(requestAS->nonce))) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Secure remove of any previous information */
	result = memset_s(requestAS, sizeof(RequestAS), 0, sizeof(RequestAS));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Unserialization */
	encOffset = 0;
	if(*encodedInput != REQUEST_AS_CODE) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	encOffset += MESSAGE_CODE_LENGTH;
	memcpy(requestAS->cname, encodedInput + encOffset, sizeof(requestAS->cname));
	encOffset += sizeof(requestAS->cname);
	memcpy(requestAS->sname, encodedInput + encOffset, sizeof(requestAS->sname));
	encOffset += sizeof(requestAS->sname);
	memcpy(requestAS->nonce, encodedInput + encOffset, sizeof(requestAS->nonce));
	encOffset += sizeof(requestAS->nonce);
	result = checkRequestAS(requestAS);
	*offset = encOffset;
FAIL:
	return result;
}

/* Get individual fields from the request */
errno_t decodeRequestAS(RequestAS* requestAs, uint8_t** cname, size_t* cnameLength, uint8_t** sname, size_t* snameLength, uint8_t** nonce, size_t* nonceLength)
{
	errno_t result;

	/* Input parameters validation */
	result = checkRequestAS(requestAs);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(cname == NULL || sname == NULL || nonce == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	if(cnameLength == NULL || snameLength == NULL || nonceLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*cname = (uint8_t*) malloc(sizeof(requestAs->cname));
	*sname = (uint8_t*) malloc(sizeof(requestAs->sname));
	*nonce = (uint8_t*) malloc(sizeof(requestAs->nonce));
	if(*cname == NULL || *sname == NULL || *nonce == NULL) {
		/* Resources must be freed only if an error occurs */
		free(*cname);
		free(*sname);
		free(*nonce);
		result = INVALID_STATE;
		goto FAIL;
	}
	
	*cnameLength = PRINCIPAL_NAME_LENGTH;
	*snameLength = PRINCIPAL_NAME_LENGTH;
	*nonceLength = NONCE_LENGTH;
	
	memcpy(*cname, requestAs->cname, sizeof(requestAs->cname));
	memcpy(*sname, requestAs->sname, sizeof(requestAs->sname));
	memcpy(*nonce, requestAs->nonce, sizeof(requestAs->nonce));
	result = SUCCESSFULL_OPERATION;

FAIL:
	return result;
}

/* Check the existance of invalid fields inside request */
errno_t checkRequestAS(RequestAS* requestAs)
{
	errno_t result;

	if(requestAs == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t eraseRequestAS(RequestAS* requestAs)
{
	errno_t result;

	/* Input validation */
	if(requestAs == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Secure erase */
	result = memset_s(requestAs, sizeof(RequestAS), 0, sizeof(RequestAS));
	if(result != SUCCESSFULL_OPERATION) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;	
}

