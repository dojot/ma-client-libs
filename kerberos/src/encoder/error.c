#include "error.h"
#include <stdint.h>

/* Fills the request */
errno_t encodeError(Error* error, uint8_t errorCode)
{
	errno_t result;

	/* Input parameters validation */
	if(error == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	error->errorCode = errorCode;
	result = checkError(error);
FAIL:
	return result;
}

/* Generate byte array encodedOutput from error */
errno_t getEncodedError(Error* error, uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;
	size_t encOffset;
	
	/* Input parameters validation */
	result = checkError(error);
	if(result != SUCCESSFULL_OPERATION) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(encodedOutput == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*encodedOutput = (uint8_t*) malloc(MESSAGE_CODE_LENGTH + ERROR_CODE_LENGTH);

	if(*encodedOutput == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}

	/* Serializes data to encodedOutput */
	encOffset = 0;
	*encodedOutput[encOffset] = ERROR_CODE;
	encOffset += MESSAGE_CODE_LENGTH;
	*encodedOutput[encOffset] = error->errorCode;
	encOffset += ERROR_CODE_LENGTH;
	*encodedLength = encOffset;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
} 

/* Generate error from byte array encodedInput */
errno_t setEncodedError(Error* error, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
	errno_t result;
	size_t encOffset;

	/* Input parameters validation */
	if(error == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Check if encoded data has the correct size */
	if(encodedLength != (MESSAGE_CODE_LENGTH + ERROR_CODE_LENGTH)) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Unserialization */
	encOffset = 0;
	if(*encodedInput != ERROR_CODE) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	encOffset += MESSAGE_CODE_LENGTH;
	error->errorCode = encodedInput[encOffset];
	encOffset += ERROR_CODE_LENGTH;
	*offset = encOffset;
FAIL:
	return result;
}

/* Get individual fields from the error */
errno_t decodeError(Error* error, uint8_t* errorCode)
{
	errno_t result;

	/* Input parameters validation */
	result = checkError(error);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(error == NULL || errorCode == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	*errorCode = error->errorCode;
	result = SUCCESSFULL_OPERATION;

FAIL:
	return result;
}

/* Check the existence of invalid fields inside the error */
errno_t checkError(Error* error)
{
	errno_t result;

	if(error == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	switch(error->errorCode) {
		case KDC_ERR_C_PRINCIPAL_UNKNOWN:
		case KDC_ERR_S_PRINCIPAL_UNKNOWN:
		case KRB_AP_ERR_BAD_INTEGRITY:
		case KRB_AP_ERR_TKT_EXPIRED:
		case KRB_AP_ERR_REPEAT:
		case KRB_AP_ERR_BADMATCH:
		case KRB_AP_ERR_SKEW:
		case KRB_ERR_GENERIC:
			result = SUCCESSFULL_OPERATION;
			break;
		default:
			result = INVALID_PARAMETER;
			break;
	}
	
FAIL:
	return result;
}

errno_t eraseError(Error* error)
{
	errno_t result;

	/* Input validation */
	if(error == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Secure erase */
	result = memset_s(error, sizeof(Error), 0, sizeof(Error));
	if(result != SUCCESSFULL_OPERATION) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;	
}

