#include "authenticator.h"

errno_t encodeAuthenticator(Authenticator* authenticator, uint8_t* cname, size_t cnameLength, uint8_t* ctime, 
				size_t ctimeLength)
{
	errno_t result;

	/* Input validation */
	if(authenticator == NULL || cname == NULL || ctime == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(cnameLength != PRINCIPAL_NAME_LENGTH || ctimeLength != TIME_LENGTH) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Ensure structure is clean */
	result = memset_s(authenticator, sizeof(Authenticator), 0, sizeof(Authenticator));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	
	/* Initialize the structure with the data */
	memcpy(authenticator->cname, cname, sizeof(authenticator->cname));
	memcpy(authenticator->ctime, ctime, sizeof(authenticator->ctime));
	
	result = checkAuthenticator(authenticator);
FAIL:
	return result;
}

errno_t getEncodedAuthenticator(Authenticator* authenticator, uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;
	size_t offset;	

	/* Input validation */
	result = checkAuthenticator(authenticator);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(encodedOutput == NULL || encodedLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	*encodedOutput = (uint8_t*) malloc(sizeof(authenticator->cname) + sizeof(authenticator->ctime));
	if(*encodedOutput == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}

	/* Serializes data to encoded output */
	offset = 0;
	memcpy(*encodedOutput + offset, authenticator->cname, sizeof(authenticator->cname));
	offset += sizeof(authenticator->cname);
	memcpy(*encodedOutput + offset, authenticator->ctime, sizeof(authenticator->ctime));
	offset += sizeof(authenticator->ctime);

	*encodedLength = offset; 
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t setEncodedAuthenticator(Authenticator* authenticator, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
	errno_t result;
	size_t encodedOffset;

	/* Input validation */
	if(authenticator == NULL || encodedInput == NULL || offset == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	if(encodedLength != sizeof(authenticator->cname) + sizeof(authenticator->ctime)) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Secure remove of any previous information */
        result = memset_s(authenticator, sizeof(Authenticator), 0, sizeof(Authenticator));
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL;
        }

	/* Unserialization */
	encodedOffset = 0;
	memcpy(authenticator->cname, encodedInput + encodedOffset, sizeof(authenticator->cname));
	encodedOffset += sizeof(authenticator->cname);
	memcpy(authenticator->ctime, encodedInput + encodedOffset, sizeof(authenticator->ctime));
	encodedOffset += sizeof(authenticator->ctime);

	result = checkAuthenticator(authenticator);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	*offset = encodedOffset;
FAIL:
	return result;

}

errno_t decodeAuthenticator(Authenticator* authenticator, uint8_t** cname, size_t* cnameLength, uint8_t** ctime, 
				size_t* ctimeLength)
{
	errno_t result;

	/* Input validation */
	result = checkAuthenticator(authenticator);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(cname == NULL || ctime == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	if(cnameLength == NULL || ctimeLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*cname = (uint8_t*) malloc(sizeof(authenticator->cname));
	*ctime = (uint8_t*) malloc(sizeof(authenticator->ctime));
	
	if(*cname == NULL || *ctime == NULL) {
		 /* Resources must be freed only if an error occurs */
		free(*cname);
		free(*ctime);
		result = INVALID_STATE;
		goto FAIL;
	}

	*cnameLength = PRINCIPAL_NAME_LENGTH;
	*ctimeLength = TIME_LENGTH;	
	
	memcpy(*cname, authenticator->cname, sizeof(authenticator->cname));
	memcpy(*ctime, authenticator->ctime, sizeof(authenticator->ctime));
	result = SUCCESSFULL_OPERATION;
	
FAIL:
	return result;
}


errno_t checkAuthenticator(Authenticator* authenticator)
{
	errno_t result;

	if(authenticator == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t eraseAuthenticator(Authenticator *authenticator)
{
	errno_t result;
	
	if(authenticator == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	result = memset_s(authenticator, sizeof(Authenticator), 0, sizeof(Authenticator));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t copyAuthenticator(Authenticator *src, Authenticator *dst)
{
	errno_t result;

	/* Input validation */
	if(src == NULL || dst == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkAuthenticator(src);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	memcpy(dst, src, sizeof(Authenticator));
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}
