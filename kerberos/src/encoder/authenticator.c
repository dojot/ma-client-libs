#include "authenticator.h"

#include "ma_comm_error_codes.h"

uint8_t encodeAuthenticator(Authenticator* authenticator,
							uint8_t* cname,
							size_t cnameLength,
							uint64_t ctime) {

	// Input validation
	if(!authenticator || !cname) {
		return MA_COMM_INVALID_PARAMETER;
	}

	if(cnameLength != PRINCIPAL_NAME_LENGTH) {
		return MA_COMM_INVALID_PARAMETER;
	}
	
	/* Initialize the structure with the data */
	memcpy(authenticator->cname, cname, sizeof(authenticator->cname));
	authenticator->ctime = ctime;

	return MA_COMM_SUCCESS;
}

uint8_t getEncodedAuthenticator(Authenticator* authenticator,
								uint8_t** encodedOutput,
								size_t* encodedLength) {
	errno_t result;
	size_t offset;	

	/* Input validation */
	if(!authenticator || !encodedOutput || !encodedLength) {
		return MA_COMM_INVALID_PARAMETER;
	}
	
	*encodedOutput = (uint8_t*) malloc(sizeof(authenticator->cname) + sizeof(authenticator->ctime));
	if(!*encodedOutput) {
		return MA_COMM_INVALID_STATE;
	}

	// Serializes data to encoded output
	offset = 0;
	// cname
	memcpy(*encodedOutput + offset, authenticator->cname, sizeof(authenticator->cname));
	offset += sizeof(authenticator->cname);
	// ctime
	uint64_t tmpCTime = htobe64(authenticator->ctime);
	memcpy(*encodedOutput + offset, &tmpCTime, sizeof(authenticator->ctime));
	offset += sizeof(authenticator->ctime);

	*encodedLength = offset; 

	return MA_COMM_SUCCESS;
}

errno_t setEncodedAuthenticator(Authenticator* authenticator,
								uint8_t* encodedInput,
								size_t encodedLength,
								size_t* offset) {
	errno_t result;
	size_t encodedOffset;

	/* Input validation */
	if(authenticator == NULL || encodedInput == NULL || offset == NULL) {
		return INVALID_PARAMETER;
	}
	
	if(encodedLength < sizeof(authenticator->cname) + sizeof(authenticator->ctime)) {
		return INVALID_PARAMETER;
	}

	/* Unserialization */
	encodedOffset = 0;
	// cname
	memcpy(authenticator->cname, encodedInput + encodedOffset, sizeof(authenticator->cname));
	encodedOffset += sizeof(authenticator->cname);
	// ctime
	memcpy(&authenticator->ctime, encodedInput + encodedOffset, sizeof(authenticator->ctime));
	authenticator->ctime = be64toh(authenticator->ctime);
	encodedOffset += sizeof(authenticator->ctime);

	*offset = encodedOffset;

	return SUCCESSFULL_OPERATION;
}

errno_t decodeAuthenticator(Authenticator* authenticator,
							uint8_t** cname,
							size_t* cnameLength,
							uint64_t* ctime) {
	/* Input validation */
	if(authenticator == NULL || cname == NULL || ctime == NULL || cnameLength == NULL) {
		return INVALID_PARAMETER;
	}
	
	*cname = (uint8_t*) malloc(sizeof(authenticator->cname));
	if(*cname == NULL) {
		return INVALID_STATE;
	}

	*cnameLength = PRINCIPAL_NAME_LENGTH;
	
	memcpy(*cname, authenticator->cname, sizeof(authenticator->cname));
	*ctime = authenticator->ctime;
	return SUCCESSFULL_OPERATION;
}

uint8_t initAuthenticator(Authenticator *authenticator) {
	if (!authenticator) {
		return MA_COMM_INVALID_PARAMETER;
	}

	memset(authenticator->cname, 0, PRINCIPAL_NAME_LENGTH);
	authenticator->ctime = 0;

	return MA_COMM_SUCCESS;
}

uint8_t eraseAuthenticator(Authenticator *authenticator) {
	
	return initAuthenticator(authenticator);
}

errno_t copyAuthenticator(Authenticator *src, Authenticator *dst) {
	errno_t result;

	/* Input validation */
	if(src == NULL || dst == NULL) {
		return INVALID_PARAMETER;
	}
	memcpy(dst, src, sizeof(Authenticator));
	return SUCCESSFULL_OPERATION;
}
