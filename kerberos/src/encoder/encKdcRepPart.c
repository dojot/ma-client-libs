#include "encKdcRepPart.h"

#include "ma_comm_error_codes.h"
#include "logger/logger.h"

uint8_t initEncKdcPart(EncKdcPart* encKdcPart) {

	if (!encKdcPart) {
		return MA_COMM_INVALID_PARAMETER;
	}
	initSessionKeys(&encKdcPart->sk);
	memset(encKdcPart->nonce, 0, NONCE_LENGTH);
	memset(encKdcPart->sname, 0, PRINCIPAL_NAME_LENGTH);
	encKdcPart->authtime = 0;
	encKdcPart->endtime = 0;

	return MA_COMM_SUCCESS;
}

uint8_t eraseEncKdcPart(EncKdcPart* encKdcPart) {

	/// Input validation
	if(!encKdcPart) {
		return MA_COMM_INVALID_PARAMETER;
	}

	// Secure erase individual fields
	eraseSessionKeys(&encKdcPart->sk);
	encKdcPart->authtime = 0;
	encKdcPart->endtime = 0;
	memset_s(encKdcPart->sname, PRINCIPAL_NAME_LENGTH, 0, PRINCIPAL_NAME_LENGTH);
	memset_s(encKdcPart->nonce, NONCE_LENGTH, 0, NONCE_LENGTH);

	return MA_COMM_SUCCESS;
}

uint8_t setEncodedEncKdcPart(EncKdcPart* encKdcPart,
							 uint8_t* encodedInput,
							 size_t encodedLength,
							 size_t* offset) {
	uint8_t result = 0;
	size_t encOffset, sessionKeyOffset;

	// Input validation
	if(!encKdcPart || !encodedInput) {
		return MA_COMM_INVALID_PARAMETER;
	}

	/* Check if encoded data has at least enough size to store the sname, times and lengths of session keys */
	if(encodedLength < PRINCIPAL_NAME_LENGTH + 2 * sizeof(uint64_t) + 2 * sizeof(uint8_t)) {
		return MA_COMM_INVALID_PARAMETER;
	}	

	initEncKdcPart(encKdcPart);

	// Unserialization
	encOffset = 0;
	result = setEncodedSessionKeys(&encKdcPart->sk, encodedInput, encodedLength, &sessionKeyOffset);
	if(result != MA_COMM_SUCCESS) {
		return MA_COMM_INVALID_PARAMETER;
	}
	encOffset += sessionKeyOffset;
	
	/* Check if encoded input has the correct size */
	size_t totalLength = encOffset + 2 * sizeof(uint64_t) + PRINCIPAL_NAME_LENGTH + NONCE_LENGTH;
	if(totalLength != encodedLength) {
		eraseSessionKeys(&encKdcPart->sk);
		return MA_COMM_INVALID_PARAMETER;
	}

	memcpy(encKdcPart->sname, encodedInput + encOffset, PRINCIPAL_NAME_LENGTH);
	encOffset += PRINCIPAL_NAME_LENGTH;
	memcpy(encKdcPart->nonce, encodedInput + encOffset, NONCE_LENGTH);
	encOffset += NONCE_LENGTH;
	memcpy(&encKdcPart->authtime, encodedInput + encOffset, sizeof(uint64_t));
	encKdcPart->authtime = be64toh(encKdcPart->authtime);
	encOffset += sizeof(uint64_t);
	memcpy(&encKdcPart->endtime, encodedInput + encOffset, sizeof(uint64_t));
	encKdcPart->endtime = be64toh(encKdcPart->endtime);
	encOffset += sizeof(uint64_t);

	return MA_COMM_SUCCESS;
}

void dumpEncKdcPart(EncKdcPart* encKdcPart, uint8_t indent) {
	if ( (!encKdcPart) || (!logger_is_log_enabled()) ) {
		return;
	}

	uint8_t i = 0;
	LOG("%*sEncKdcPart:\n", indent, "");
	LOG("%*ssname: ", indent + 1, "");
	for(i = 0; i < PRINCIPAL_NAME_LENGTH; ++i) {
	    LOG("%02x", encKdcPart->sname[i]);
	}
	LOG("\n");
	dumpSessionKeys(&encKdcPart->sk, indent + 1);
	LOG("%*snonce: ", indent + 1, "");
	for(i = 0; i < NONCE_LENGTH; ++i) {
	    LOG("%02x", encKdcPart->nonce[i]);
	}
	LOG("\n");
	LOG("%*sauthTime: %llu\n", indent + 1, "", encKdcPart->authtime);
	LOG("%*sendTime: %llu\n", indent + 1, "", encKdcPart->endtime);
}

