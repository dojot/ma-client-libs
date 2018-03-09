#include "replyAP.h"

#include "ma_comm_error_codes.h"

errno_t encodeReplyAP(ReplyAP* replyAp, EncryptedData* encData)
{
	errno_t result;

	/* Input validation */
	if(replyAp == NULL || encData == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Copy individual field */
	result = copyEncData(encData, &replyAp->encData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

FAIL:
	return result;
}

errno_t getEncodedReplyAP(ReplyAP* replyAp, uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;
	uint8_t* output;
	
	/* Input validation */
	result = checkReplyAP(replyAp);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(encodedOutput == NULL || encodedLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	/* Copy the only field to output */	
	result = getEncodedEncData(&replyAp->encData, encodedOutput, encodedLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	output = (uint8_t*) malloc(sizeof(uint8_t) * (*encodedLength + MESSAGE_CODE_LENGTH));
	if(output == NULL) {
		result = INVALID_STATE;
		goto FAIL_CLEAN;
	}
	
	*output = REPLY_AP_CODE;
	memcpy(output + MESSAGE_CODE_LENGTH, *encodedOutput, *encodedLength);
FAIL_CLEAN:
	result |= memset_s(*encodedOutput, sizeof(uint8_t) * (*encodedLength), 0, sizeof(uint8_t) * (*encodedLength));
FAIL:
	*encodedOutput = output;
	*encodedLength = *encodedLength + MESSAGE_CODE_LENGTH;
	return result;
}

uint8_t setEncodedReplyAP(ReplyAP* replyAp,
						  uint8_t* encodedInput,
						  size_t encodedLength,
						  size_t* offset) {
	uint8_t result = MA_COMM_SUCCESS;
	size_t encLength;

	// Input validation
	if(!replyAp || !encodedInput || !offset) {
		return MA_COMM_INVALID_PARAMETER;
	}
	
	if(*encodedInput != REPLY_AP_CODE) {
		return MA_COMM_INVALID_STATE;
	}

	initReplyAP(replyAp);

	*offset = MESSAGE_CODE_LENGTH;

	// Decode the encrypted data field
	result = setEncodedEncData(&replyAp->encData,
							   encodedInput + *offset,
							   encodedLength - *offset,
							   &encLength);
	*offset += encLength;
	if(result != MA_COMM_SUCCESS){
	    eraseReplyAP(replyAp);
	    return MA_COMM_INVALID_STATE;
	}

	return MA_COMM_SUCCESS;
}

errno_t decodeReplyAP(ReplyAP* replyAp, EncryptedData* encData)
{
	errno_t result;

	/* Input validation */
	result = checkReplyAP(replyAp);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(encData == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Copy the encrypted data field */
	result = copyEncData(&replyAp->encData, encData);
FAIL:
	return result;
}

errno_t checkReplyAP(ReplyAP* replyAp)
{
	errno_t result;

	/* Input validation */
	if(replyAp == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkEncData(&replyAp->encData);

FAIL:
	return result;
}

uint8_t initReplyAP(ReplyAP* replyAp) {
	uint8_t result = MA_COMM_SUCCESS;

	// Input validation
	if(!replyAp) {
		return MA_COMM_INVALID_PARAMETER;
	}

	result = initEncryptedData(&replyAp->encData);

	return result;
}

uint8_t eraseReplyAP(ReplyAP* replyAp) {
	uint8_t result = MA_COMM_SUCCESS;

	// Input validation
	if(!replyAp) {
		return MA_COMM_INVALID_PARAMETER;
	}

	result = eraseEncData(&replyAp->encData);

	return result;
}

errno_t copyReplyAP(ReplyAP* src, ReplyAP* dst)
{
	errno_t result;

	/* Input validation */
	result = checkReplyAP(src);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Copy field to dst */
	result = copyEncData(&src->encData, &dst->encData);

FAIL:
	return result;
}



