#include "replyAS.h"

#include "ma_comm_error_codes.h"
#include "logger/logger.h"

/* Generates ReplyAS from encoded input */
uint8_t setEncodedReplyAS(ReplyAS* replyAS,
						  uint8_t* encodedInput,
						  size_t encodedLength,
						  size_t* offset) {
	uint8_t result = MA_COMM_SUCCESS;
	size_t encodedOffset = 0;
	size_t length = 0;

	/* Input validation */
	if(!replyAS || !encodedInput) {
		LOG("Invalid parameter\n");
		return MA_COMM_INVALID_PARAMETER;
	}
	
	/* Check if encodedInput has at least enough bytes to encoded 2 principal names */
	if(encodedLength < 2 * PRINCIPAL_NAME_LENGTH) {
		LOG("Invalid size\n");
		return MA_COMM_INVALID_PARAMETER;
	}

	result = initReplyAS(replyAS);
	if (result != MA_COMM_SUCCESS) {
		LOG("Init failed\n");
		return MA_COMM_INVALID_STATE;
	}
	
	// Unserialization

	// message code
	encodedOffset = 0;
	if(*encodedInput != REPLY_AS_CODE) {
		return INVALID_PARAMETER;
	}
	encodedOffset += MESSAGE_CODE_LENGTH;

	// cname
	memcpy(replyAS->cname, encodedInput + encodedOffset, sizeof(replyAS->cname));
	encodedOffset += sizeof(replyAS->cname);

	// ticket
	result = setEncodedTicket(&replyAS->ticket, encodedInput + encodedOffset, encodedLength - encodedOffset, &length);
	if(result != MA_COMM_SUCCESS) {
		LOG("Fail to deserialize ticket\n");
		eraseReplyAS(replyAS);
		return MA_COMM_INVALID_STATE;
	}
	encodedOffset += length;

	// enc part
	result = setEncodedEncData(&replyAS->encPart, encodedInput + encodedOffset,  encodedLength - encodedOffset, &length);
	if(result != MA_COMM_SUCCESS) {
		LOG("Fail to deserialize enc data\n");
		eraseReplyAS(replyAS);
		return MA_COMM_INVALID_STATE;
	}
	encodedOffset += length;

	*offset = encodedOffset;

	return MA_COMM_SUCCESS;
}

uint8_t eraseReplyAS(ReplyAS* replyAS) {

	if(!replyAS) {
		return MA_COMM_INVALID_PARAMETER;
	}

	memset_s(replyAS->cname, PRINCIPAL_NAME_LENGTH, 0, PRINCIPAL_NAME_LENGTH);

	eraseTicket(&replyAS->ticket);
	eraseEncData(&replyAS->encPart);

	return MA_COMM_SUCCESS;
}

uint8_t initReplyAS(ReplyAS* replyAS) {
	uint8_t result = MA_COMM_SUCCESS;

	if (!replyAS) {
		return MA_COMM_INVALID_PARAMETER;
	}

	memset(replyAS->cname, 0, PRINCIPAL_NAME_LENGTH);

	result = initTicket(&replyAS->ticket);
	if (result != MA_COMM_SUCCESS) {
		return result;
	}

	result = initEncryptedData(&replyAS->encPart);
	if (result != MA_COMM_SUCCESS) {
		return result;
	}

	return MA_COMM_SUCCESS;
}

void dumpReplyAS(ReplyAS* replyAS, uint8_t indent) {
	if ( (!replyAS) || (!logger_is_log_enabled()) ) {
		return;
	}

	uint8_t i = 0;
	LOG("%*sreplyAS:\n", indent, "");
	LOG("%*scname: ", indent + 1, "");
	for(i = 0; i < PRINCIPAL_NAME_LENGTH; ++i) {
	    LOG("%02x", replyAS->cname[i]);
	}
	LOG("\n");
	dumpTicket(&replyAS->ticket, indent + 1);
	dumpEncryptedData(&replyAS->encPart, indent + 1);
}
