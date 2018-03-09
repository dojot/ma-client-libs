#include "requestAP.h"
#include "logger/logger.h"

#include "ma_comm_error_codes.h"

errno_t encodeRequestAP(RequestAP* requestAp, Ticket* ticket, EncryptedData* encryptedData)
{
	errno_t result;

	/* Input validation */
	if(requestAp == NULL || ticket == NULL || encryptedData == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkTicket(ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = checkEncData(encryptedData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Ensure structure is clean */
	result = memset_s(requestAp, sizeof(RequestAP), 0, sizeof(RequestAP));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Copy individual fields */
	result = copyTicket(ticket, &requestAp->ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = copyEncData(encryptedData, &requestAp->encryptedData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = checkRequestAP(requestAp);
FAIL:
	return result;
}

uint8_t getEncodedRequestAP(RequestAP* requestAp,
							uint8_t** encodedOutput,
							size_t* encodedLength,
							uint8_t* sessionId,
							size_t sessionIdLength) {
	uint8_t result = MA_COMM_SUCCESS;
	size_t offset = 0;
	size_t encodedTicketLength = 0;
	size_t encodedEncryptedDataLength = 0;

	/* Input validation */
	if(!requestAp || !encodedOutput || !encodedLength) {
		return MA_COMM_INVALID_PARAMETER;
	}

	// retrieve encoded lengths and compute it
	result = getEncodedLengthTicket(&requestAp->ticket, &encodedTicketLength);
	if (result != MA_COMM_SUCCESS) {
		return MA_COMM_INVALID_PARAMETER;
	}
	result = getEncodedLengthEncData(&requestAp->encryptedData, &encodedEncryptedDataLength);
	if (result != MA_COMM_SUCCESS) {
		return MA_COMM_INVALID_PARAMETER;
	}

	*encodedLength = MESSAGE_CODE_LENGTH +
					 encodedEncryptedDataLength +
					 encodedTicketLength +
					 sessionIdLength;

	*encodedOutput = (uint8_t*) malloc(*encodedLength);
	if (!*encodedOutput) {
		*encodedLength = 0;
		return MA_COMM_OUT_OF_MEMORY;
	}

	//Serialization order:
	// sessionID
	// operation code
	// ticket
	// encrypted data
	offset = 0;
	memcpy(*encodedOutput, sessionId, sessionIdLength);
	offset += sessionIdLength;
	*(*encodedOutput + offset) = REQUEST_AP_CODE;
	offset += MESSAGE_CODE_LENGTH;

	result = getEncodedTicketOnBuffer(&requestAp->ticket,
									  *encodedLength - offset,
									  *encodedOutput + offset,
									  &encodedTicketLength);
	if (result != MA_COMM_SUCCESS) {
		result = MA_COMM_INVALID_STATE;
		goto FAIL;
	}
	offset += encodedTicketLength;
	result = getEncodedEncDataOnBuffer(&requestAp->encryptedData,
									  *encodedLength - offset,
									  *encodedOutput + offset,
									  &encodedEncryptedDataLength);
	if (result != MA_COMM_SUCCESS) {
		result = MA_COMM_INVALID_STATE;
		goto FAIL;
	}
	offset += encodedEncryptedDataLength;

	//just make sure everything matches
	if (offset != *encodedLength) {
		result = MA_COMM_INVALID_STATE;
		goto FAIL;
	}

	return MA_COMM_SUCCESS;

// fail flow
FAIL:
	*encodedLength = 0;
	free(*encodedOutput);
	*encodedOutput = NULL;
	return result;
}


errno_t setEncodedRequestAP(RequestAP* requestAp, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
	errno_t result;
	size_t ticketLength, authLength;
	
	/* Input validation */
	if(requestAp == NULL || encodedInput == NULL || offset == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Unserialization */
	*offset = 0;
	if(*encodedInput != REQUEST_AP_CODE) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	*offset += MESSAGE_CODE_LENGTH;
	result = setEncodedTicket(&requestAp->ticket, encodedInput + *offset, encodedLength, &ticketLength);
	if(result != SUCCESSFULL_OPERATION) { 
		goto FAIL;
	} else if(ticketLength > encodedLength) {
		result = INVALID_STATE;
		goto FAIL;
	}
	*offset += ticketLength;
	result = setEncodedEncData(&requestAp->encryptedData, encodedInput + *offset, encodedLength - ticketLength, &authLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	} else if(ticketLength + authLength > encodedLength) {
		result = INVALID_STATE;
		goto FAIL;
	}
	*offset += authLength;
	result = checkRequestAP(requestAp);
FAIL:
	return result;
}


errno_t decodeRequestAP(RequestAP* requestAp, Ticket* ticket, EncryptedData* encryptedData)
{
	errno_t result;

	/* Input validation */
	result = checkRequestAP(requestAp);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	if(ticket == NULL || encryptedData == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Copy individual fields */
	result = copyTicket(&requestAp->ticket, ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = copyEncData(&requestAp->encryptedData, encryptedData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
FAIL:
	return result;
}


errno_t checkRequestAP(RequestAP* requestAp)
{
	errno_t result;

	/* Input validation */
	if(requestAp == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkTicket(&requestAp->ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = checkEncData(&requestAp->encryptedData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

uint8_t initRequestAP(RequestAP* requestAP) {
	uint8_t result = MA_COMM_SUCCESS;

	result = initTicket(&requestAP->ticket);
	if (result != MA_COMM_SUCCESS) {
		return result;
	}
	result = initEncryptedData(&requestAP->encryptedData);

	return result;
}

uint8_t eraseRequestAP(RequestAP* requestAp) {
	errno_t result;

	// Input validation
	if(!requestAp) {
		return MA_COMM_INVALID_PARAMETER;
	}

	// Secure erase individual fields */
	eraseTicket(&requestAp->ticket);
	eraseEncData(&requestAp->encryptedData);
	
	return MA_COMM_INVALID_PARAMETER;
}

void dumpRequestAP(RequestAP* requestAp, uint8_t indent) {
	if ( (!requestAp) || (!logger_is_log_enabled()) ) {
		return;
	}

	LOG("%*sRequestAP:\n", indent, "");
	dumpTicket(&requestAp->ticket, indent + 1);
	dumpEncryptedData(&requestAp->encryptedData, indent + 1);
}
