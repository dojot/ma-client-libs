#include "requestAP.h"

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

errno_t getEncodedRequestAP(RequestAP* requestAp, uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;
	uint8_t *encodedTicket, *encodedEncryptedData;
	size_t offset, encodedTicketLength, encodedEncryptedDataLength;

	/* Input validation */
	if(requestAp == NULL || encodedOutput == NULL || encodedLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkRequestAP(requestAp);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Serialize individual fields */
	result = getEncodedTicket(&requestAp->ticket, &encodedTicket, &encodedTicketLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = getEncodedEncData(&requestAp->encryptedData, &encodedEncryptedData, &encodedEncryptedDataLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Copy serialized fields to output */
	*encodedLength = MESSAGE_CODE_LENGTH + encodedEncryptedDataLength + encodedTicketLength;
	*encodedOutput = (uint8_t*) malloc(*encodedLength);
	if(*encodedOutput == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}
	
	offset = 0;
	**encodedOutput = REQUEST_AP_CODE;
	offset += MESSAGE_CODE_LENGTH;
	memcpy(*encodedOutput + offset, encodedTicket, encodedTicketLength);
	offset += encodedTicketLength;
	memcpy(*encodedOutput + offset, encodedEncryptedData, encodedEncryptedDataLength);
	offset += encodedEncryptedDataLength;

	result = SUCCESSFULL_OPERATION;
FAIL:
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


errno_t eraseRequestAP(RequestAP* requestAp)
{
	errno_t result;

	/* Input validation */
	result = checkRequestAP(requestAp);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Secure erase individual fields */
	result = eraseTicket(&requestAp->ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = eraseEncData(&requestAp->encryptedData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}


