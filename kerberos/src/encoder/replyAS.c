#include "replyAS.h"

#include <stdio.h>

errno_t encodeReplyAS(ReplyAS* replyAS, uint8_t* cname, size_t cnameLength, Ticket* ticket, EncryptedData* encPart)
{
    printf("encodeReplyAS\n");
	errno_t result;
	
	/* Input validation */
	if(replyAS == NULL || cname == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(cnameLength != PRINCIPAL_NAME_LENGTH) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkTicket(ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = checkEncData(encPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Ensure structure is clean */
	result = memset_s(replyAS, sizeof(ReplyAS), 0, sizeof(ReplyAS));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Copy individual fields */	
	memcpy(replyAS->cname, cname, cnameLength);
	result = copyTicket(ticket, &replyAS->ticket);	
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = copyEncData(encPart, &replyAS->encPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = checkReplyAS(replyAS);
FAIL:
	return result;
}

errno_t getEncodedReplyAS(ReplyAS* replyAS, uint8_t** encodedOutput, size_t* encodedLength)
{
    printf("getEncodedReplyAS\n");
	errno_t result;
	uint8_t *encodedTicket, *encodedData;
	size_t offset, encodedTicketLength, encodedDataLength; 

	/* Input validation */
	result = checkReplyAS(replyAS);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(encodedOutput == NULL || encodedLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Serialize individual fields */
	result = getEncodedTicket(&replyAS->ticket, &encodedTicket, &encodedTicketLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = getEncodedEncData(&replyAS->encPart, &encodedData, &encodedDataLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_ENCDATA;
	}

	/* Copy serialized fields to output */
	*encodedLength = MESSAGE_CODE_LENGTH + encodedDataLength + encodedTicketLength + sizeof(replyAS->cname);
	*encodedOutput = (uint8_t*) malloc(*encodedLength);
	if(*encodedOutput == NULL) {
		result = INVALID_STATE;
		goto FAIL_ALLOC;
	}

	offset = 0;
	*(*encodedOutput + offset) = REPLY_AS_CODE;
	offset += MESSAGE_CODE_LENGTH;
	memcpy(*encodedOutput + offset, replyAS->cname, sizeof(replyAS->cname));
	offset += sizeof(replyAS->cname);
	memcpy(*encodedOutput + offset, encodedTicket, encodedTicketLength);
	offset += encodedTicketLength;
	memcpy(*encodedOutput + offset, encodedData, encodedDataLength);
	offset += encodedDataLength;

FAIL_ALLOC:
	result |= memset_s(encodedData, encodedDataLength, 0, encodedDataLength);
	free(encodedData);
FAIL_ENCDATA:
	result |= memset_s(encodedTicket, encodedTicketLength, 0, encodedTicketLength);
	free(encodedTicket);
FAIL:
	return result;	

}

/* Generates ReplyAS from encoded input */
errno_t setEncodedReplyAS(ReplyAS* replyAS, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
    printf("setEncodedReplyAS\n");
	errno_t result;
	size_t encodedOffset, length;

	/* Input validation */
	if(replyAS == NULL || encodedInput == NULL) {
	    printf("input validation failed\n");
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Check if encodedInput has at least enough bytes to encoded 2 principal names */
	if(encodedLength < 2 * PRINCIPAL_NAME_LENGTH) {
		result = INVALID_PARAMETER;
		printf("encodedInput does not have enough bytes\n");
		goto FAIL;
	}
	
	/* Unserialization */
	encodedOffset = 0;
	if(*encodedInput != REPLY_AS_CODE) {
		result = INVALID_PARAMETER;
		printf("Unserialization 1 failed\n");
		goto FAIL;
	}
	encodedOffset += MESSAGE_CODE_LENGTH;
	memcpy(replyAS, encodedInput + encodedOffset, sizeof(replyAS->cname));
	encodedOffset += sizeof(replyAS->cname);

	result = setEncodedTicket(&replyAS->ticket, encodedInput + encodedOffset, encodedLength - encodedOffset, &length);
	encodedOffset += length;
	if(result != SUCCESSFULL_OPERATION || encodedOffset > encodedLength) {
	    printf("Unserialization 2 failed\n");
		goto FAIL;
	}

	result = setEncodedEncData(&replyAS->encPart, encodedInput + encodedOffset,  encodedLength - encodedOffset, &length);
	encodedOffset += length;
	if(result != SUCCESSFULL_OPERATION || encodedOffset > encodedLength) {
	    printf("Unserialization 3 failed\n");
		goto FAIL;
	}

	*offset = encodedOffset;

FAIL:
	return result;
}

errno_t decodeReplyAS(ReplyAS* replyAS, uint8_t** cname, size_t* cnameLength, Ticket* ticket, EncryptedData* encPart)
{
    printf("decodeReplyAS\n");
	errno_t result;

	/* Input validation */
	result = checkReplyAS(replyAS);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(cname == NULL || cnameLength == NULL || ticket == NULL || encPart == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	
	/* Copy individual fields */
	*cname = (uint8_t*) malloc(sizeof(replyAS->cname));
	if(cname == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}
	*cnameLength = PRINCIPAL_NAME_LENGTH;
	memcpy(*cname, replyAS->cname, sizeof(replyAS->cname));	
	
	result = copyTicket(&replyAS->ticket, ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_TICKET;
	}

	result = copyEncData(&replyAS->encPart, encPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_ENCDATA;
	}
	goto SUCCESS;
FAIL_ENCDATA:
FAIL_TICKET:
	result |= memset_s(cname, sizeof(replyAS->cname), 0, sizeof(replyAS->cname));
	free(*cname);
FAIL:
SUCCESS:
	return result;
}

errno_t checkReplyAS(ReplyAS* replyAs) 
{
    printf("checkReplyAS\n");
	errno_t result;

	/* Input validation */
	if(replyAs == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Check if ticket data is valid */
        result = checkTicket(&replyAs->ticket);
        if(result != SUCCESSFULL_OPERATION) {
       		result = INVALID_PARAMETER;
        	goto FAIL;
        }
                                                 
        /* Check if encrypted data is valid */
        result = checkEncData(&replyAs->encPart);
        if(result != SUCCESSFULL_OPERATION) {
        	result = INVALID_PARAMETER;
        	goto FAIL;
        }

FAIL:
	return result;
}


errno_t eraseReplyAS(ReplyAS* replyAS)
{
    printf("eraseReplyAS\n");
	errno_t result;

	result = checkReplyAS(replyAS);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Secure erase */
	result = memset_s(replyAS->cname, sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH, 0, sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = eraseTicket(&replyAS->ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = eraseEncData(&replyAS->encPart);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

FAIL:
	return result;
}
