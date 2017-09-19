#include "ticket.h"
#include <stdio.h>
errno_t encodeTicket(Ticket* ticket, uint8_t* sname, size_t snameLength, EncryptedData* encData)
{
	errno_t result;

	/* Input validation */
	if(ticket == NULL || sname == NULL || encData == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(snameLength != PRINCIPAL_NAME_LENGTH) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkEncData(encData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Ensure structure is clean */
        result = memset_s(ticket, sizeof(Ticket), 0, sizeof(Ticket));
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL;
        }
	
	/* Initialize the structure with the data */
	memcpy(ticket->sname, sname, sizeof(ticket->sname));
	result = copyEncData(encData, &ticket->encData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = checkTicket(ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

FAIL:
	return result;	

}

errno_t getEncodedTicket(Ticket* ticket, uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;
	size_t encDataLength, offset;
	uint8_t *encodedEncData;	

	/* Input validation */
	result = checkTicket(ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(encodedOutput == NULL || encodedLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Serializes data to encodedOutput */

	/* Get serialiazed version of encrypted data field */
	result = getEncodedEncData(&ticket->encData, &encodedEncData, &encDataLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Allocate space to encoded output */
	*encodedOutput = (uint8_t*) malloc(encDataLength + PRINCIPAL_NAME_LENGTH);
        if(*encodedOutput == NULL) {
                result = INVALID_STATE;
                goto FAIL;
        }
		
	offset = 0;
	memcpy(*encodedOutput + offset, ticket->sname, sizeof(ticket->sname));
	offset += sizeof(ticket->sname);	
	memcpy(*encodedOutput + offset, encodedEncData, encDataLength);
	offset += encDataLength; 
	*encodedLength = offset;

FAIL:
	result |= memset_s(encodedEncData, encDataLength, 0, encDataLength);
	free(encodedEncData);
	return result;
}

errno_t setEncodedTicket(Ticket* ticket, uint8_t* encodedInput, size_t encodedLength, size_t* offset)
{
	errno_t result;
	size_t encodedOffset, encodedDataLength;

	/* Input validation */
	if(ticket == NULL || encodedInput == NULL) {
		result = INVALID_PARAMETER;
	}

	/* It must be bigger than PRINCIPAL_NAME because of the existence of Encrypted Data which must not be null*/
	if(encodedLength <= PRINCIPAL_NAME_LENGTH) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Secure remove of any previous information */
	result = memset_s(ticket, sizeof(Ticket), 0, sizeof(Ticket));
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL;
        }
		
        /* Unserialization */
	encodedOffset = 0;
	memcpy(ticket->sname, encodedInput + encodedOffset, sizeof(ticket->sname));
	encodedOffset += sizeof(ticket->sname);
	result = setEncodedEncData(&ticket->encData, encodedInput + encodedOffset, encodedLength - encodedOffset, &encodedDataLength);
	encodedOffset += encodedDataLength;
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	*offset = encodedOffset;
	result = checkTicket(ticket);
FAIL:
	return result;	
}



errno_t decodeTicket(Ticket* ticket, uint8_t** sname, size_t* snameLength, EncryptedData* encData)
{
	errno_t result;
	
	/* Input validation */
	result = checkTicket(ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(sname == NULL || snameLength == NULL || encData == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*sname = (uint8_t*) malloc(sizeof(ticket->sname));
	if(*sname == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}

	*snameLength = PRINCIPAL_NAME_LENGTH;
	memcpy(*sname, ticket->sname, sizeof(ticket->sname));
	result = copyEncData(&ticket->encData, encData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
FAIL:
	return result;	
}

errno_t checkTicket(Ticket* ticket)
{
	errno_t result;

	if(ticket == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	result = checkEncData(&ticket->encData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

FAIL:
	return result;
}

errno_t eraseTicket(Ticket* ticket) 
{
	errno_t result;
	
	/* Input validation */
	result = checkTicket(ticket);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = eraseEncData(&ticket->encData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = memset_s(ticket, sizeof(Ticket), 0, sizeof(Ticket));	
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
FAIL:
	return result;
}

errno_t copyTicket(Ticket* src, Ticket *dst)
{
		
	errno_t result;
	
	/* Input validation */
	if(dst == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = checkTicket(src);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	memcpy(dst->sname, src->sname, sizeof(src->sname));
	result = copyEncData(&src->encData, &dst->encData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
FAIL:
	return result;	
}
