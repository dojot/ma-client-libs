#include "ticket.h"
#include <stdio.h>

#include "ma_comm_error_codes.h"
#include "logger/logger.h"

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

uint8_t getEncodedTicketOnBuffer(Ticket* ticket,
								 size_t bufferLength,
								 uint8_t* buffer,
								 size_t* offset) {
	uint8_t result = MA_COMM_SUCCESS;
	size_t encDataOffset = 0;

	// Input validation
	if ( (!buffer) || (!offset) ) {
		return MA_COMM_INVALID_PARAMETER;
	}
	result = checkTicket(ticket);
	if(result != MA_COMM_SUCCESS) {
		return MA_COMM_INVALID_PARAMETER;
	}

	//buffer size validation
	size_t encodedLength = 0;
	result = getEncodedLengthTicket(ticket, &encodedLength);
	if(result != MA_COMM_SUCCESS) {
		return MA_COMM_INVALID_PARAMETER;
	}
	if (encodedLength > bufferLength) {
		return MA_COMM_INVALID_PARAMETER;
	}


	// Serializes data to encodedOutput
	*offset = 0;
	memcpy(buffer + *offset, ticket->sname, sizeof(ticket->sname));
	*offset += sizeof(ticket->sname);

	// Get serialiazed version of encrypted data field
	result = getEncodedEncDataOnBuffer(&ticket->encData,
									   bufferLength - *offset,
									   buffer + *offset,
									   &encDataOffset);
	if(result != MA_COMM_SUCCESS) {
		*offset = 0;
		return result;
	}
	*offset += encDataOffset;

	return MA_COMM_SUCCESS;
}

uint8_t setEncodedTicket(Ticket* ticket,
						 uint8_t* encodedInput,
						 size_t encodedLength,
						 size_t* offset) {
	uint8_t result = MA_COMM_SUCCESS;
	size_t encodedOffset = 0;
	size_t encodedDataLength = 0;

	/* Input validation */
	if(!ticket || !encodedInput) {
		return MA_COMM_INVALID_PARAMETER;
	}

	/* It must be bigger than PRINCIPAL_NAME because of the existence of Encrypted Data which must not be null*/
	if(encodedLength <= PRINCIPAL_NAME_LENGTH) {
		return MA_COMM_INVALID_PARAMETER;
	}

	/* Secure remove of any previous information */
	result = initTicket(ticket);
	if (result != MA_COMM_SUCCESS) {
		return MA_COMM_INVALID_STATE;
	}
		
    // Unserialization
	encodedOffset = 0;

	//sname
	memcpy(ticket->sname, encodedInput + encodedOffset, sizeof(ticket->sname));
	encodedOffset += sizeof(ticket->sname);

	//encoded data
	result = setEncodedEncData(&ticket->encData, encodedInput + encodedOffset, encodedLength - encodedOffset, &encodedDataLength);
	if(result != MA_COMM_SUCCESS) {
		eraseTicket(ticket);
		return MA_COMM_INVALID_STATE;
	}
	encodedOffset += encodedDataLength;

	*offset = encodedOffset;

	return MA_COMM_SUCCESS;
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

uint8_t checkTicket(Ticket* ticket) {

	uint8_t result = MA_COMM_SUCCESS;

	if(!ticket) {
		return MA_COMM_INVALID_PARAMETER;
	}
	result = checkEncData(&ticket->encData);

	return result;
}

uint8_t getEncodedLengthTicket(Ticket* ticket, size_t* length) {

	int8_t result = MA_COMM_SUCCESS;

	if (!ticket || !length) {
		return MA_COMM_INVALID_PARAMETER;
	}

	result = getEncodedLengthEncData(&ticket->encData, length);
	if (result != MA_COMM_SUCCESS) {
		return MA_COMM_INVALID_STATE;
	}
    *length += PRINCIPAL_NAME_LENGTH;

	return MA_COMM_SUCCESS;
}

uint8_t eraseTicket(Ticket* ticket) {
	
	// Input validation
	if(!ticket) {
		return MA_COMM_INVALID_PARAMETER;
	}

	eraseEncData(&ticket->encData);

	memset_s(ticket->sname, sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH, 0, sizeof(uint8_t) *PRINCIPAL_NAME_LENGTH);

	return MA_COMM_SUCCESS;
}

uint8_t copyTicket(Ticket* src, Ticket *dst) {

	uint8_t result = MA_COMM_SUCCESS;
	
	// Input validation
	if(!dst || !src) {
		return MA_COMM_INVALID_PARAMETER;
	}
	initTicket(dst);

	memcpy(dst->sname, src->sname, sizeof(src->sname));
	result = copyEncData(&src->encData, &dst->encData);

	return result;
}

uint8_t initTicket(Ticket *ticket) {
	uint8_t result = MA_COMM_SUCCESS;

	if (!ticket) {
		return MA_COMM_INVALID_PARAMETER;
	}

	result = initEncryptedData(&ticket->encData);
	if (result != MA_COMM_SUCCESS) {
		return result;
	}

	memset(ticket->sname, 0 , PRINCIPAL_NAME_LENGTH);

	return MA_COMM_SUCCESS;
}

void dumpTicket(Ticket *ticket, uint8_t indent) {

	if ( (!ticket) || (!logger_is_log_enabled()) ) {
		return;
	}

	uint8_t i = 0;
	LOG("%*sTicket:\n", indent, "");
	LOG("%*ssname: ", indent + 1, "");
	for(i = 0; i < PRINCIPAL_NAME_LENGTH; ++i) {
	    LOG("%02x", ticket->sname[i]);
	}
	LOG("\n");
	dumpEncryptedData(&ticket->encData, indent + 1);
}
