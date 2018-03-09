#ifndef TICKET_H_
#define TICKET_H_

#include "constants.h"
#include "encryptedData.h"
#include "errno.h"

typedef struct {
        uint8_t sname[PRINCIPAL_NAME_LENGTH];
        EncryptedData encData; /* EncTicketPart */
} Ticket;

errno_t encodeTicket(Ticket* /* ticket */, uint8_t* /* sname */, size_t /* snameLength */, EncryptedData* /* encData */);

errno_t getEncodedTicket(Ticket* /* ticket */, uint8_t** /* encodedOutput */, size_t* /* encodedLength */);

uint8_t setEncodedTicket(Ticket* /* ticket */, uint8_t* /* encodedOutput */, size_t /* encodedLength */, size_t* /* offset */);

errno_t decodeTicket(Ticket* /* ticket */, uint8_t** /* sname */, size_t* /* snameLength */, EncryptedData* /* encData */);
 
uint8_t checkTicket(Ticket* /* ticket */);

uint8_t getEncodedTicketOnBuffer(Ticket* ticket,
								 size_t bufferLength,
								 uint8_t* buffer,
								 size_t* offset);

uint8_t getEncodedLengthTicket(Ticket* ticket, size_t* length);

uint8_t eraseTicket(Ticket*  ticket);

uint8_t copyTicket(Ticket* src, Ticket* dst);

uint8_t initTicket(Ticket *ticket);

void dumpTicket(Ticket *ticket, uint8_t indent);

#endif /* TICKET_H_ */
