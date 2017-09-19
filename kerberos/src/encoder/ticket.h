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

errno_t setEncodedTicket(Ticket* /* ticket */, uint8_t* /* encodedOutput */, size_t /* encodedLength */, size_t* /* offset */);

errno_t decodeTicket(Ticket* /* ticket */, uint8_t** /* sname */, size_t* /* snameLength */, EncryptedData* /* encData */);
 
errno_t checkTicket(Ticket* /* ticket */);

errno_t eraseTicket(Ticket* /* ticket */);

errno_t copyTicket(Ticket* /* src */, Ticket* /* dst */);
#endif /* TICKET_H_ */
