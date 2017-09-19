#ifndef ENC_TICKET_PART_
#define ENC_TICKET_PART_

#include "errno.h"
#include "constants.h"
#include "sessionKey.h"

#include <stdlib.h>

typedef struct {
        SessionKeys sk;
        uint8_t cname[PRINCIPAL_NAME_LENGTH];
        uint8_t authtime[TIME_LENGTH];
        uint8_t endtime[TIME_LENGTH];
} EncTicketPart;

errno_t encodeEncTicketPart(EncTicketPart* /* encTicketPart */, SessionKeys* /* sk */, uint8_t* /* cname */, size_t /* cnameLength */,
				uint8_t* /* authtime */, size_t /* authtimeLength */, uint8_t* /* endtime */, size_t /* endtimeLength */);

errno_t getEncodedEncTicketPart(EncTicketPart* /* encTicketPart */, uint8_t** /* encodedOutput */, size_t* /* encodedLength */);
errno_t setEncodedEncTicketPart(EncTicketPart* /* encTicketPart */, uint8_t* /* encodedOutput */, size_t /* encodedLength */, size_t* /* offset */);

errno_t decodeEncTicketPart(EncTicketPart* /* encTicketPart */, SessionKeys* /* sk */, uint8_t** /* cname */, uint8_t* /* cnameLength */,
			uint8_t** /* authtime */, size_t* /* authtimeLength */, uint8_t** /* endtime */, size_t* /* endtimeLength */);

errno_t checkEncTicketPart(EncTicketPart* /* encTicketPart */);

errno_t eraseEncTicketPart(EncTicketPart* /* encTicketPart */);

#endif /* ENC_TICKET_PART */
