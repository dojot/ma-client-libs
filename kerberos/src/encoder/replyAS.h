#ifndef REPLY_AS_
#define REPLY_AS_

#include "authenticator.h"
#include "constants.h"
#include "errno.h"
#include "ticket.h"

#include <stdint.h>
#include <stdlib.h>

#define REPLY_AS_CODE    0x0B

typedef struct {
    uint8_t cname[PRINCIPAL_NAME_LENGTH];
    Ticket ticket;
    EncryptedData encPart;
} ReplyAS;

uint8_t setEncodedReplyAS(ReplyAS* replyAS,
                          uint8_t* encodedInput,
                          size_t encodedLength,
                          size_t* offset);

uint8_t initReplyAS(ReplyAS* replyAS);

uint8_t eraseReplyAS(ReplyAS* replyAS);

void dumpReplyAS(ReplyAS* replyAS, uint8_t indent);
#endif /* REPLY_AS_ */
