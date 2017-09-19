#ifndef REPLY_AS_
#define REPLY_AS_

#include "authenticator.h"
#include "constants.h"
#include "errno.h"
#include "ticket.h"

#include <stdint.h>
#include <stdlib.h>

#define REPLY_AS_CODE	0x0B

typedef struct {
	uint8_t cname[PRINCIPAL_NAME_LENGTH];
	Ticket ticket;
	EncryptedData encPart;
} ReplyAS;

errno_t encodeReplyAS(ReplyAS* /* replyAS */, uint8_t* /* cname */, size_t /* cnameLength */, Ticket* /* ticket */, EncryptedData* /* encPart */);

errno_t getEncodedReplyAS(ReplyAS* /* replyAS */, uint8_t** /* encodedOutput */, size_t* /* encodedLength */);

errno_t setEncodedReplyAS(ReplyAS* /* replyAS */, uint8_t* /* encodedInput */, size_t /* encodedLength */, size_t* /* offset */);

errno_t decodeReplyAS(ReplyAS* /* replyAS */, uint8_t** /* cname */, size_t* /* cnameLength */, Ticket* /* ticket */, EncryptedData* /* encPart */);

errno_t checkReplyAS(ReplyAS* /* replyAS */);

errno_t eraseReplyAS(ReplyAS* /* replyAS */);
#endif /* REPLY_AS_ */
