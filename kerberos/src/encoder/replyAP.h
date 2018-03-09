#ifndef REPLY_AP_
#define REPLY_AP_

#include "encryptedData.h"

#include <stdint.h>

#define REPLY_AP_CODE 0x0f

typedef struct {
	EncryptedData encData;
} ReplyAP;

errno_t encodeReplyAP(ReplyAP* /* replyAp */, EncryptedData* /* encData */);
errno_t getEncodedReplyAP(ReplyAP* /* replyAp */, uint8_t** /* encodedOutput */, size_t* /* encodedLength */);
errno_t setEncodedReplyAP(ReplyAP* /* replyAp */, uint8_t* /* encodedInput */,  size_t /* encodedLength */, size_t* /* offset */);
errno_t decodeReplyAP(ReplyAP* /* replyAp */, EncryptedData* /* encData */);
errno_t checkReplyAP(ReplyAP* /* replyAp */);

uint8_t initReplyAP(ReplyAP* replyAp);
uint8_t eraseReplyAP(ReplyAP* replyAp);

#endif /* REPLY_AP_ */
