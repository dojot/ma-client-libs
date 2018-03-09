#ifndef REQUEST_AP_
#define REQUEST_AP_

#include "encryptedData.h"
#include "constants.h"
#include "ticket.h"

#define REQUEST_AP_CODE	0x0e

typedef struct {
	Ticket ticket;
	EncryptedData encryptedData;
} RequestAP;

errno_t encodeRequestAP(RequestAP* /* requestAp */, Ticket* /* ticket */, EncryptedData* /* encryptedData */);

errno_t getEncodedRequestAP(RequestAP* /* requestAp */, uint8_t** /* encodedOutput */, size_t* /* encodedLength */, uint8_t* /* sessionId */, size_t /* sessionIdLength */);

errno_t setEncodedRequestAP(RequestAP* /* requestAp */, uint8_t* /* encodedInput */, size_t /* encodedLength */, size_t* /* offset */);

errno_t decodeRequestAP(RequestAP* /* requestAp */, Ticket* /* ticket */, EncryptedData* /* encryptedData */);

errno_t checkRequestAP(RequestAP* /* requestAp */);

uint8_t initRequestAP(RequestAP* requestAP);

uint8_t eraseRequestAP(RequestAP* requestAp);

void dumpRequestAP(RequestAP* requestAp, uint8_t indent);

#endif /* REQUEST_AP_ */
