#ifndef KERBEROS_PROTOCOL_
#define KERBEROS_PROTOCOL_

#include "../encoder/authenticator.h"
#include "../encoder/error.h"
#include "../encoder/replyAP.h"
#include "../encoder/replyAS.h"
#include "../encoder/requestAS.h"
#include "../encoder/requestAP.h"
#include "../encoder/sessionKey.h"
#include "../encoder/errno.h"
#include "../encoder/encKdcRepPart.h"
#include "../encoder/constants.h"
#include "communication.h"
#include "secure-util.h"
#include "unique.h"

#include <stdio.h>
#include <stdint.h>

typedef enum { 
	NOT_INITIALIZED, 
	WAIT_REPLY_AS,
	WAIT_REPLY_AP,
	ESTABLISHED_CHANNEL
} ProtocolState;

/* This defines must be directly manipulated by the generators if they need to be modified */
#define SHARED_KEY_LENGTH	32
#define TAG_LEN			16
#define SECURE_CHANNEL_OK	0
#define SECURE_CHANNEL_FAILED	1
#define SESSION_ID_LENGTH 32


/* All the necessary information to establish a secure channel is kept in the Kerberos context */
typedef struct 
{
 	uint8_t *host;          /* IP Address of the Kerberos server */
	uint8_t* uriRequestAS;	/* URI of Kerberos Request AS rest interface. */
	uint8_t* uriRequestAP;	/* URI of Kerberos Request AP rest interface. */
	void (*callback)(int);
	ProtocolState state;		/* State of the Kerberos protocol */
	uint8_t* sharedKey;			/* Pre-shared key with Kerberos AS */
	uint8_t tagLen;				/* Size of the tags */
	uint8_t cname[PRINCIPAL_NAME_LENGTH];	/* ID of this application instance */
	uint8_t sname[PRINCIPAL_NAME_LENGTH];	/* ID of the server application */
	uint8_t nonce[NONCE_LENGTH];
	Ticket ticket;
	SessionKeys sessionKeys;	/* Parameters used to create a secure channel */
	uint8_t timestamp[TIME_LENGTH];
	uint8_t offset[TIME_LENGTH];
	errno_t errorCode;
	uint8_t sessionId[SESSION_ID_LENGTH];    /*The session information generated after RequestAS*/
} KerberosContext;

/* Executes the full Kerberos handshake */
errno_t executeKerberosHandshake();

/** Sets the callback function to be called after an error occurs or after the secure channel is closed. */
errno_t setCallback(void (*callback)(int));

/** Initializes the kerberos structure. */
errno_t initializeKerberos(uint8_t* host, uint8_t hostLength, uint8_t* uriRequestAS, uint8_t requestASLength, uint8_t* uriRequestAP, uint8_t requestAPLength);

/* Initializes the URI and host parameters. */
errno_t initKerberosURIs(uint8_t* /* host */, uint8_t /* hostLength */, uint8_t* /* uriRequestAS */, uint8_t /* requestASLength */, uint8_t* /* uriRequestAP */, uint8_t /* requestAPLength */);

/* Initializes the Kerberos context */
errno_t initContext(uint8_t* /* cname */, uint8_t /* cnameLength */, uint8_t* /* sname */, uint8_t /* snameLength */, 
			uint8_t* /* sharedKey */, uint8_t /* keyLength */); 

/* Sends the first message to Kerberos AS */
errno_t doRequestAS(uint8_t** /* encodedOutput */, size_t* /* encodedLength */);

/* Sends the ticket and an authenticator, which is a encrypted data used to authenticate the flash component to the application server */
errno_t doRequestAP(uint8_t** /* encodedOutput */, size_t* /* encodedLength */);

/* Verifies the reply from the AS */
errno_t verifyReplyAS(uint8_t* /* encodedInput */, size_t /* encodedLength */);

/* Verifies the reply from the application server. Reply from application should contain information to authenticate the application to the flash component */
errno_t verifyReplyAP(uint8_t* /* encodedInput */, size_t /* encodedLength */);

/* Upon receipt of a message, executes the action related to the current state */
void processState(uint8_t* /* encodedInput */, size_t /* encodedLength */);

void processReply();

/* Updates the state machine by performing a transition */
void goNextState();

/* Check if the received message is an error */
void checkIfError(uint8_t* encodedInput, size_t encodedInputLength, uint8_t *isError);

/* Check if any error has occurred. Client application doesn't know the meaning. */
uint8_t hasErrorOccurred();

/* Check if secure channel is open */
uint8_t isSecureChannelOpen();

#endif /* KERBEROS_PROTOCOL_ */
