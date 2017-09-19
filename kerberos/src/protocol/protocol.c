#include "protocol.h"

static KerberosContext kerberosCtx;

/** Sets the callback function to be called after an error occurs or after the secure channel is closed. */
errno_t setCallback(void (*callback)(int)) {
	kerberosCtx.callback = callback;
	return 0;
}

/** Initialize the kerberos request URIs and the host. */
errno_t initKerberosURIs(uint8_t* host, uint8_t hostLength, uint8_t* uriRequestAS, uint8_t requestASLength, uint8_t* uriRequestAP, uint8_t requestAPLength)
{
	errno_t result;

	/** Input validation. */
	if(host == NULL || uriRequestAS == NULL || uriRequestAP == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

   	if(hostLength == 0 || requestASLength == 0 || requestAPLength == 0) {
		result = INVALID_PARAMETER;
   		goto FAIL;
   	}
   	/* Initializes the IP address of the Kerberos server */
	/* It is a little different from flash. Check it!*/
	kerberosCtx.host = malloc(sizeof(uint8_t) * (hostLength + 1));
	if(kerberosCtx.host == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}
	strcpy(kerberosCtx.host, host);
	
	/* Initializes the rest address of the request AS. */
	kerberosCtx.uriRequestAS = malloc(sizeof(uint8_t) * (requestASLength + 1));
	if(kerberosCtx.uriRequestAS == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}
	strcpy(kerberosCtx.uriRequestAS, uriRequestAS);
	
	/* Initializes the rest address of the request AP. */
	kerberosCtx.uriRequestAP = malloc(sizeof(uint8_t) * (requestAPLength + 1));
	if(kerberosCtx.uriRequestAP == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}
	strcpy(kerberosCtx.uriRequestAP, uriRequestAP);
	result = SUCCESSFULL_OPERATION;
	goto SUCCESS;

FAIL:
	result |= memset_s(kerberosCtx.host, sizeof(uint8_t) * (hostLength + 1), 0, sizeof(uint8_t) * (hostLength + 1));
	result |= memset_s(kerberosCtx.uriRequestAS, sizeof(uint8_t) * (requestASLength + 1), 0, sizeof(uint8_t) * (requestASLength + 1));
	result |= memset_s(kerberosCtx.uriRequestAP, sizeof(uint8_t) * (requestAPLength + 1), 0, sizeof(uint8_t) * (requestAPLength + 1));
	free(kerberosCtx.host);
	free(kerberosCtx.uriRequestAS);
	free(kerberosCtx.uriRequestAP);
SUCCESS:
	return result;

}

/** Initializes the kerberos structure. */
errno_t initializeKerberos(uint8_t* host, uint8_t hostLength, uint8_t* uriRequestAS, uint8_t requestASLength, uint8_t* uriRequestAP, uint8_t requestAPLength)
{
	errno_t result;

	/* Initializes the kerberos context */
	uint8_t sharedKey[] = SHARED_KEY;
	uint8_t idComponent[] = FLASH_ID;
	uint8_t idServerApp[] = SERVER_ID;

	/* Initializing the random number generator. */
	srand(time(NULL));
	result = initKerberosURIs(host, hostLength, uriRequestAS, requestASLength, uriRequestAP, requestAPLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}	

	result = initContext(idComponent, PRINCIPAL_NAME_LENGTH, idServerApp, PRINCIPAL_NAME_LENGTH, sharedKey, KEY_LENGTH);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

/* Executes the full Kerberos handshake */
errno_t executeKerberosHandshake()
{
	processState(NULL, 0);
}

/* Initializes the Kerberos context */
errno_t initContext(uint8_t* cname, uint8_t cnameLength, uint8_t* sname, uint8_t snameLength, 
			uint8_t* sharedKey, uint8_t keyLength) 
{
	errno_t result;

	/* Input validation */
	if(cname == NULL || sname == NULL || sharedKey == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	if(cnameLength != PRINCIPAL_NAME_LENGTH || snameLength != PRINCIPAL_NAME_LENGTH || keyLength != KEY_LENGTH) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
   

	/* Initializes the Kerberos context variables */
	kerberosCtx.state = NOT_INITIALIZED;
	/* Initializes the component id, half of it is determined by the server, and the other half is randomly generated */
	memcpy(kerberosCtx.cname, cname, sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH / 2);
	result = generateRandom(kerberosCtx.cname + sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH / 2, sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH / 2);
	
	memcpy(kerberosCtx.sname, sname, sizeof(uint8_t) * PRINCIPAL_NAME_LENGTH);
	/* Biggest tag size possible */
	kerberosCtx.tagLen = 128;
	
	/* Get secure random number to be the nonce */
	result = generateRandom(kerberosCtx.nonce, NONCE_LENGTH);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	kerberosCtx.sharedKey = (uint8_t*) malloc(sizeof(uint8_t) * KEY_LENGTH);
	if(kerberosCtx.sharedKey == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}
	memcpy(kerberosCtx.sharedKey, sharedKey, sizeof(uint8_t) * KEY_LENGTH);
	
	/* No errors should have occurred until this moment */
	kerberosCtx.errorCode = SUCCESSFULL_OPERATION;
	
	/* Until here we don't have a ticket, therefore we can't fill it */
	result = memset_s(&kerberosCtx.ticket, sizeof(Ticket), 0, sizeof(Ticket));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_SK;
	}
	goto SUCCESS;

FAIL_SK:
	result |= memset_s(kerberosCtx.sharedKey, sizeof(uint8_t) * KEY_LENGTH, 0, sizeof(uint8_t) * KEY_LENGTH);
	free(kerberosCtx.sharedKey);
FAIL:
	result |= memset_s(&kerberosCtx, sizeof(KerberosContext), 0, sizeof(KerberosContext));
SUCCESS:
	return result;
}

void processError() 
{
	kerberosCtx.state = NOT_INITIALIZED;
	kerberosCtx.errorCode = NETWORK_ERROR;
}		

void processReply(size_t encodedInputLength, uint8_t* encodedInput) 
{
	uint8_t isError;

	/* If the reply is too big, then something must be wrong. */
	if(encodedInputLength > MAX_HTTP_REPLY) {
		kerberosCtx.state = NOT_INITIALIZED;
		return;
	}
	
	if(encodedInput == NULL) {
		kerberosCtx.state = NOT_INITIALIZED;
		return;
	}
	
	checkIfError(encodedInput, encodedInputLength, &isError);
	if(isError == 0) {
		processState(encodedInput, encodedInputLength);
	}
	else {
		kerberosCtx.callback(isError);
	}
}

/* Check if the received message is an error */
void checkIfError(uint8_t* encodedInput, size_t encodedInputLength, uint8_t *isError)
{
	size_t offset;
	errno_t result;
	Error error;
	
	/* If it properly decodes, then it is an error */
	result = setEncodedError(&error, encodedInput, encodedInputLength, &offset);
	if(result == SUCCESSFULL_OPERATION) {
		kerberosCtx.state = NOT_INITIALIZED;
		decodeError(&error, &kerberosCtx.errorCode);
		*isError = 1;
	} else {
		*isError = 0;
	}
}

/* Upon receipt of a message, executes the action related to the current state */
void processState(uint8_t* encodedInput, size_t encodedInputLength)
{
	errno_t result;
	uint8_t *encodedOutput;
	size_t encodedOutputLength;
	
	/* State machine that represents client side of the kerberos protocol */
	switch(kerberosCtx.state)
	{
		/* Secure channel not yet initialized. Creates a requestAS and send_message it to the kerberos server */
		case NOT_INITIALIZED:
			result = doRequestAS(&encodedOutput, &encodedOutputLength);
			if(result != SUCCESSFULL_OPERATION) {
				kerberosCtx.callback(SECURE_CHANNEL_FAILED);
				kerberosCtx.state = NOT_INITIALIZED;
				break;
			}
			printf("*** sending message\n");
			goNextState();
			send_message(encodedOutput, encodedOutputLength, kerberosCtx.host, kerberosCtx.uriRequestAS); 
			
			break;
		/*
		 * After requestAS was sent, the state machine goes to WAIT_REPLY_AS state. 
		 * This states expects to receive a valid reply AS and then send_messages a requestAP.
         */
		case WAIT_REPLY_AS:
			result = verifyReplyAS(encodedInput, encodedInputLength);
			if(result != SUCCESSFULL_OPERATION) {
			    printf("*** replyAS failed\n");
				kerberosCtx.callback(SECURE_CHANNEL_FAILED);
				kerberosCtx.state = NOT_INITIALIZED;
				break;
			}
			printf("*** replyAS OK\n");
			printf("*** encoding requestAP\n");
			result = doRequestAP(&encodedOutput, &encodedOutputLength);
			if(result != SUCCESSFULL_OPERATION) {
				kerberosCtx.callback(SECURE_CHANNEL_FAILED);
				kerberosCtx.state = NOT_INITIALIZED;
				break;
			}
			printf("*** sending message\n");
			goNextState();
			send_message(encodedOutput, encodedOutputLength, kerberosCtx.host, kerberosCtx.uriRequestAP); 
			
			break;
		/*
		 * After request AP was sent, the state machine goes to WAIT_REPLY_AP.
		 * This states expects to receive a valid reply AP, which causes the secure channel
		 * to be established and ready to send_message and receive data which must be protected.
		 */
		case WAIT_REPLY_AP:
		    printf("*** state is WAIT_REPLY_AP\n");
		    printf("*** verifying replyAP\n");
			result = verifyReplyAP(encodedInput, encodedInputLength);
			if(result != SUCCESSFULL_OPERATION) {
			    printf("*** replyAP failed\n");
				kerberosCtx.callback(SECURE_CHANNEL_FAILED);
				kerberosCtx.state = NOT_INITIALIZED;
				break;
			}
			printf("*** replyAP OK\n");
			goNextState();
			kerberosCtx.callback(SECURE_CHANNEL_OK);
			break;
		/* 
		 * ESTABLISHED CHANNEL does not need to be handle here, because
		 * it is impossible to processReply to get a message without it being
		 * asked.
		 */
	}
	kerberosCtx.errorCode = result;
}


/* Encode the first message to Kerberos AS */
errno_t doRequestAS(uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;
	RequestAS requestAS;
	
	result = encodeRequestAS(&requestAS, kerberosCtx.cname, sizeof(kerberosCtx.cname), kerberosCtx.sname, sizeof(kerberosCtx.sname),
					kerberosCtx.nonce, sizeof(kerberosCtx.nonce));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = getEncodedRequestAS(&requestAS, encodedOutput, encodedLength);
FAIL:
	result |= memset_s(&requestAS, sizeof(RequestAS), 0, sizeof(RequestAS));	
	return result;
}


/* Sends the ticket and an authenticator, which is a encrypted data used to authenticate the flash component to the application server */
errno_t doRequestAP(uint8_t** encodedOutput, size_t* encodedLength)
{
	errno_t result;

	/* Generates the authenticator */
	Authenticator authenticator;

	/* Get the number of milliseconds since midnight January 1, 1970 */
	getAdjustedUTC(kerberosCtx.timestamp, kerberosCtx.offset);

	/* Create the authenticator part of the request */
	uint8_t* encodedAuth;
	size_t encodedAuthLength;

	result = encodeAuthenticator(&authenticator, kerberosCtx.cname, sizeof(kerberosCtx.cname), kerberosCtx.timestamp, TIME_LENGTH);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = getEncodedAuthenticator(&authenticator, &encodedAuth, &encodedAuthLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Initializes the secure channel */
	result = initSecureChannel(kerberosCtx.sessionKeys.keyLength, kerberosCtx.sessionKeys.ivLength, kerberosCtx.tagLen, 
						kerberosCtx.sessionKeys.keyCS, kerberosCtx.sessionKeys.keySC, kerberosCtx.sessionKeys.ivCS,
						kerberosCtx.sessionKeys.ivSC);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Encrypts the authenticator using the session key and session iv for the client -> server communication */
	uint8_t *encryptedAuth;
	size_t encryptedAuthLength;
	result = encryptTo(NULL, 0, encodedAuth, encodedAuthLength, &encryptedAuth, &encryptedAuthLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Create the encrypted data from the authenticator */
	EncryptedData encEncryptedAuth;
	result = encodeEncData(&encEncryptedAuth, kerberosCtx.sessionKeys.ivCS, kerberosCtx.sessionKeys.ivLength, encryptedAuth, encryptedAuthLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	RequestAP requestAP;
	result = encodeRequestAP(&requestAP, &kerberosCtx.ticket, &encEncryptedAuth);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = getEncodedRequestAP(&requestAP, encodedOutput, encodedLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
FAIL:
	return result;
}


/* Verifies the reply from the AS */
errno_t verifyReplyAS(uint8_t* encodedInput, size_t encodedLength)
{
	errno_t result;
	size_t offset = 0;
	
	ReplyAS replyAS;
	EncryptedData encData;
	size_t cnameLength;
	uint8_t *cname;
	
	result = setEncodedReplyAS(&replyAS, encodedInput, encodedLength, &offset);
	if(result != SUCCESSFULL_OPERATION){
	    printf("setEncodedReplyAS failed\n");
		goto FAIL;
	}
	
	result = decodeReplyAS(&replyAS, &cname, &cnameLength, &kerberosCtx.ticket, &encData);
	if(result != SUCCESSFULL_OPERATION) {
	    printf("decodeReplyAS failed\n");
		goto FAIL;
	}
	
	/* Check if the received cleartext cname match what was requested */
	if(cnameLength != PRINCIPAL_NAME_LENGTH || memcmp(kerberosCtx.cname, cname, PRINCIPAL_NAME_LENGTH) != 0) {
	    printf("Received cleartext cname does not match requested\n");
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Check if IVsc is equal to the IV used during encryption of the received message */
	uint8_t *iv, *ciphertext;
	uint8_t ivLength, ciphertextLength;
	
	result = decodeEncData(&encData, &iv, &ivLength, &ciphertext, &ciphertextLength);
	if(result != SUCCESSFULL_OPERATION) {
	    printf("decodeEncData failed\n");
		goto FAIL;
	}
	
	/* It's used only for communication between this component and the Kerberos AS */
	result = initSecureChannel(SHARED_KEY_LENGTH, ivLength, TAG_LEN, kerberosCtx.sharedKey, kerberosCtx.sharedKey, iv, iv);
	if(result != SUCCESSFULL_OPERATION) {
	    printf("initSecureChannel failed\n");
		goto FAIL;
	}
	
	/* Properly decrypts the encrypted part of the replyAS */
	uint8_t* decEncKdcRep;
	size_t decEncKdcRepLength;
	
	int i = 0;
	for(i = 0; i < ciphertextLength; i++){
	    printf("%x", *(ciphertext + i));
	}
	printf("\n");
	    
	
	result = decryptTo(NULL, 0, ciphertext, ciphertextLength, &decEncKdcRep, &decEncKdcRepLength);
	if(result != SUCCESSFULL_OPERATION) {
	    printf("decryptTo failed\n");
		goto FAIL;
	}
	
	/* Decode EncKdcPart */
	EncKdcPart EncKdcPart;
	uint8_t	*snameObt, *nonceObt, *authObt, *endObt;
	size_t snameObtLength, nonceObtLength, authObtLength, endObtTime;
	
	result = setEncodedEncKdcPart(&EncKdcPart, decEncKdcRep, decEncKdcRepLength, &offset);
	if(result != SUCCESSFULL_OPERATION) {
	    printf("setEncodedEncKdcPart failed\n");
		goto FAIL;
	}
	
	result = decodeEncKdcPart(&EncKdcPart, &kerberosCtx.sessionKeys, &snameObt, &snameObtLength,
			&nonceObt, &nonceObtLength, &authObt, &authObtLength, &endObt, &endObtTime);
	if(result != SUCCESSFULL_OPERATION) {
	    printf("decodeEncKdcPart failed\n");
		goto FAIL;
	}
	
	/* Check if nonce is equal to the nonce that was sent */
	if(nonceObtLength != NONCE_LENGTH || memcmp(kerberosCtx.nonce, nonceObt, NONCE_LENGTH) != 0) {
	    printf("nonce is not equal to the nonce that was sent\n");
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Check if snames are equal */
	if(snameObtLength != PRINCIPAL_NAME_LENGTH || memcmp(kerberosCtx.sname, snameObt, PRINCIPAL_NAME_LENGTH) != 0) {
	    printf("snames are not equal\n");
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Ticket and session keys were already saved during decode calls */
	/* Save offset between client and server */	
	calculateOffset(authObt, kerberosCtx.offset);
FAIL:
	return result;
}


/* Verifies the reply from the application server. Reply from application should contain information to authenticate the application to the flash component */
errno_t verifyReplyAP(uint8_t* encodedInput, size_t encodedLength)
{
	errno_t result;
	EncryptedData encData;
	ReplyAP replyAP;
	size_t offset;
	
	/* Decoding Reply AP */
	result = setEncodedReplyAP(&replyAP, encodedInput, encodedLength, &offset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = decodeReplyAP(&replyAP, &encData);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	if(offset != encodedLength) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Decrypting the timestamp */
	uint8_t *iv, *ciphertext, *timestamp;
	uint8_t ivLength, ciphertextLength;
	uint32_t timestampLength;
	
	result = decodeEncData(&encData, &iv, &ivLength, &ciphertext, &ciphertextLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = decryptTo(NULL, 0, ciphertext, (size_t)ciphertextLength, &timestamp, &timestampLength);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Verify if timestamp equals timestamp on the authenticator */
	if(timestampLength != TIME_LENGTH || memcmp(timestamp, kerberosCtx.timestamp, TIME_LENGTH) != 0) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
FAIL:
	return result;
}

/* Updates the state machine by performing a transition */
void goNextState()
{
	switch(kerberosCtx.state)
	{
		case NOT_INITIALIZED:
			kerberosCtx.state = WAIT_REPLY_AS;
			break;
		case WAIT_REPLY_AS:
			kerberosCtx.state = WAIT_REPLY_AP;
			break;
		case WAIT_REPLY_AP:
			kerberosCtx.state = ESTABLISHED_CHANNEL;
			break;
	}
}

/* Check if secure channel is open */
uint8_t isSecureChannelOpen()
{
	uint8_t isOpen = 0;
	
	if(kerberosCtx.state == ESTABLISHED_CHANNEL && kerberosCtx.errorCode == SUCCESSFULL_OPERATION) {
		isOpen = 1;
	}
	
	return isOpen;
}

/* Check if any error has occurred. Client application doesn't know the meaning. */
uint8_t hasErrorOccurred()
{
	return kerberosCtx.errorCode;
}
