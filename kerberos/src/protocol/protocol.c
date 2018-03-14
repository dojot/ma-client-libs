#include "protocol.h"

#include "encoder/authenticator.h"
#include "encoder/error.h"
#include "encoder/replyAP.h"
#include "encoder/replyAS.h"
#include "encoder/requestAS.h"
#include "encoder/requestAP.h"
#include "encoder/sessionKey.h"
#include "encoder/errno.h"
#include "encoder/encKdcRepPart.h"
#include "encoder/constants.h"
#include "communication.h"
#include "secure-util.h"
#include "endian.h"

#include "logger/logger.h"
#include "ma_comm_error_codes.h"

typedef enum {
    NOT_INITIALIZED,
    WAIT_REPLY_AS,
    WAIT_REPLY_AP,
    ESTABLISHED_CHANNEL
} ProtocolState;

// All the necessary information to establish a secure channel
// is kept in the Kerberos context
typedef struct {
    char* urlRequestAS;    /* URI of Kerberos Request AS rest interface. */
    char* urlRequestAP;    /* URI of Kerberos Request AP rest interface. */
    ProtocolState state;        /* State of the Kerberos protocol */
    uint8_t sharedKey[SHARED_KEY_LENGTH];            /* Pre-shared key with Kerberos AS */
    uint8_t tagLen;                /* Size of the tags */
    uint8_t cname[PRINCIPAL_NAME_LENGTH];    /* ID of this application instance */
    uint8_t sname[PRINCIPAL_NAME_LENGTH];    /* ID of the server application */
    uint8_t nonce[NONCE_LENGTH];
    Ticket ticket;
    SessionKeys sessionKeys;    /* Parameters used to create a secure channel */
    uint64_t timestamp;
    uint64_t offset;
    uint64_t expireTimestamp;
    errno_t errorCode;
    uint8_t sessionId[SESSION_ID_LENGTH];    /*The session information generated after RequestAS*/
} KerberosContext;


void context_init(KerberosContext* pContext);

void context_deinit(KerberosContext* pContext);

/***
 * @brief Initialize the kerberos request URIs and the host.
 * @return 0 on success, otherwise non-zero
 */
uint8_t context_set_urls(KerberosContext* pContext,
                        const char* urlRequestAS,
                        const char* urlRequestAP);

uint8_t context_set_client_server_parameters(KerberosContext *pContext,
                                             const uint8_t* cname,
                                             size_t cnameLength,
                                             const uint8_t* sname,
                                             size_t snameLength,
                                             const uint8_t* sharedKey,
                                             size_t keyLength);

uint8_t generateNonce(KerberosContext *pContext);

/* Upon receipt of a message, executes the action related to the current state */
uint8_t processState(KerberosContext *pContext,
                      uint8_t* encodedInput,
                      size_t encodedInputLength);

/**
 * @brief Updates the state machine by performing a transition
 **/
void goNextState(KerberosContext *pContext);

uint8_t processReply(KerberosContext* pContext,
                  size_t encodedInputLength,
                  uint8_t* encodedInput);

/* Check if the received message is an error */
uint8_t checkIfError(KerberosContext* pContext,
                     uint8_t* encodedInput,
                     size_t encodedInputLength);

/* Encode the first message to Kerberos AS */
uint8_t doRequestAS(KerberosContext *pContext,
                    uint8_t** encodedOutput,
                    size_t* encodedLength);

uint8_t verifyReplyAS(KerberosContext *pContext,
                      uint8_t* encodedInput,
                      size_t encodedLength);

uint8_t doRequestAP(KerberosContext *pContext,
                    uint8_t** encodedOutput,
                    size_t* encodedLength);

uint8_t verifyReplyAP(KerberosContext *pContext,
                      uint8_t* encodedInput,
                      size_t encodedLength);


uint8_t kerberos_protocol_init(const char* urlRequestAS,
                               const char* urlRequestAP,
                               const uint8_t *appId,
                               size_t appIdSize,
                               const uint8_t *serverId,
                               size_t serverIdSize,
                               const uint8_t *sharedKey,
                               size_t sharedKeySize,
                               void** pContext) {
    KerberosContext* pKerberosContext = NULL;
    uint8_t result = MA_COMM_SUCCESS;

    // Initializing the random number generator.
    srand(time(NULL));

    pKerberosContext = (KerberosContext*) malloc(sizeof(KerberosContext));
    if (!pKerberosContext) {
        LOG("Fail to alloc kerberos context\n");
        result = MA_COMM_OUT_OF_MEMORY;
        goto FAIL;
    }

    context_init(pKerberosContext);

    result = context_set_urls(pKerberosContext, urlRequestAS, urlRequestAP);
    if(result != MA_COMM_SUCCESS) {
        LOG("Fail to fill kerberos context\n");
        result = MA_COMM_INVALID_STATE;
        goto FAIL;
    }

    result = context_set_client_server_parameters(pKerberosContext,
                                                  appId,
                                                  appIdSize,
                                                  serverId,
                                                  serverIdSize,
                                                  sharedKey,
                                                  sharedKeySize);
    if(result != MA_COMM_SUCCESS) {
        LOG("Fail to fill kerberos context\n");
        result = MA_COMM_INVALID_STATE;
        goto FAIL;
    }

    *pContext = pKerberosContext;
    result = MA_COMM_SUCCESS;
    goto SUCCESS;

FAIL:
    free(pKerberosContext);

SUCCESS:
    return result;
}

uint8_t kerberos_protocol_deinit(void** pContext) {
    uint8_t result = MA_COMM_SUCCESS;
    KerberosContext* pKerberosContext = NULL;

    if (!pContext) {
        LOG("Invalid kerberos context\n");
        return MA_COMM_INVALID_PARAMETER;
    }
    pKerberosContext = (KerberosContext*) *pContext;

    context_deinit(pKerberosContext);
    free(pKerberosContext);
    *pContext = NULL;

    clearSecureChannel();

    return MA_COMM_SUCCESS;
}

char* protocolStateToString(ProtocolState state);

void context_init(KerberosContext* pContext) {
    pContext->urlRequestAS = NULL;
    pContext->urlRequestAP = NULL;
    pContext->state = NOT_INITIALIZED;
    memset(pContext->sharedKey, 0, SHARED_KEY_LENGTH);
    pContext->tagLen = 128;    // todo remove this magic number
    memset(pContext->cname, 0, PRINCIPAL_NAME_LENGTH);
    memset(pContext->sname, 0, PRINCIPAL_NAME_LENGTH);
    memset(pContext->nonce, 0, NONCE_LENGTH);
    initTicket(&pContext->ticket);
    initSessionKeys(&pContext->sessionKeys);
    pContext->timestamp = 0;
    pContext->offset = 0;
    pContext->expireTimestamp = 0;
    pContext->errorCode = SUCCESSFULL_OPERATION;
    memset(pContext->nonce, 0, SESSION_ID_LENGTH);
}

void context_deinit(KerberosContext* pContext) {
    if (pContext->urlRequestAS) {
        free(pContext->urlRequestAS);
        pContext->urlRequestAS = NULL;
    }
    if (pContext->urlRequestAP) {
        free(pContext->urlRequestAP);
        pContext->urlRequestAP = NULL;
    }
    pContext->state = NOT_INITIALIZED;
    memset(pContext->sharedKey, 0, SHARED_KEY_LENGTH);
    pContext->tagLen = 0;
    memset(pContext->cname, 0, PRINCIPAL_NAME_LENGTH);
    memset(pContext->sname, 0, PRINCIPAL_NAME_LENGTH);
    memset(pContext->nonce, 0, NONCE_LENGTH);
    eraseTicket(&pContext->ticket);
    eraseSessionKeys(&pContext->sessionKeys);
    pContext->timestamp = 0;
    pContext->offset = 0;
    pContext->expireTimestamp = 0;
    pContext->errorCode = SUCCESSFULL_OPERATION;
    memset(pContext->nonce, 0, SESSION_ID_LENGTH);
}

uint8_t context_set_urls(KerberosContext* pContext,
                        const char* urlRequestAS,
                        const char* urlRequestAP) {
    size_t requestASLength = 0;
    size_t requestAPLength = 0;
    uint8_t result = 0;

    // Input validation.
    if (!pContext ||
        !urlRequestAS ||
        !urlRequestAP) {
        return MA_COMM_INVALID_PARAMETER;
    }

    // compute string lengths
    requestASLength = strlen(urlRequestAS) + 1;
    requestAPLength = strlen(urlRequestAP) + 1;

       if (requestASLength == 0 || requestAPLength == 0) {
        return MA_COMM_INVALID_PARAMETER;
       }

    // copies the request AS.
    pContext->urlRequestAS = (char*) malloc(sizeof(char) * requestASLength);
    if (!pContext->urlRequestAS) {
        result = MA_COMM_OUT_OF_MEMORY;
        goto FAIL;
    }
    strcpy(pContext->urlRequestAS, urlRequestAS);

    // copies the request AP.
    pContext->urlRequestAP = (char*) malloc(sizeof(char) * requestAPLength);
    if (!pContext->urlRequestAP) {
        result = 1;
        goto FAIL;
    }
    strcpy(pContext->urlRequestAP, urlRequestAP);

    result = MA_COMM_SUCCESS;
    goto SUCCESS;

FAIL:
    if (pContext->urlRequestAS) {
        free(pContext->urlRequestAS);
        pContext->urlRequestAS = NULL;
    }
    if (pContext->urlRequestAP) {
        free(pContext->urlRequestAP);
        pContext->urlRequestAP = NULL;
    }

SUCCESS:
    return result;
}

uint8_t context_set_client_server_parameters(KerberosContext *pContext,
                                             const uint8_t* cname,
                                             size_t cnameLength,
                                             const uint8_t* sname,
                                             size_t snameLength,
                                             const uint8_t* sharedKey,
                                             size_t keyLength) {
    // Input validation
    if (!pContext || !cname || !sname || !sharedKey) {
        return MA_COMM_INVALID_PARAMETER;
    }

    if (cnameLength != PRINCIPAL_NAME_LENGTH ||
        snameLength != PRINCIPAL_NAME_LENGTH ||
        keyLength != KEY_LENGTH) {
        LOG("Invalid appId, serverId, or sharedKey length\n");
        return MA_COMM_INVALID_PARAMETER;
    }

    memcpy(pContext->cname, cname, PRINCIPAL_NAME_LENGTH);
    memcpy(pContext->sname, sname, PRINCIPAL_NAME_LENGTH);
    memcpy(pContext->sharedKey, sharedKey, KEY_LENGTH);

    return MA_COMM_SUCCESS;
}

uint8_t generateNonce(KerberosContext *pContext) {
    uint8_t result = 0;

    // Get secure random number to be the nonce
    //todo: change it to a real secure random method
    result= generateRandom(pContext->nonce, NONCE_LENGTH);
    if (result != SUCCESSFULL_OPERATION) {
        return MA_COMM_INVALID_STATE;
    }
    return MA_COMM_SUCCESS;
}

uint8_t kerberos_protocol_execute_handshake(void* pContext) {
    uint8_t result = 0;
    KerberosContext* pKerberosContext = NULL;

    if (!pContext) {
        LOG("Invalid kerberos context\n");
        return MA_COMM_INVALID_PARAMETER;
    }

    pKerberosContext = (KerberosContext*) pContext;

    // reset handshake related attributes
    result = generateNonce(pKerberosContext);
    if (result != MA_COMM_SUCCESS) {
        LOG("Fail to generate nonce\n");
        return MA_COMM_INVALID_STATE;
    }
    pKerberosContext->state = NOT_INITIALIZED;

    result = processState(pKerberosContext, NULL, 0);
    if (result != MA_COMM_SUCCESS) {
        LOG("Fail to execute kerberos handshake. Error: %u\n",
            pKerberosContext->errorCode);
        result = MA_COMM_INVALID_STATE;
    }
    return result;
}

uint8_t kerberos_protocol_is_mutual_authenticated(void* pContext) {
    KerberosContext *pKerberosContext = NULL;

    if (!pContext) {
        LOG("invalid kerberos context\n");
        return MA_COMM_FALSE;
    }
    pKerberosContext = (KerberosContext*) pContext;

    if (pKerberosContext->state != ESTABLISHED_CHANNEL) {
        LOG("Channel is not established (%d)\n", pKerberosContext->state);
        return MA_COMM_FALSE;
    }

    uint64_t currServerTime = 0;
    getAdjustedUTC(pKerberosContext->offset, &currServerTime);
    if (currServerTime > pKerberosContext->expireTimestamp) {
        LOG("Authentication has been expired\n");
        return MA_COMM_FALSE;
    }

    LOG("Remaining %llu ms to expire the mutual authentication\n",
            pKerberosContext->expireTimestamp - currServerTime);
    return MA_COMM_TRUE;
}

uint8_t processState(KerberosContext *pContext,
                      uint8_t* encodedInput,
                      size_t encodedInputLength) {
    errno_t result = 0;
    uint8_t *encodedOutput = NULL;
    size_t encodedOutputLength = 0;
    uint8_t* pResponse = NULL;
    size_t responseSize = 0;

    LOG("Processing state: %s\n", protocolStateToString(pContext->state));

    // State machine that represents client side of the kerberos protocol
    switch(pContext->state) {
        // Secure channel not yet initialized. Creates a requestAS and
        // send_message it to the kerberos server
        case NOT_INITIALIZED:
            LOG("Creating requestAS\n");
            result = doRequestAS(pContext, &encodedOutput, &encodedOutputLength);
            if(result != SUCCESSFULL_OPERATION) {
                result = 1;
                break;
            }
            goNextState(pContext);
            LOG("Sending requestAS\n");
            result = send_message(pContext->urlRequestAS,
                                  NULL,
                                  0,
                                  encodedOutput,
                                  encodedOutputLength,
                                  &pResponse,
                                  &responseSize);
            free(encodedOutput);
            if (result != SUCCESSFULL_OPERATION) {
                result = 1;
                break;
            }

            result = processReply(pContext, responseSize, pResponse);
            free(pResponse);
            if (result != 0) {
                result = 1;
                break;
            }

            result = 0;
            break;
        // After requestAS was sent, the state machine goes to WAIT_REPLY_AS state.
        // This states expects to receive a valid reply AS and then send_messages a requestAP.
        case WAIT_REPLY_AS:
            LOG("ReplyAS received. Verifying data received ...\n");
            result = verifyReplyAS(pContext, encodedInput, encodedInputLength);
            if(result != MA_COMM_SUCCESS) {
                LOG("Fail to verify ReplyAS\n");
                result = 1;
                break;
            }
            LOG("ReplyAS verified. Creating requestAP\n");
            result = doRequestAP(pContext, &encodedOutput, &encodedOutputLength);
            if(result != SUCCESSFULL_OPERATION) {
                LOG("Fail to create RequestAP\n");
                result = 1;
                break;
            }
            goNextState(pContext);
            LOG("Sending requestAP\n");
            result = send_message(pContext->urlRequestAP,
                                  NULL,
                                  0,
                                  encodedOutput,
                                  encodedOutputLength,
                                  &pResponse,
                                  &responseSize);
            free(encodedOutput);
            if (result != SUCCESSFULL_OPERATION) {
                LOG("Fail to send RequestAP\n");
                result = 1;
                break;
            }

            result = processReply(pContext, responseSize, pResponse);
            free(pResponse);
            if (result != 0) {
                result = 1;
                break;
            }

            result = 0;
            break;
//         After request AP was sent, the state machine goes to WAIT_REPLY_AP.
//         This states expects to receive a valid reply AP, which causes the secure channel
//         to be established and ready to send_message and receive data which must be protected.
        case WAIT_REPLY_AP:
            LOG("ReplyAP received. Verifying data received\n");
            result = verifyReplyAP(pContext, encodedInput, encodedInputLength);
            if(result != SUCCESSFULL_OPERATION) {
                LOG("Fail to verify ReplyAP\n");
                result = 1;
                break;
            }
            LOG("ReplyAP verified\n");
            goNextState(pContext);
            result = 0;
            break;
        case ESTABLISHED_CHANNEL:
//         ESTABLISHED CHANNEL does not need to be handle here, because
//         it is impossible to processReply to get a message without it being
//         asked.
            break;
    }

    if (result != 0) {
        LOG("problem on %s\n", protocolStateToString(pContext->state));
        pContext->state = NOT_INITIALIZED;
    }

    return result;
}

void goNextState(KerberosContext *pContext) {
    switch (pContext->state) {
        case NOT_INITIALIZED:
            pContext->state = WAIT_REPLY_AS;
            break;
        case WAIT_REPLY_AS:
            pContext->state = WAIT_REPLY_AP;
            break;
        case WAIT_REPLY_AP:
            pContext->state = ESTABLISHED_CHANNEL;
            break;
        case ESTABLISHED_CHANNEL:
            // do nothing
            break;
    }
}

uint8_t processReply(KerberosContext* pContext,
                  size_t encodedInputLength,
                  uint8_t* encodedInput) {
    uint8_t isError = 0;
    errno_t result = 0;

    if ( (!encodedInput) || (encodedInputLength == 0) ) {
        return 1;
    }

    isError = checkIfError(pContext, encodedInput, encodedInputLength);
    if(isError == 0) {
        result = processState(pContext, encodedInput, encodedInputLength);
        if (result != 0) {
            result = 1;
        }
    } else {
        result = 1;
    }

    return result;
}

/* Check if the received message is an error */
uint8_t checkIfError(KerberosContext* pContext,
                     uint8_t* encodedInput,
                     size_t encodedInputLength) {
    size_t offset = 0;
    errno_t result = 0;
    Error error;

    /* If it properly decodes, then it is an error */
    result = setEncodedError(&error, encodedInput, encodedInputLength, &offset);
    if(result == SUCCESSFULL_OPERATION) {
        decodeError(&error, &(pContext->errorCode));
        LOG("An error response has been received: %s\n", getErrorString(error));
        return 1;
    }

    return 0;
}

uint8_t doRequestAS(KerberosContext *pContext,
                    uint8_t** encodedOutput,
                    size_t* encodedLength) {
    uint8_t result = 0;
    RequestAS requestAS;

    result = encodeRequestAS(&requestAS,
                             pContext->cname,
                             sizeof(pContext->cname),
                             pContext->sname,
                             sizeof(pContext->sname),
                             pContext->nonce,
                             sizeof(pContext->nonce));
    if(result != MA_COMM_SUCCESS) {
        LOG("Fail to encode requestAS\n");
        return MA_COMM_INVALID_STATE;
    }

    result = getEncodedRequestAS(&requestAS, encodedOutput, encodedLength);
    if (result != MA_COMM_SUCCESS) {
        LOG("Fail to serialize the request AS\n");
        eraseRequestAS(&requestAS);
        return MA_COMM_INVALID_STATE;
    }

    dumpRequestAS(&requestAS, 0);
    eraseRequestAS(&requestAS);

    return MA_COMM_SUCCESS;
}

/* Verifies the reply from the AS */
uint8_t verifyReplyAS(KerberosContext *pContext,
                      uint8_t* encodedInput,
                      size_t encodedLength) {
    uint8_t result = MA_COMM_SUCCESS;
    size_t offset = 0;
    ReplyAS replyAS;
    size_t cnameLength = 0;
    uint8_t cname[PRINCIPAL_NAME_LENGTH];

    /* Store sessionId */
    if(encodedLength < SESSION_ID_LENGTH){
        LOG("Invalid ReplyAS length\n");
        return MA_COMM_INVALID_PARAMETER;
    }
    memcpy(pContext->sessionId, encodedInput, SESSION_ID_LENGTH);

    /* Modify encodedInput to ignore sessionId */
    encodedInput = encodedInput + (SESSION_ID_LENGTH);
    encodedLength = encodedLength - SESSION_ID_LENGTH;

    result = setEncodedReplyAS(&replyAS, encodedInput, encodedLength, &offset);
    if(result != MA_COMM_SUCCESS){
        LOG("Fail to deserialize the Reply AS\n")
        result = MA_COMM_INVALID_STATE;
        goto SESSION_ID_CLEAN;
    }

    LOG("SessionId: ");
    uint8_t i = 0;
    for(i = 0; i < SESSION_ID_LENGTH; ++i) {
        LOG("%02x", pContext->sessionId[i]);
    }
    LOG("\n");
    dumpReplyAS(&replyAS, 0);

    // Check if the received cleartext cname match what was requested
    if (memcmp(pContext->cname, replyAS.cname, PRINCIPAL_NAME_LENGTH) != 0) {
        LOG("ReplyAS cname does not match\n");
        result = MA_COMM_INVALID_STATE;
        goto REPLY_AS_CLEAN;
    }

    // It's used only for communication between this component and the Kerberos AS
    result = initSecureChannel(SHARED_KEY_LENGTH,
                               replyAS.encPart.ivLength,
                               TAG_LEN,
                               pContext->sharedKey,
                               pContext->sharedKey,
                               replyAS.encPart.iv,
                               replyAS.encPart.iv);
    if(result != SUCCESSFULL_OPERATION) {
        LOG("Fail to initialize crypto\n");
        result = MA_COMM_INVALID_STATE;
        goto REPLY_AS_CLEAN;
    }

    // Properly decrypts the encrypted part of the replyAS
    uint8_t* decEncKdcRep = NULL;
    size_t decEncKdcRepLength = 0;

    result = decryptTo(NULL,
                       0,
                       replyAS.encPart.ciphertext,
                       replyAS.encPart.ciphertextLength,
                       &decEncKdcRep,
                       &decEncKdcRepLength);
    clearSecureChannel();

    if(result != SUCCESSFULL_OPERATION) {
        LOG("Fail to decrypt ReplyAS enc part\n");
        result = MA_COMM_INVALID_STATE;
        goto REPLY_AS_CLEAN;
    }

    EncKdcPart encKdcPart;
    result = setEncodedEncKdcPart(&encKdcPart, decEncKdcRep, decEncKdcRepLength, &offset);
    //free decEncKdcRep
    memset_s(decEncKdcRep, decEncKdcRepLength, 0, decEncKdcRepLength);
    free(decEncKdcRep);
    if(result != MA_COMM_SUCCESS) {
        LOG("Fail to deserialize ReplyAS enc part\n");
        result = MA_COMM_INVALID_STATE;
        goto REPLY_AS_CLEAN;
    }

    dumpEncKdcPart(&encKdcPart, 0);

    uint64_t localTimeOffset = 0;
    // compute the offset between the local and server time
    calculateOffset(encKdcPart.authtime, &localTimeOffset);

    // Check if nonce is equal to the nonce that was sent
    if (memcmp(pContext->nonce, encKdcPart.nonce, NONCE_LENGTH) != 0) {
        LOG("ReplyAs nonce does not match\n");
        result = MA_COMM_INVALID_STATE;
        goto REPLY_AS_CLEAN;
    }

    if (memcmp(pContext->sname, encKdcPart.sname, PRINCIPAL_NAME_LENGTH) != 0) {
        LOG("ReplyAs sname does not match\n");
        result = MA_COMM_INVALID_STATE;
        goto REPLY_AS_CLEAN;
    }

    // everything is right, so let's commit the data into context
    result = copyTicket(&replyAS.ticket, &pContext->ticket);
    if (result != MA_COMM_SUCCESS) {
        LOG("Fail to copy ticket into context\n");
        result = MA_COMM_OUT_OF_MEMORY;
        goto REPLY_AS_CLEAN;
    }
    result = copySessionKeys(&encKdcPart.sk, &pContext->sessionKeys);
    if (result != MA_COMM_SUCCESS) {
        LOG("Fail to copy session keys into context\n");
        result = MA_COMM_OUT_OF_MEMORY;
        goto TICKET_CTX_CLEAN;
    }
    pContext->expireTimestamp = encKdcPart.endtime;
    pContext->offset = localTimeOffset;

    eraseReplyAS(&replyAS);
    eraseEncKdcPart(&encKdcPart);
    return MA_COMM_SUCCESS;

//rollback flow:
TICKET_CTX_CLEAN:
    eraseTicket(&pContext->ticket);
ENC_KDC_PART_CLEAN:
    eraseEncKdcPart(&encKdcPart);
REPLY_AS_CLEAN:
    eraseReplyAS(&replyAS);
SESSION_ID_CLEAN:
    memset_s(pContext->sessionId, SESSION_ID_LENGTH, 0, SESSION_ID_LENGTH);
    return result;
}

/* Sends the ticket and an authenticator, which is a encrypted data used to authenticate the flash component to the application server */
uint8_t doRequestAP(KerberosContext *pContext,
                    uint8_t** encodedOutput,
                    size_t* encodedLength) {
    uint8_t result;
    RequestAP requestAP;

    /* Generates the authenticator */
    Authenticator authenticator;

    /* Get the number of milliseconds since midnight January 1, 1970 */
    getAdjustedUTC(pContext->offset, &pContext->timestamp);

    /* Create the authenticator part of the request */
    uint8_t* encodedAuth;
    size_t encodedAuthLength;

    result = encodeAuthenticator(&authenticator,
                                 pContext->cname,
                                 PRINCIPAL_NAME_LENGTH,
                                 pContext->timestamp);
    if(result != MA_COMM_SUCCESS) {
        LOG("Fail to create ReplyAP's authenticator\n");
        return MA_COMM_INVALID_STATE;
    }

    result = getEncodedAuthenticator(&authenticator, &encodedAuth, &encodedAuthLength);
    if(result != MA_COMM_SUCCESS) {
        LOG("Fail to serialize RequestAP's authenticator\n");
        eraseAuthenticator(&authenticator);
        return MA_COMM_INVALID_STATE;
    }

    eraseAuthenticator(&authenticator);

    // Initializes the secure channel
    // todo: is it the better place to do it? once we will not
    // close it any more
    result = initSecureChannel(pContext->sessionKeys.keyLength,
                               pContext->sessionKeys.ivLength,
                               pContext->tagLen,
                               pContext->sessionKeys.keyCS,
                               pContext->sessionKeys.keySC,
                               pContext->sessionKeys.ivCS,
                               pContext->sessionKeys.ivSC);
    if(result != SUCCESSFULL_OPERATION) {
        LOG("Fail to initialize crypto\n");
        free(encodedAuth);
        return MA_COMM_INVALID_STATE;
    }

    initRequestAP(&requestAP);

    /* Encrypts the authenticator using the session key and session iv for the client -> server communication */
    result = encryptTo(NULL,
                       0,
                       encodedAuth,
                       encodedAuthLength,
                       &requestAP.encryptedData.ciphertext,
                       &requestAP.encryptedData.ciphertextLength);
    free(encodedAuth);
    if(result != SUCCESSFULL_OPERATION) {
        LOG("Fail to encrypt RequestAP's authenticator\n");
        return MA_COMM_INVALID_STATE;
    }

    result = copyIVOnEncData(&requestAP.encryptedData,
                             pContext->sessionKeys.ivCS,
                             pContext->sessionKeys.ivLength);
    if (result != MA_COMM_SUCCESS) {
        LOG("Fail to copy ticket on RequestAP\n");
        eraseRequestAP(&requestAP);
        return MA_COMM_INVALID_STATE;
    }

    result = copyTicket(&pContext->ticket, &requestAP.ticket);
    if (result != MA_COMM_SUCCESS) {
        LOG("Fail to copy ticket on RequestAP\n");
        eraseRequestAP(&requestAP);
        return MA_COMM_INVALID_STATE;
    }

    LOG("RequestAP created:\n");
    dumpRequestAP(&requestAP, 0);

    result = getEncodedRequestAP(&requestAP,
                                 encodedOutput,
                                 encodedLength,
                                 pContext->sessionId,
                                 SESSION_ID_LENGTH);
    eraseRequestAP(&requestAP);
    if(result != MA_COMM_SUCCESS) {
        LOG("Fail to serialize RequestAP\n");
        return MA_COMM_INVALID_STATE;
    }

    return MA_COMM_SUCCESS;
}

/* Verifies the reply from the application server. Reply from application should contain information to authenticate the application to the flash component */
uint8_t verifyReplyAP(KerberosContext *pContext,
                      uint8_t* encodedInput,
                      size_t encodedLength) {
    uint8_t result = MA_COMM_SUCCESS;
    ReplyAP replyAP;
    size_t offset = 0;

    /* Decoding Reply AP */
    result = setEncodedReplyAP(&replyAP, encodedInput, encodedLength, &offset);
    if(result != MA_COMM_SUCCESS) {
        LOG("Fail to deserialize ReplyAP\n");
        return MA_COMM_INVALID_PARAMETER;
    }

    LOG("ReplyAP received:\n");
    dumpEncryptedData(&replyAP.encData, 0);

    // just check the lengths
    if(offset != encodedLength) {
        LOG("ReplyAP length failed. Some unexpected thing is trailing the message?\n");
        eraseReplyAP(&replyAP);
        return MA_COMM_INVALID_PARAMETER;
    }


    uint8_t *plainData = NULL;
    size_t plainDataLength = 0;
    uint64_t timestamp = 0;
    result = decryptTo(NULL,
                       0,
                       replyAP.encData.ciphertext,
                       replyAP.encData.ciphertextLength,
                       &plainData,
                       &plainDataLength);
    eraseReplyAP(&replyAP);
    if(result != SUCCESSFULL_OPERATION) {
        LOG("Fail to decrypt ReplyAP\n");
        return MA_COMM_INVALID_PARAMETER;
    }
    // checking content
    if(plainDataLength != sizeof(uint64_t)) {
        LOG("Unexpected ReplyAP plain context length\n");
        free(plainData);
        return MA_COMM_INVALID_PARAMETER;
    }
    memcpy(&timestamp, plainData, plainDataLength);
    free(plainData);
    //endianness issue
    timestamp = be64toh(timestamp);

    // Verify if timestamp equals timestamp on the authenticator
    if(timestamp != pContext->timestamp) {
        LOG("ReplyAP's timestamp does not match with authenticator's timestamp\n");
        return MA_COMM_INVALID_PARAMETER;
    }

    return MA_COMM_SUCCESS;
}

char* protocolStateToString(ProtocolState state) {
    switch(state) {
        case NOT_INITIALIZED:
            return "NOT_INITIALIZED";
        case WAIT_REPLY_AS:
            return "WAIT_REPLY_AS";
        case WAIT_REPLY_AP:
            return "WAIT_REPLY_AP";
        case ESTABLISHED_CHANNEL:
            return "ESTABLISHED_CHANNEL";
    }

    return "UNDEFINED";
}
