#include "ma_communication.h"

#include <pthread.h>
#include <curl/curl.h>
#include <string.h>

#include "protocol/protocol.h"
#include "logger/logger.h"
#include "ma_comm_error_codes.h"
#include "crypto/codes.h"

#define IV_LENGTH 12
#define MUTUAL_AUTH_HEADER_LENGTH 80

typedef struct SCommContext {
    uint8_t isSecureChannelEnabled;
    uint8_t initCurl;
    void* pKerberosContext;
    char mutualAuthHeader[MUTUAL_AUTH_HEADER_LENGTH];
} CommContext;

static int initialized = 0;
static CommContext internalContext;

uint8_t concatIvWithCipheredData(uint8_t *iv,
                                 size_t ivLength,
                                 uint8_t *cipherData,
                                 size_t cipherDataLength,
                                 uint8_t **concatData,
                                 size_t *concatDataLength);

uint8_t rebuildMutualAuthenticationHeader();

void initCommContext(CommContext *pContext) {
    pContext->isSecureChannelEnabled = 0;
    pContext->initCurl = 0;
    pContext->pKerberosContext = NULL;
    memset(pContext->mutualAuthHeader, 0, MUTUAL_AUTH_HEADER_LENGTH);
}

uint8_t ma_communication_init(uint8_t initCurl,
                              uint8_t enableLogger,
                              uint8_t enableSecureChannel,
                              const char* urlRequestAS,
                              const char* urlRequestAP,
                              const uint8_t *appId,
                              size_t appIdSize,
                              const uint8_t *serverId,
                              size_t serverIdSize,
                              const uint8_t *sharedKey,
                              size_t sharedKeySize) {
    int8_t result = 0;

    if ( (!urlRequestAS) || (!urlRequestAS) ) {
        return MA_COMM_INVALID_PARAMETER;
    }

    if (enableLogger) {
        logger_enable();
    }

    if (initialized) {
        LOG("You cannot call init twice\n");
        return MA_COMM_INVALID_STATE;
    }

    initCommContext(&internalContext);

    internalContext.initCurl = initCurl;
    internalContext.isSecureChannelEnabled = enableSecureChannel;
    result = kerberos_protocol_init(urlRequestAS,
                                    urlRequestAP,
                                    appId,
                                    appIdSize,
                                    serverId,
                                    serverIdSize,
                                    sharedKey,
                                    sharedKeySize,
                                    &internalContext.pKerberosContext);
    if (result != 0) {
        LOG("Error to initialize kerberos context\n");
        return MA_COMM_INVALID_STATE;
    }

    if (internalContext.initCurl) {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    initialized = 1;
    LOG("MA comm initialized\n");
    return MA_COMM_SUCCESS;
}

uint8_t ma_communication_deinit() {
    if (!initialized) {
        LOG("MA communication is not initialized\n");
        return MA_COMM_INVALID_STATE;
    }

    if (internalContext.initCurl) {
        curl_global_cleanup();
    }

    kerberos_protocol_deinit(&internalContext.pKerberosContext);
    memset(internalContext.mutualAuthHeader, 0, MUTUAL_AUTH_HEADER_LENGTH);

    LOG("MA comm deinitialized\n");
    return MA_COMM_SUCCESS;
}

uint8_t ma_communication_send(const char *url,
                              char * httpMethod,
                              struct curl_slist **headers,
                              unsigned char* content,
                              size_t contentSize,
                              uint32_t *httpStatusCode,
                              unsigned char** pResponse,
                              size_t *responseSize) {

    int32_t result = 0;
    uint8_t* pContentToSend = content;
    size_t contentToSendSize = contentSize;
    *httpStatusCode = 0;
    if ((!url) || (!content) || (!responseSize) ) {
        if (*headers) {
            curl_slist_free_all(*headers);
            *headers = NULL;
        }
        LOG("Invalid parameter\n");
        return MA_COMM_INVALID_PARAMETER;
    }

    if (!initialized) {
        if (*headers) {
            curl_slist_free_all(*headers);
            *headers = NULL;
        }
        LOG("MA communication is not initialized\n");
        return MA_COMM_INVALID_STATE;
    }

    if (!kerberos_protocol_is_mutual_authenticated(internalContext.pKerberosContext)) {
        LOG("The application is not mutual authenticated\n");
        result = kerberos_protocol_execute_handshake(internalContext.pKerberosContext);
        if (result != MA_COMM_SUCCESS) {
            if (*headers) {
                curl_slist_free_all(*headers);
                *headers = NULL;
            }
            LOG("Fail to execute kerberos handshake. Error %d\n", result);
            return MA_COMM_INVALID_STATE;
        }
        rebuildMutualAuthenticationHeader();
    } else {
        LOG("The application is mutual authenticated\n");
    }

    if ( (internalContext.isSecureChannelEnabled) && (contentSize > 0) ){
        LOG("Ciphering the content\n");
        uint8_t *cipherContent = NULL;
        size_t cipherContentSize = 0;

        //todo change this call to a secure random generator
        uint8_t iv[IV_LENGTH];
        generateRandom(iv, IV_LENGTH);

        //encrypt
        result = changeIvAndEncryptTo(iv,
                                      IV_LENGTH,
                                      NULL,
                                      0,
                                      content,
                                      contentSize,
                                      &cipherContent,
                                      &cipherContentSize);
        if (result != SUCCESSFULL_OPERATION) {
            if (*headers) {
                curl_slist_free_all(*headers);
                *headers = NULL;
            }
            LOG("Fail to encrypt content\n");
            return MA_COMM_INVALID_STATE;
        }

        // concatenate iv with the ciphered data
        result = concatIvWithCipheredData(iv,
                                          IV_LENGTH,
                                          cipherContent,
                                          cipherContentSize,
                                          &pContentToSend,
                                          &contentToSendSize);
        free(cipherContent);
        if (result != MA_COMM_SUCCESS) {
            if (*headers) {
                curl_slist_free_all(*headers);
                *headers = NULL;
            }
            LOG("Fail to allocate memory\n");
            return MA_COMM_OUT_OF_MEMORY;
        }
    }

    // set the headers
    *headers = curl_slist_append(*headers, internalContext.mutualAuthHeader);

    // send the message
    uint8_t* pResponseAux = NULL;
    size_t responseSizeAux = 0;

    result = send_message(url,
                          httpMethod,
                          headers,
                          pContentToSend,
                          contentToSendSize,
                          httpStatusCode,
                          &pResponseAux,
                          &responseSizeAux);
    if (internalContext.isSecureChannelEnabled) {
        free(pContentToSend);
    }

    if (result != SUCCESSFULL_OPERATION) {
        LOG("Fail to send message\n");
        return MA_COMM_INVALID_STATE;
    }

    if ( (internalContext.isSecureChannelEnabled) && (responseSizeAux > 0) ) {
        LOG("Deciphering the response\n");
        uint8_t *plainContent = NULL;
        size_t plainContentSize = 0;

        // retrieve the iv
        size_t offset = 0;
        uint8_t ivLength = pResponseAux[0];
        offset += 1;
        uint8_t* iv = NULL;
        iv = (uint8_t*) malloc(ivLength);
        if (!iv) {
            free(pResponseAux);
            LOG("Fail to allocate memory\n");
            return MA_COMM_OUT_OF_MEMORY;
        }

        memcpy(iv, &pResponseAux[offset], ivLength);
        offset += ivLength;

        // decrypt
        result = changeIvAndDecryptTo(iv,
                                      ivLength,
                                      NULL,
                                      0,
                                      &pResponseAux[offset],
                                      responseSizeAux - offset,
                                      &plainContent,
                                      &plainContentSize);
        free(iv);
        free(pResponseAux);
        if (result != SUCCESSFULL_OPERATION) {
            LOG("Fail to decrypt response\n");
            return MA_COMM_INVALID_STATE;
        }
        pResponseAux = plainContent;
        responseSizeAux = plainContentSize;
    }

    *pResponse = pResponseAux;
    *responseSize = responseSizeAux;

    return MA_COMM_SUCCESS;
}

uint8_t concatIvWithCipheredData(uint8_t *iv,
                                 size_t ivLength,
                                 uint8_t *cipherData,
                                 size_t cipherDataLength,
                                 uint8_t **concatData,
                                 size_t *concatDataLength) {

    size_t finalContentSize = cipherDataLength + ivLength + 1;
    size_t offset = 0;

    if (ivLength > 255) {
        return MA_COMM_INVALID_PARAMETER;
    }

    uint8_t* finalContent = malloc(finalContentSize);
    if (!finalContent) {
        return MA_COMM_OUT_OF_MEMORY;
    }

    finalContent[0] = ivLength;
    offset += 1;
    memcpy(&finalContent[offset], iv, ivLength);
    offset += IV_LENGTH;
    memcpy(&finalContent[offset], cipherData, cipherDataLength);
    offset += cipherDataLength;

    *concatData = finalContent;
    *concatDataLength = finalContentSize;
    return MA_COMM_SUCCESS;
}

uint8_t rebuildMutualAuthenticationHeader() {

    uint8_t sessionId[SESSION_ID_LENGTH];
    memset(internalContext.mutualAuthHeader, 0, MUTUAL_AUTH_HEADER_LENGTH);

    kerberos_protocol_get_session_id(internalContext.pKerberosContext,
                                     SESSION_ID_LENGTH,
                                     sessionId);
    uint32_t j = 0;
    uint32_t i = 0;
    //todo do the error checking
    j = snprintf(internalContext.mutualAuthHeader,
                 MUTUAL_AUTH_HEADER_LENGTH,
                 "ma-session-id: ");
    for (i = 0; i < SESSION_ID_LENGTH; ++i, j+=2) {
        snprintf(&internalContext.mutualAuthHeader[j],
                 MUTUAL_AUTH_HEADER_LENGTH,
                 "%02x",
                 sessionId[i]);
    }

    return MA_COMM_SUCCESS;
}
