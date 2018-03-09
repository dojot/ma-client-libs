#include "requestAS.h"
#include <stdint.h>

#include "ma_comm_error_codes.h"
#include "logger/logger.h"

/* Fills the request */
uint8_t encodeRequestAS(RequestAS* requestAs,
                        uint8_t* cname,
                        size_t cnameLength,
                        uint8_t* sname,
                        size_t snameLength,
                        uint8_t* nonce,
                        size_t nonceLength) {

    // Input parameters validation
    if(!requestAs || !cname || !sname || !nonce) {
        return MA_COMM_INVALID_PARAMETER;
    }

    if(cnameLength != PRINCIPAL_NAME_LENGTH || snameLength != PRINCIPAL_NAME_LENGTH) {
        return MA_COMM_INVALID_PARAMETER;
    }

    initRequestAS(requestAs);

    memcpy(requestAs->cname, cname, sizeof(uint8_t) * cnameLength);
    memcpy(requestAs->sname, sname, sizeof(uint8_t) * snameLength);
    memcpy(requestAs->nonce, nonce, sizeof(uint8_t) * nonceLength);

    return MA_COMM_SUCCESS;
}

/* Generate byte array encodedOutput from requestAS */
uint8_t getEncodedRequestAS(RequestAS* requestAS,
                            uint8_t** encodedOutput,
                            size_t* encodedLength) {
    uint8_t result = 0;
    size_t encOffset = 0;

    /* Input parameters validation */
    if ( (!requestAS) || (!encodedOutput) || (!encodedLength) ) {
        return MA_COMM_INVALID_PARAMETER;
    }

    *encodedOutput = (uint8_t*) malloc(MESSAGE_CODE_LENGTH +
                                sizeof(requestAS->cname) +
                                sizeof(requestAS->sname) +
                                sizeof(requestAS->nonce));
    if(!*encodedOutput) {
        return MA_COMM_OUT_OF_MEMORY;
    }

    /* Serializes data to encodedOutput */
    **encodedOutput = REQUEST_AS_CODE;
    encOffset += MESSAGE_CODE_LENGTH;
    memcpy(*encodedOutput + encOffset, requestAS->cname, sizeof(requestAS->cname));
    encOffset += sizeof(requestAS->cname);
    memcpy(*encodedOutput + encOffset, requestAS->sname, sizeof(requestAS->sname));
    encOffset += sizeof(requestAS->sname);
    memcpy(*encodedOutput + encOffset, requestAS->nonce, sizeof(requestAS->nonce));
    encOffset += sizeof(requestAS->nonce);
    *encodedLength = encOffset;

    return MA_COMM_SUCCESS;
}

uint8_t initRequestAS(RequestAS* requestAs) {
    if (!requestAs) {
        return MA_COMM_INVALID_PARAMETER;
    }
    memset(requestAs->cname, 0, PRINCIPAL_NAME_LENGTH);
    memset(requestAs->sname, 0, PRINCIPAL_NAME_LENGTH);
    memset(requestAs->nonce, 0, NONCE_LENGTH);

    return MA_COMM_SUCCESS;
}

uint8_t eraseRequestAS(RequestAS* requestAs) {
    uint8_t result = MA_COMM_SUCCESS;

    /* Input validation */
    if(!requestAs) {
        return INVALID_PARAMETER;
    }

    /* Secure erase */
    result = memset_s(requestAs, sizeof(RequestAS), 0, sizeof(RequestAS));
    if(result != MA_COMM_SUCCESS) {
        return MA_COMM_INVALID_PARAMETER;
    }

    return MA_COMM_SUCCESS;
}

void dumpRequestAS(RequestAS *requestAs, uint8_t indent) {
    if ( (!requestAs) || (!logger_is_log_enabled()) ) {
        return;
    }

    uint8_t i = 0;
    LOG("%*sResquestAs:\n", indent, "");
    LOG("%*scname: ", indent + 1, "");
    for(i = 0; i < PRINCIPAL_NAME_LENGTH; ++i) {
        LOG("%02x", requestAs->cname[i]);
    }
    LOG("\n");
    LOG("%*ssname: ", indent + 1, "");
    for(i = 0; i < PRINCIPAL_NAME_LENGTH; ++i) {
        LOG("%02x", requestAs->sname[i]);
    }
    LOG("\n");
    LOG("%*snonce: ", indent + 1, "");
    for(i = 0; i < NONCE_LENGTH; ++i) {
        LOG("%02x", requestAs->nonce[i]);
    }
    LOG("\n");
}

