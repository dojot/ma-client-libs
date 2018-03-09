#include "communication.h"

#include <stdlib.h>
#include <curl/curl.h>

#include "logger/logger.h"
#include "ma_comm_error_codes.h"

#define INITIAL_BUFFER_SIZE 1024

typedef struct SBufferStruct {
  char *pData;
  size_t size;
} BufferStruct;

size_t process_chuck(void *pContent, size_t size, size_t nmemb, void *pUserPtr) {
    size_t realSize = size * nmemb;
    BufferStruct *pBuffer = (BufferStruct *)pUserPtr;

    // check if there is sufficient space in our buffer
    if (pBuffer->size + realSize > INITIAL_BUFFER_SIZE) {
        pBuffer->pData = realloc(pBuffer->pData, pBuffer->size + realSize);
        if(!pBuffer->pData) {
          // out of memory!
          LOG("not enough memory (realloc returned NULL)\n");
          return 0;
        }
    }

    // update the buffer's content and size
    memcpy(&(pBuffer->pData[pBuffer->size]), pContent, realSize);
    pBuffer->size += realSize;

    return realSize;
}

/*
 * Sends binary data to the Kerberos service.
 * Upon receipt of a reply, the callback method specified in loader.addEventListener is called
 */
uint8_t send_message(const char* url,
                     const char** headers,
                     const size_t numHeaders,
                     uint8_t* encodedInput,
                     size_t encodedLength,
                     uint8_t** pResponse,
                     size_t* pResponseSize) {
    CURLcode res;
    BufferStruct buffer;
    uint8_t result = 0;
    CURL *pCurlHandler = NULL;
    struct curl_slist *pSlist = NULL;

    // initialize output parameters
    *pResponseSize = 0;
    *pResponse = NULL;

    // initialize the buffer with INITIAL_BUFFER_SIZE
    buffer.size = 0;
    buffer.pData = (char*) malloc(INITIAL_BUFFER_SIZE);
    if (!buffer.pData) {
        goto FAIL;
    }

    // initialize the curl handler
    pCurlHandler = curl_easy_init();
    if(!pCurlHandler){
        goto FAIL;
    }

    // set the headers
    pSlist = curl_slist_append(pSlist, "Content-Type: application/x-www-form-urlencoded");
    size_t i = 0;
    for(i = 0; i < numHeaders; ++i) {
        pSlist = curl_slist_append(pSlist, headers[i]);
    }

    // prepare the request
    curl_easy_setopt(pCurlHandler, CURLOPT_HTTPHEADER, pSlist);
    curl_easy_setopt(pCurlHandler, CURLOPT_URL, url);
    curl_easy_setopt(pCurlHandler, CURLOPT_POSTFIELDSIZE, encodedLength);
    curl_easy_setopt(pCurlHandler, CURLOPT_POSTFIELDS, encodedInput);
    curl_easy_setopt(pCurlHandler, CURLOPT_WRITEFUNCTION, process_chuck);
    curl_easy_setopt(pCurlHandler, CURLOPT_WRITEDATA, (void *)&buffer);

    res = curl_easy_perform(pCurlHandler);
    if (res != CURLE_OK) {
        LOG("send message failed: %s\n", curl_easy_strerror(res));
        goto FAIL;
    } else {
        *pResponseSize = buffer.size;
        *pResponse = buffer.pData;
        goto SUCCESS;
    }

FAIL:
    result = MA_COMM_INVALID_STATE;
    if (buffer.pData) {
        free(buffer.pData);
    }
    goto CLEAN_UP;

SUCCESS:
    result = MA_COMM_SUCCESS;

CLEAN_UP:
    if (pCurlHandler) {
        curl_easy_cleanup(pCurlHandler);
    }
    if (pSlist) {
        curl_slist_free_all(pSlist);
    }

    return result;
}
