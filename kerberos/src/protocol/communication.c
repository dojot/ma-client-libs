#include "communication.h"

#include <stdlib.h>

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
                     const char *method,
                     struct curl_slist **headers,
                     uint8_t* encodedInput,
                     size_t encodedLength,
                     uint32_t* httpStatusCode,
                     uint8_t** pResponse,
                     size_t* pResponseSize) {
    CURLcode res;
    BufferStruct buffer;
    uint8_t result = 0;
    CURL *pCurlHandler = NULL;

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

    // set the http method
    curl_easy_setopt(pCurlHandler, CURLOPT_CUSTOMREQUEST, method);

    // set the headers
    if (*headers) {
        curl_easy_setopt(pCurlHandler, CURLOPT_HTTPHEADER, *headers);
    }

    // prepare the request
    curl_easy_setopt(pCurlHandler, CURLOPT_URL, url);
    if (encodedLength > 0) {
        curl_easy_setopt(pCurlHandler, CURLOPT_POSTFIELDSIZE, encodedLength);
        curl_easy_setopt(pCurlHandler, CURLOPT_POSTFIELDS, encodedInput);
    }
    curl_easy_setopt(pCurlHandler, CURLOPT_WRITEFUNCTION, process_chuck);
    curl_easy_setopt(pCurlHandler, CURLOPT_WRITEDATA, (void *)&buffer);

    res = curl_easy_perform(pCurlHandler);
    if (res != CURLE_OK) {
        LOG("send message failed: %s\n", curl_easy_strerror(res));
        goto FAIL;
    } else {
        curl_easy_getinfo (pCurlHandler, CURLINFO_RESPONSE_CODE, httpStatusCode);
        LOG("http status code: %u\n", *httpStatusCode);
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
    if (*headers) {
        curl_slist_free_all(*headers);
        *headers = NULL;
    }

    return result;
}
