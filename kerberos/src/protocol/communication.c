#include "communication.h"

#include <curl/curl.h>
#include <stdio.h>

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
		  printf("not enough memory (realloc returned NULL)\n");
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
errno_t send_message(uint8_t* encodedInput,
					 size_t encodedLength,
					 uint8_t* host,
					 uint8_t* path,
					 uint8_t** pResponse,
					 size_t* pResponseSize) {
    CURLcode res;
    BufferStruct buffer;
    uint8_t result = 0;
    char* pUrl = NULL;
    size_t urlLen = 0;
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

    // configure the URL: host + path
    urlLen = strlen((char*)host) + strlen((char*)path);
    pUrl = (char*) malloc(sizeof(char) * (urlLen + 1));
    if(!pUrl){
    	goto FAIL;
    }
    strcpy(pUrl, host);
    strcat(pUrl, path);

    // initialize the curl handler
    pCurlHandler = curl_easy_init();
    if(!pCurlHandler){
    	goto FAIL;
    }

    // prepare the request
    pSlist = curl_slist_append(pSlist, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(pCurlHandler, CURLOPT_HTTPHEADER, pSlist);
    curl_easy_setopt(pCurlHandler, CURLOPT_URL, pUrl);
    curl_easy_setopt(pCurlHandler, CURLOPT_POSTFIELDSIZE, encodedLength);
    curl_easy_setopt(pCurlHandler, CURLOPT_POSTFIELDS, encodedInput);
    curl_easy_setopt(pCurlHandler, CURLOPT_WRITEFUNCTION, process_chuck);
    curl_easy_setopt(pCurlHandler, CURLOPT_WRITEDATA, (void *)&buffer);

    res = curl_easy_perform(pCurlHandler);
    if (res != CURLE_OK) {
    	printf("send message failed: %s\n", curl_easy_strerror(res));
    	goto FAIL;
    } else {
    	*pResponseSize = buffer.size;
    	*pResponse = buffer.pData;
    	goto SUCCESS;
    }

    FAIL:
    	result = !SUCCESSFULL_OPERATION;
    	if (buffer.pData) {
    		free(buffer.pData);
    	}
    	goto CLEAN_UP;

	SUCCESS:
		result = SUCCESSFULL_OPERATION;

	CLEAN_UP:
		if (pCurlHandler) {
			curl_easy_cleanup(pCurlHandler);
		}
		if (pSlist) {
			curl_slist_free_all(pSlist);
		}
		if (pUrl) {
			free(pUrl);
		}

    return result;
}
