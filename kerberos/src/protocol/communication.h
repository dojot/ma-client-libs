#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include <stdint.h>
#include <string.h>
#include <curl/curl.h>

uint8_t send_message(const char* url,
                     const char *method,
                     struct curl_slist **headers,
                     uint8_t* encodedInput,
                     size_t encodedLength,
                     uint32_t* httpStatusCode,
                     uint8_t** pResponse,
                     size_t* pResponseSize);

#endif /* COMMUNICATION_H_ */
