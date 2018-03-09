#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include <stdint.h>
#include <string.h>

uint8_t send_message(const char* url,
                     const char** headers,
                     const size_t numHeaders,
                     uint8_t* encodedInput,
                     size_t encodedLength,
                     uint8_t** pResponse,
                     size_t* pResponseSize);

#endif /* COMMUNICATION_H_ */
