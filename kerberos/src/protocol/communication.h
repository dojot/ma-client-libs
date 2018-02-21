#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include "../encoder/constants.h"
#include "../encoder/errno.h"
#include "utils.h"

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief
 * @param[in] encodedInput
 * @param[in] encodedLength
 * @param[in] host
 * @param[in] path
 * @param[out] pResponse
 * @param[out] pResponseSize
 * @return SUCCESSFULL_OPERATION if success
 */
errno_t send_message(uint8_t* encodedInput,
                     size_t encodedLength,
                     uint8_t* host,
					 uint8_t* path,
					 uint8_t** pResponse,
					 size_t* pResponseSize);

#endif /* COMMUNICATION_H_ */
