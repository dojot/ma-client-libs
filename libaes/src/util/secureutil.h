#ifndef SECUREUTIL_
#define SECUREUTIL_

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "codes.h"
#ifdef errno
	#include <errno.h>
#else
	#include "../util/errno.h"
#endif

/* Secure arithmetic operations for unsigned values */
errno_t add_s(uint32_t /* op1 */, uint32_t /* op2 */, uint32_t* /* res */);
errno_t sub_s(uint32_t /* op1 */, uint32_t /* op2 */, uint32_t* /* res */);
errno_t mul_s(uint32_t /* op1 */, uint32_t /* op2 */, uint32_t* /* res */);
errno_t div_s(uint32_t /* op1 */, uint32_t /* op2 */, uint32_t* /* res */);

/* Secure parameters check */
errno_t checkIfValidParameters(const uint8_t* /* input */, uint8_t* /* output */, uint32_t* /* outputOffset */);

errno_t calculateFullBlocks(uint32_t /* blockSize */, uint32_t /* bufferOffset */, uint32_t /* inputLen */, uint32_t* /* fullBlocks */);
errno_t calculateRemainingBytes(uint32_t /* blockSize */, uint32_t /* bufferOffset */, uint32_t /* inputLen */, uint32_t /* fullBlocks */, uint32_t* /* remainingBytes */);

errno_t memset_s(void* /* v */, size_t /* smax */, uint8_t /* c */, size_t /* n */);
errno_t resize_s(uint8_t** /* data */, uint32_t /* currentSize */, uint32_t /* newSize */);
#endif /* SECUREUTIL_ */