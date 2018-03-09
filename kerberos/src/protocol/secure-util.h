#ifndef SECURE_UTIL_H_
#define SECURE_UTIL_H_

#include "../encoder/constants.h"
#include "../encoder/errno.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* 
 *	Generates a random number with nonceLength bytes. This random number
 *  is gathered from the OS entropy pool. Error just indicates that 
 *  the underlying OS function wasn't able to generate the random bytes
 *  requested.
 */
errno_t generateRandom(uint8_t* /* nonce */, uint8_t /* nonceLength */);
							
#endif /* SECURE_UTIL_H_ */
