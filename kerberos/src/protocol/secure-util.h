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

 /*
  * Wrapper function which uses cryptographic functions provided by LibCrypto.
  * Length parameters specify the size of the keys, ivs and tags that are being used.
  * Key and iv parameters specify the initial state of the cipher modes used to create the secure channel.
  */
errno_t initSecureChannel(uint8_t /* keyLength */, uint8_t /* ivLength */, uint8_t /* tagLen */, uint8_t* /* keyLocal */, 
							uint8_t* /* keyExtern */, uint8_t* /* ivLocal */, uint8_t* /* ivExtern */);

/*
 * Wrapper function which uses the encrypt function provided by LibCrypto.
 */
errno_t encrypt(uint8_t* /* aad */, size_t /* aadLen */, uint8_t* /* plaintext */, size_t /* plaintextLength */, uint8_t** /* ciphertext */, 
					size_t* /* ciphertextLength */);

/*
 * Wrapper function which uses the decrypt function provided by LibCrypto.
 */
errno_t decrypt(uint8_t* /* aad */, size_t /* aadLen */, uint8_t* /* ciphertext */, size_t /* ciphertextLength */, uint8_t** /* plaintext */,
					size_t* /* plaintextLength */);
							
#endif /* SECURE_UTIL_H_ */
