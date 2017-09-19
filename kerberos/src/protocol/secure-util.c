#include "secure-util.h"

/** 
  * Warning! This function does not generates secure random numbers.
  * However, because it is only used one time to generate the nonce for the kerberos protocol, 
  * there should be no problem.
*/
errno_t generateRandom(uint8_t* nonce, uint8_t nonceLength) 
{
	errno_t result = SUCCESSFULL_OPERATION;
	uint8_t i;

	memset(nonce, 0, sizeof(uint8_t) * nonceLength);
	for(i = 0; i < nonceLength; i++) {
		nonce[i] = rand() % 256;
	}	
	return result;
}
