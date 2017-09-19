#ifndef AES_KERBEROS_H_
#define AES_KERBEROS_H_

#include <stdio.h>
#include <stdint.h>

#include "codes.h"
#include "errno.h"

#define MAXNR 14

typedef struct aes_ctx_st {
	uint8_t Nk, Nw, Nr;
	uint16_t keysize;
	uint32_t e_sched[4*(MAXNR + 1)];
	uint32_t d_sched[4*(MAXNR + 1)];
	uint8_t direction;
} aes_ctx_st;

errno_t aesInit_(uint8_t* /* key */, uint16_t /* keySize */, uint8_t /* dir */, aes_ctx_st* /* ctx */);
errno_t aesClearContext_(aes_ctx_st* /* ctx */);
errno_t aesProcessBlock_(const uint8_t* /* input */, uint8_t* /* output */, void* /* ctx */);
errno_t aesCheckContext_(aes_ctx_st* /* ctx */);

#endif /* AES_KERBEROS_H_ */
