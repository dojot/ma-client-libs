#ifndef AES_
#define AES_

#include "../util/cryptoutil.h"
#include "../util/secureutil.h"
#include "../util/codes.h"
#include "../util/errno.h"
#include <stdio.h>
#include <stdint.h>

#define MAXNR 14

typedef struct aes_ctx_st {
	uint8_t Nk, Nw, Nr;
	uint16_t keysize;
	uint32_t e_sched[4*(MAXNR + 1)];
	uint32_t d_sched[4*(MAXNR + 1)];
	uint8_t direction;
} aes_ctx_st;

errno_t aesInit(uint8_t* /* key */, uint16_t /* keySize */, uint8_t /* dir */, aes_ctx_st* /* ctx */);
errno_t aesClearContext(aes_ctx_st* /* ctx */);
errno_t aesProcessBlock(const uint8_t* /* input */, uint8_t* /* output */, void* /* ctx */);
errno_t aesCheckContext(aes_ctx_st* /* ctx */);

#endif /* AES_ */