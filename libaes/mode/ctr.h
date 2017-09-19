#ifndef CTR_
#define CTR_

#include "../util/cryptoutil.h"
#include "../util/codes.h"
#include "../util/secureutil.h"
#include <stdlib.h>
#include <string.h>

#ifdef errno
	#include <errno.h>
#else
	#include "../util/errno.h"
#endif

/* Supports cipher with block size not bigger than 16 bytes */
#define MAX_BLOCK_SIZE	16	

/* All values inside the structure are modified during execution */
typedef struct {
	/* Block cipher is the one who determines the size of the block in bytes */
	uint8_t blockSize;
	/* A specific block cipher context */
	void *blockCipherCtx; 
	/* The block cipher function itself */
	errno_t (*blockCipher)(const uint8_t* /* input */, uint8_t* /* output */, void* /* blockCipherCtx */);
	/* Depending on the mode, decryption and encryption may be different */
	uint8_t dir;
	uint8_t* iv;	
	/* Counter mode needs a buffer */
	uint8_t buffer[MAX_BLOCK_SIZE];
	uint8_t bufferOffset;
} ctr_ctx_st;

errno_t ctrInit(ctr_ctx_st* /* ctx */, uint8_t /* blockSize */, uint8_t /* dir */, uint8_t* /* iv */,
										void* /* blockCipherCtx */, errno_t /*blockCipher*/(const uint8_t*, uint8_t *, void*));


errno_t ctrUpdate(ctr_ctx_st* /* ctx */, const uint8_t* /* input */, uint32_t /* inputLen */, uint32_t /* inputOffset */, uint8_t* /* output */, 
										uint32_t /* outputLen */, uint32_t* /* outputOffset */);

errno_t ctrFinal(ctr_ctx_st* /* ctx */, const uint8_t* /* input */, uint32_t /* inputLen */, uint32_t /* inputOffset */, uint8_t* /* output */, 
									   uint32_t /* outputLen */, uint32_t* /* outputOffset */);

errno_t ctrClearContext(ctr_ctx_st* /* ctx */);

errno_t ctrCalculateOutputSize(ctr_ctx_st* /* ctx */, uint32_t /* inputLen */, uint32_t* /* outputLen */);

errno_t ctrCheckContext(ctr_ctx_st* /* ctx */);

#endif /* CTR_ */