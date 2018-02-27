#ifndef ECB_
#define ECB_

#include "../padding/padding.h"
#include "../util/cryptoutil.h"
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
	uint32_t blockSize;
	/* A specific block cipher context */
	void *blockCipherCtx; 
	/* The block cipher function itself */
	errno_t (*blockCipher)(const uint8_t* /* input */, uint8_t* /* output */, void* /* blockCipherCtx */);
	/* The padding scheme */
	PaddingScheme ps;
	/* Depending on the mode, decryption and encryption may be different */
	uint32_t dir;
	/* Counter mode needs a buffer */
	uint8_t buffer[MAX_BLOCK_SIZE];
	uint32_t bufferOffset;
} ecb_ctx_st;

errno_t ecbInit(ecb_ctx_st* /* ctx */, uint32_t /* blockSize */, uint32_t /* dir */, 
									void* /* blockCipherCtx */, errno_t /*blockCipher*/(const uint8_t*, uint8_t *, void*), 
									PaddingScheme /* ps */);

errno_t ecbUpdate(ecb_ctx_st* /* ctx */, const uint8_t* /* input */, uint32_t /* inputLen */, uint32_t /* inputOffset */, uint8_t* /* output */, 
										uint32_t /* outputLen */, uint32_t* /* outputOffset */);

errno_t ecbFinal(ecb_ctx_st* /* ctx */, const uint8_t* /* input */, uint32_t /* inputLen */, uint32_t /* inputOffset */, uint8_t* /* output */, 
									   uint32_t /* outputLen */, uint32_t* /* outputOffset */);

errno_t ecbCalculateOutputSize(ecb_ctx_st* /* ctx */, uint32_t /* inputLen */, uint32_t* /* outputLen */);

errno_t ecbClearContext(ecb_ctx_st* /* ctx */);

errno_t ecbCheckContext(ecb_ctx_st* /* ctx */);

#endif /* ECB_ */