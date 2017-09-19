#ifndef CRYPTO_KERBEROS_H_
#define CRYPTO_KERBEROS_H_

#include "aes.h"
#include "errno.h"
#include <stdlib.h>
#include <string.h> 

/* Supports cipher with block size not bigger than 16 bytes */
#define MAX_BLOCK_SIZE	16	
#define MAX_TAG_SIZE	16

#define TAB_LBIT    3 /* (2^TAB_LBIT)-bit tables */
#define TAB_BITS    (1 << TAB_LBIT)
#define TAB_INTS    4 /* optimized for 128-bit blocks, twice as much as needed for 64-bit blocks */

typedef uint32_t gtab_t[1 << TAB_BITS][TAB_INTS];

typedef struct {
    uint8_t blockSize;
    uint8_t blockBits;
    uint8_t blockInts;
    uint16_t numTabs;
    uint32_t R;
    gtab_t *G;  // GF(2^128) multiplication tables
    uint8_t* X;    // CW accumulator
    uint8_t rem;   // remaining space on X, in bytes
    uint64_t lenA;
    uint64_t lenC;
    uint32_t *Z;
    uint8_t state;
	uint8_t tagLen;
} ghash_ctx_st;

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
	
	/* Buffer for data which hasn't been ghashed */
	uint8_t buffer[MAX_BLOCK_SIZE];
	uint8_t bufferOffset;

	/* AAD */
	uint8_t aad[MAX_BLOCK_SIZE];
	uint8_t aadOffset;

	uint8_t tagSize;
	uint8_t Y0[MAX_BLOCK_SIZE]; /* Initial counter. Considering sizeof(uint32_t) == 4 */
	uint8_t E0[MAX_BLOCK_SIZE]; /* Tag Mask */
	uint8_t Vt[MAX_BLOCK_SIZE];

	/* Counter mode context */
	ctr_ctx_st ctr_ctx;
	/* Ghash context */
	ghash_ctx_st ghash_ctx;

} gcm_ctx_st;

errno_t initCryptoKerberos(uint8_t /* keyLength */, uint8_t /* ivLength */, uint8_t /* tagLength */, uint8_t* /* key */, uint8_t* /* iv */);

errno_t decryptKerberos(uint8_t* /* aad */, size_t /* aadLength */, uint8_t* /* ciphertext */, size_t /* ciphertextLength */, 
																					uint8_t** /* plaintext */, size_t* /* plaintextLength */);
                                                               
                                                               


errno_t gcmInit(gcm_ctx_st* /* ctx */, uint8_t /* blockSize */, uint8_t /* dir */, uint8_t* /* nonce */, 
									uint32_t /* nonceLength */, uint8_t /* tagSize */, void* /* blockCipherCtx */, 
									errno_t /*blockCipher*/(const uint8_t*, uint8_t *, void*));

errno_t gcmUpdateAAD(gcm_ctx_st* /* ctx */, const uint8_t* /* input */, uint32_t /* inputLen */, uint32_t /* inputOffset */);

errno_t gcmUpdate(gcm_ctx_st* /* ctx */, const uint8_t* /* input */, uint32_t /* inputLen */, uint32_t /* inputOffset */, uint8_t* /* output */, 
										uint32_t /* outputLen */, uint32_t* /* outputOffset */);

errno_t gcmFinal(gcm_ctx_st* /* ctx */, const uint8_t* /* input */, uint32_t /* inputLen */, uint32_t /* inputOffset */, uint8_t* /* output */, 
									   uint32_t /* outputLen */, uint32_t* /* outputOffset */);

errno_t gcmCalculateOutputSize(gcm_ctx_st* /* ctx */, uint32_t /* inputLen */, uint32_t* /* outputLen */);

errno_t gcmInitNonce(gcm_ctx_st* /* ctx */, uint8_t* /* nonce */, uint32_t /* nonceLength */);

errno_t gcmClearContext(gcm_ctx_st* /* ctx */);

errno_t gcmCheckContext(gcm_ctx_st* /* ctx */);
#endif
