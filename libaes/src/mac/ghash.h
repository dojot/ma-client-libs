#ifndef GHASH_H_
#define GHASH_H_

#include <stdint.h>

#include "../util/cryptoutil.h"
#include "../util/codes.h"
#include "../util/secureutil.h"


#ifdef _MSC_VER
//typedef unsigned __int64 ulen;
#else
//typedef uint64_t long ulen;
#endif

#ifdef errno
	#include <errno.h>
#else
	#include "../util/errno.h"
#endif

#define TRUE 1
#define FALSE 0

/*
 * Limits the quantity of AAD and plaintext that can be processed. Actually,
 * the maximum values defined by the standard are a little bigger than the
 * values used here.
 */
#define GCM_MAX_INPUT	68719476736ULL			//(2 << 35)
#define GCM_MAX_IV		2305843009213693952ULL	//(2 << 60)
#define GCM_MAX_AAD		2305843009213693952ULL		//(2 << 60)

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

errno_t ghashInit(ghash_ctx_st* /* ctx */, uint8_t /* blockSize */, uint8_t /* tagLen */, const uint32_t* /* H */);

void ghashInitState(ghash_ctx_st* /* ctx */);

errno_t ghashClearCtx(ghash_ctx_st* /* ctx */);

errno_t ghashUpdate(ghash_ctx_st* /* ctx */, const uint8_t* /* input */, uint32_t /* inputLen */, uint8_t /* isAAD */);

errno_t ghashFinal(ghash_ctx_st* /* ctx */, uint8_t* /* output */, uint32_t /* outputLen */, uint32_t* /* outputOffset */);

void ghashMultXH(ghash_ctx_st* /* ctx */);

errno_t ghashFinish(ghash_ctx_st* /* ctx */, uint8_t /* isAAD */);

errno_t ghashClearContext(ghash_ctx_st* /* ctx */);

errno_t ghashCheckContext(ghash_ctx_st* /* ctx */);

#endif /* GHASH_H_ */

