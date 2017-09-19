/*
 * ghash.cpp
 *
 * The GHASH Carter-Wegman message authentication code over GF(2^128).
 *
 * @author Paulo S. L. M. Barreto
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ghash.h"

#define GHASH_A 1UL
#define GHASH_C 2UL
#define GHASH_E 3UL

#define TAB_TOPX    (1 << (TAB_BITS - 1))

errno_t ghashInit(ghash_ctx_st* ctx, uint8_t blockSize, uint8_t tagLen, const uint32_t* H) {
	errno_t result;
	int32_t k;
	uint32_t u, s, i, j;
	uint32_t *G_s, *G_d, *G_ti, *G_tj, *G_tk;

	if(H == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	ctx->tagLen = (tagLen < blockSize && tagLen != 0) ? tagLen : blockSize;
    ctx->blockSize = blockSize;
    ctx->blockBits = blockSize << 3;
    ctx->blockInts = blockSize >> 2;
    ctx->R = ( ctx->blockBits == 128) ? 0xE1000000 : 0xD8000000;

    ctx->X = (uint8_t*)calloc(blockSize, sizeof(uint8_t));
	if(ctx->X == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

    // compute the GF(2^m) multiplication tables:
	ctx->numTabs = blockSize << (3 - TAB_LBIT);
    ctx->G = (gtab_t *)calloc(ctx->numTabs, sizeof(gtab_t));
	if(ctx->G == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL_X;
	}

    G_s = ctx->G[0][TAB_TOPX];
    memmove(G_s, H, blockSize);

    for (u = 1; u <  ctx->blockBits; u++) {
        //uint *G_d = G[u / TAB_BITS][TAB_TOPX >> (u % TAB_BITS)];
        G_d = ctx->G[u >> TAB_LBIT][TAB_TOPX >> (u & (TAB_BITS-1))];
        for (k = ctx->blockInts - 1; k > 0; k--) {
            G_d[k] = (G_s[k] >> 1) ^ (G_s[k-1] << 31);
        }
        G_d[0] = (G_s[0] >> 1) ^ ((G_s[ctx->blockInts - 1] & 1) == 1 ? ctx->R : 0);
        G_s = G_d;
    }
	
    for (s = 0; s < ctx->numTabs; s++) {
        for (i = 2; i <= TAB_TOPX; i <<= 1) {
            G_ti = ctx->G[s][i];
            for (j = 1; j < i; j++) {
                G_tj = ctx->G[s][j], G_tk = ctx->G[s][i + j];
                for (k = ctx->blockInts-1; k >= 0; k--) {
                    G_tk[k] = G_ti[k] ^ G_tj[k];
                }
            }
        }
    }
	ctx->Z = (uint32_t *)calloc(ctx->blockInts, 4);
	if(ctx->Z == NULL) {
		result = INVALID_STATE;
		goto FAIL_G;
	}

	ghashInitState(ctx);
	result = SUCCESSFULL_OPERATION;
	goto SUCCESS;
FAIL_G:
	result |= memset_s(ctx->G, ctx->numTabs * sizeof(uint8_t), 0, ctx->numTabs * sizeof(uint8_t));
	free(ctx->G);
FAIL_X:
	result |= memset_s(ctx->X, blockSize * sizeof(uint8_t), 0, blockSize * sizeof(uint8_t));
	free(ctx->X);
FAIL:
SUCCESS:
	return result;
}

void ghashInitState(ghash_ctx_st* ctx) {
    memset(ctx->X, 0, ctx->blockSize);
    ctx->rem = 0;
    ctx->lenA = 0ULL;
    ctx->lenC = 0ULL;
    ctx->state = GHASH_A; // ready to process AAD
}



/**
 * Update the GHASH tag computation with a message (AAD or ciphertext) chunk.
 * @param   M   AAD or ciphertext chunk
 * @param   m   its length in bytes
 * @param   aad whether the message chunk is part of the AAD (or else the ciphertext)
 */
errno_t ghashUpdate(ghash_ctx_st* ctx, const uint8_t *input, uint32_t inputLen, uint8_t isAAD) {
	errno_t result;
	uint32_t i, process;
	uint64_t aadLen, messageLen;

    if (isAAD == TRUE) {
		if (ctx->state != GHASH_A) {
			result = INVALID_STATE;
			goto FAIL;
		}
		messageLen = ctx->lenA + (inputLen << 3);
		if(messageLen < ctx->lenA || messageLen > GCM_MAX_INPUT) {
			result = INVALID_STATE;
			goto FAIL;
		}
		ctx->lenA = messageLen;
	} else {
		if (ctx->state == GHASH_A) {
			ghashFinish(ctx, TRUE);
		} else if (ctx->state != GHASH_C) {
			result = INVALID_STATE;
			goto FAIL;
		}
		
		aadLen = ctx->lenC + (inputLen << 3);
		if(aadLen < ctx->lenC || aadLen > GCM_MAX_AAD) {
			result = INVALID_STATE;
			goto FAIL;
		}
		ctx->lenC = aadLen;
	}

	/* 
	 * Although based on Paulo's implementation, it was better to change the
	 * the X calculation code. The code below allows partial updates, while
	 * the original one didn't support such case.
	 */
	while(inputLen > 0) {
		process = (inputLen >= (ctx->blockSize - ctx->rem)) ? (ctx->blockSize - ctx->rem) : inputLen;
		for(i = 0; i < process; i++) {
			ctx->X[ctx->rem + i] ^= input[i];
		}
		ctx->rem += (uint8_t)process;
		inputLen -= process;
		input += process;
		if(ctx->rem == ctx->blockSize) {
			 // multiply X by H:
			ghashMultXH(ctx);
			ctx->rem = 0;
		}
	}
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

/**
 * Complete a phase (AAD or ciphertext) of the GHASH computation.
 * @param   aad whether the message chunk is part of the AAD (or else the ciphertext)
 */
errno_t ghashFinish(ghash_ctx_st* ctx, uint8_t isAAD) {
	errno_t result;
	int32_t i, s;

	result = ghashCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

    if (ctx->state != (isAAD == TRUE ? GHASH_A : GHASH_C)) {
		result = INVALID_STATE;
		goto FAIL;
    }

    if (ctx->rem != 0) {
        ghashMultXH(ctx);
        ctx->rem = 0;
    }
    if (isAAD == TRUE) {
        ctx->state = GHASH_C; // ready to process the ciphertext
    } else {
        if (ctx->blockBits == 128) {
            for (i = 0, s = 56; s >= 0; i++, s -= 8) {
                ctx->X[i] ^= (uint8_t)(ctx->lenA >> s);
                ctx->X[i + 8] ^= (uint8_t)(ctx->lenC >> s);
            }
        } else {
            for (i = 0, s = 56; s >= 0; i++, s -= 8) {
                ctx->X[i] ^= (uint8_t)(ctx->lenA >> s);
            }
            ghashMultXH(ctx);
            for (i = 0, s = 56; s >= 0; i++, s -= 8) {
                ctx->X[i] ^= (uint8_t)(ctx->lenC >> s);
            }
        }
        ghashMultXH(ctx);
        ctx->state = GHASH_E; // GHASH tag is available
    }
FAIL:
	return result;	
}

errno_t ghashFinal(ghash_ctx_st* ctx, uint8_t* output, uint32_t outputLen, uint32_t* outputOffset) {
	errno_t result;
	result = ghashCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if (ctx->state == GHASH_A) {
		result = ghashFinish(ctx, TRUE);
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL;
		}
	}
	if (ctx->state == GHASH_C) {
		result = ghashFinish(ctx, FALSE);
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL;
		}
	}
	
	if(*outputOffset + ctx->blockSize > outputLen) {
		result = INVALID_OUTPUT_SIZE;
		goto FAIL;
	}

	memmove(output + *outputOffset, ctx->X, ctx->blockSize);
	*outputOffset += ctx->blockSize;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

void ghashMultXH(ghash_ctx_st* ctx) {
    uint32_t* Gsw;
	gtab_t* G = ctx->G;
	uint8_t* X = (uint8_t*)ctx->X;
	uint32_t* Z = ctx->Z;

    if (ctx->blockBits == 128) {
        Z[0] = Z[1] = Z[2] = Z[3] = 0;
        /*
        for (uint8_t s = 0; s < block_size; s++) {
            Gsw = G[s][X[s] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        }
        */
        Gsw = G[ 0][X[ 0] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[ 1][X[ 1] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[ 2][X[ 2] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[ 3][X[ 3] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[ 4][X[ 4] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[ 5][X[ 5] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[ 6][X[ 6] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[ 7][X[ 7] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[ 8][X[ 8] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[ 9][X[ 9] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[10][X[10] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[11][X[11] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[12][X[12] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[13][X[13] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[14][X[14] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];
        Gsw = G[15][X[15] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1]; Z[2] ^= Gsw[2]; Z[3] ^= Gsw[3];

    } else {
        Z[0] = Z[1] = 0;
        /*
        for (uint8_t s = 0; s < block_size; s++) {
            Gsw = G[s][X[s] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1];
        }
        */
        Gsw = G[ 0][X[ 0] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1];
        Gsw = G[ 1][X[ 1] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1];
        Gsw = G[ 2][X[ 2] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1];
        Gsw = G[ 3][X[ 3] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1];
        Gsw = G[ 4][X[ 4] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1];
        Gsw = G[ 5][X[ 5] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1];
        Gsw = G[ 6][X[ 6] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1];
        Gsw = G[ 7][X[ 7] & 0xFF]; Z[0] ^= Gsw[0]; Z[1] ^= Gsw[1];
    }
	unpackWordBigEndian(ctx->Z[0], ctx->X,  0);
	unpackWordBigEndian(ctx->Z[1], ctx->X,  4);
	unpackWordBigEndian(ctx->Z[2], ctx->X,  8);
	unpackWordBigEndian(ctx->Z[3], ctx->X, 12);
}

errno_t ghashClearContext(ghash_ctx_st* ctx) 
{
	errno_t result;

	if(ctx == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = memset_s(ctx->G, ctx->numTabs * sizeof(gtab_t), 0, ctx->numTabs * sizeof(gtab_t));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = memset_s(ctx->X, ctx->blockSize, 0, ctx->blockSize);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = memset_s(ctx->Z, ctx->blockSize, 0, ctx->blockSize);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	free(ctx->G);
	free(ctx->X);
	free(ctx->Z);
	result = memset_s(ctx, sizeof(ghash_ctx_st), 0, sizeof(ghash_ctx_st));	
FAIL:
	return result;
}

errno_t ghashCheckContext(ghash_ctx_st *ctx)
{
	errno_t result;

	if(ctx == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(ctx->X == NULL || ctx->G == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	if(ctx->R != 0xE1000000 && ctx->R != 0xD8000000) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if( ((ctx->blockSize << 3) != ctx->blockBits) || ((ctx->blockSize >> 2) != ctx->blockInts) ){
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(ctx->numTabs != ctx->blockSize << (3 - TAB_LBIT)) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}
