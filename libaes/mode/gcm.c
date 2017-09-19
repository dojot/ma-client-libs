#include "gcm.h"
#include <stdio.h>

errno_t gcmInit(gcm_ctx_st* ctx, uint8_t blockSize, uint8_t dir, uint8_t *nonce, 
	uint32_t nonceLength, uint8_t tagSize, void* blockCipherCtx, errno_t blockCipher(const uint8_t*, uint8_t *, void*))
{
	errno_t result;
	uint32_t Y0[4];
	
	
	if(ctx == NULL || blockCipherCtx == NULL || blockCipher == NULL || nonce == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(blockSize != 8 && blockSize != 16) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	if(dir != DIR_ENCRYPTION && dir != DIR_DECRYPTION) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* It isn't necessary, because nonceLength is 32 bits only
	if(nonceLength >= GCM_MAX_IV) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	*/
	/* Nist recommended tag sizes Ref.: SP800-38D */
	switch(tagSize) {
	case 128:
	case 120:
	case 112:
	case 104:
	case 96:
	case 64:
	case 32:
		tagSize /= 8;
		break;
	case 16:
	case 15:
	case 14:
	case 13:
	case 12: 
	case 8:
	case 4:
		break;
	default:
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	ctx->blockCipher = blockCipher;
	ctx->tagSize = tagSize;
	ctx->blockSize = blockSize;
	ctx->blockCipherCtx = blockCipherCtx;
	ctx->dir = dir;
	ctx->bufferOffset = 0;
	ctx->aadOffset = 0;

	memset(ctx->Y0, 0, sizeof(uint8_t) * blockSize);
	memset(ctx->E0, 0, sizeof(uint8_t) * blockSize);
	memset(ctx->Vt, 0, sizeof(uint8_t) * blockSize);
	
	result = ctx->blockCipher(ctx->Y0, ctx->Y0, ctx->blockCipherCtx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	Y0[0] = packWordBigEndian(ctx->Y0, 0);
	Y0[1] = packWordBigEndian(ctx->Y0, 4);
	Y0[2] = packWordBigEndian(ctx->Y0, 8);
	Y0[3] = packWordBigEndian(ctx->Y0, 12);

	result = ghashInit(&ctx->ghash_ctx, ctx->blockSize, ctx->tagSize, Y0);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = memset_s(Y0, sizeof(Y0), 0, sizeof(Y0));
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = gcmInitNonce(ctx, nonce, nonceLength);
FAIL:
	return result;
}


errno_t gcmInitNonce(gcm_ctx_st* ctx, uint8_t *nonce, uint32_t nonceLength)
{
	errno_t result;
	uint32_t outputOffset = 0;
	if(nonceLength != 0) {
		if(ctx->blockSize == 16) {
			if(nonceLength == 12) {
				memcpy(ctx->Y0, nonce, nonceLength);
				memset(ctx->Y0 + nonceLength, 0, 4);
				ctx->Y0[ctx->blockSize - 1] = 1;
			} else {
				ghashInitState(&ctx->ghash_ctx);
				ghashUpdate(&ctx->ghash_ctx, nonce, nonceLength, FALSE);
				ghashFinal(&ctx->ghash_ctx, ctx->Y0, MAX_BLOCK_SIZE, &outputOffset);
			}
		} else {
			if (nonceLength == 4) {
				unpackWordBigEndian(1, ctx->Y0, 0);
				memcpy(ctx->Y0 + 4, nonce, nonceLength);
			} else {
				ghashInitState(&ctx->ghash_ctx);
				ghashUpdate(&ctx->ghash_ctx, nonce, nonceLength, FALSE);
				ghashFinal(&ctx->ghash_ctx, ctx->Y0, MAX_BLOCK_SIZE, &outputOffset);
			}
		}
	}
	outputOffset = 0;
	ghashInitState(&ctx->ghash_ctx);

	result = ctrInit(&ctx->ctr_ctx, ctx->blockSize, DIR_ENCRYPTION, ctx->Y0, ctx->blockCipherCtx, ctx->blockCipher);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	memset(ctx->E0, 0, ctx->blockSize);

	result = ctrUpdate(&ctx->ctr_ctx, ctx->E0, ctx->blockSize, 0, ctx->E0, ctx->blockSize, &outputOffset); // mask for the authentication tag
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

FAIL:
	return result;
}

/* 
* Process only complete blocks, incomplete ones are written to the buffer.
* input - Input to be encrypted or decrypted
* inputLen - Number of bytes to be processed
* inputOffset - Start index
* output - Result will be written to output
* outputLen - Output size not considering output offset
* outputOffset - Start index
* ctx - Context variable
*/
errno_t gcmUpdate(gcm_ctx_st* ctx, const uint8_t* input, uint32_t inputLen, uint32_t inputOffset, uint8_t* output, uint32_t outputLen, uint32_t* outputOffset)
{
	errno_t result;
	uint32_t outputOffsetBefore, outputOffsetAfter;

	result = gcmCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(input == NULL || output == NULL || outputOffset == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	outputOffsetBefore = *outputOffset;
	result = ctrUpdate(&ctx->ctr_ctx, input, inputLen, inputOffset, output, outputLen, outputOffset);
	outputOffsetAfter = *outputOffset;
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(ctx->dir == DIR_ENCRYPTION) {
		result = ghashUpdate(&ctx->ghash_ctx, output + outputOffsetBefore, outputOffsetAfter - outputOffsetBefore, FALSE);
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL;
		}
	} else if(ctx->dir == DIR_DECRYPTION) {
		result = ghashUpdate(&ctx->ghash_ctx, input + inputOffset, inputLen, FALSE);
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL;
		}
	}
FAIL:
	return result;
}

/* 
* Finishes operation and delete all sensitive data.
* input - Input to be encrypted or decrypted
* inputLen - Number of bytes to be processed, including the tag
* inputOffset - Start index
* output - Result will be written to output
* outputLen - Output size not considering output offset
* outputOffset - Start index
* ctx - Context variable
*/
errno_t gcmFinal(gcm_ctx_st* ctx, const uint8_t* input, uint32_t inputLen, uint32_t inputOffset, uint8_t* output, uint32_t outputLen, uint32_t* outputOffset)
{
	errno_t result;
	uint32_t outputOffsetBefore, outputOffsetAfter, i;
	uint32_t tagOffset = 0;
	uint8_t* tag = NULL;

	result = gcmCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
	    printf("gcmCheckContext failed\n");
		goto FAIL;
	}
	
	if(output == NULL || outputOffset == NULL) {
		result = INVALID_PARAMETER;
		printf("output or outputOffset null\n");
		goto FAIL;
	}
	
	if(ctx->dir == DIR_DECRYPTION && (inputLen < ctx->tagSize || input == NULL)) {
		result = INVALID_PARAMETER;
		printf("input null failed\n");
		goto FAIL;	
	}
	
	if(ctx->dir == DIR_DECRYPTION) {
		inputLen = inputLen - ctx->tagSize;
	}

	/* 
	 * The parameters used in here will be validated by ctrFinal, so there is no need to recalculate the necessary
	 * and the available space in the output buffer.
	 */
	outputOffsetBefore = *outputOffset;
	if(input != NULL) {
		result = ctrFinal(&ctx->ctr_ctx, input, inputLen, inputOffset, output, outputLen, outputOffset);
		if(result != SUCCESSFULL_OPERATION) {
		    printf("ctrFinal failed\n");
			goto FAIL;
		}
	}
	outputOffsetAfter = *outputOffset;
	
	/* Calcultates TAG */
	tag = (uint8_t*)malloc(sizeof(uint8_t) * ctx->blockSize);
	if(tag == NULL) {
		result = INVALID_STATE;
		printf("malloc failed\n");
		goto FAIL;
	}
	
	if(ctx->dir == DIR_ENCRYPTION) {
		/* Finish the ghash calculation */
		result = ghashUpdate(&ctx->ghash_ctx, output + outputOffsetBefore, outputOffsetAfter - outputOffsetBefore, FALSE);
		if(result != SUCCESSFULL_OPERATION) {
		    printf("ghashUpdate failed\n");
			goto FAIL_CLEAN;
		}
		result = ghashFinal(&ctx->ghash_ctx, tag, ctx->blockSize, &tagOffset);
		if(result != SUCCESSFULL_OPERATION) {
		    printf("ghashFinal failed\n");
			goto FAIL_CLEAN;
		}
		
	} else if(ctx->dir == DIR_DECRYPTION) {
		/* Finish the ghash calculation */
		result = ghashUpdate(&ctx->ghash_ctx, input + inputOffset, inputLen, FALSE);
		if(result != SUCCESSFULL_OPERATION) {
		    printf("ghashUpdate2 failed\n");
			goto FAIL_CLEAN;
		}
		result = ghashFinal(&ctx->ghash_ctx, tag, ctx->blockSize, &tagOffset);
		if(result != SUCCESSFULL_OPERATION) {
		    printf("ghashFinal2 failed\n");
			goto FAIL_CLEAN;
		}
	}
	/* Calculating the tag */
	for (i = 0; i < ctx->tagSize; i++) {
		tag[i] ^= ctx->E0[i];
	}

	/* Verifying the tag */
	if(ctx->dir == DIR_DECRYPTION) {
		if(compareArrayToArrayDiffConstant(tag, ctx->tagSize, input + inputOffset + inputLen, ctx->tagSize) != 0x00) {
		    printf("ctx->tagSize = %d\n", ctx->tagSize);
		    printf("inputOffset = %d\n", inputOffset);
		    printf("tagA: ");
		    for(i = 0; i < ctx->tagSize; i++){
		        printf("%02x", *(tag + i));
		    }
		    printf("\ntagB: ");
		    for(i = 0; i < ctx->tagSize; i++){
		        printf("%02x", *(input + inputOffset + i));
		    }
		    printf("\n");
		    
			result = INVALID_TAG;
			printf("compareArrayToArrayDiffConstant failed\n");
			goto FAIL_CLEAN;
		}
	/* Add tag to the output */
	} else if(ctx->dir == DIR_ENCRYPTION) {
		memcpy(output + *outputOffset, tag, ctx->tagSize);
		*outputOffset += ctx->tagSize;
	}
	result = SUCCESSFULL_OPERATION;
FAIL_CLEAN:
	result |= memset_s(tag, sizeof(uint8_t) * ctx->blockSize, 0, sizeof(uint8_t) * ctx->blockSize);
	free(tag);
FAIL:
	result |= gcmClearContext(ctx);
	return result;
}

errno_t gcmUpdateAAD(gcm_ctx_st* ctx, const uint8_t* input, uint32_t inputLen, uint32_t inputOffset)
{
	errno_t result;
	result = ghashUpdate(&ctx->ghash_ctx, input + inputOffset, inputLen, TRUE);
	return result;
}


errno_t gcmCalculateOutputSize(gcm_ctx_st* ctx, uint32_t inputLen, uint32_t *outputLen) 
{
	errno_t result;

	result = gcmCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* It may overestimate output size. But it doesn't matter */
	result = ctrCalculateOutputSize(&ctx->ctr_ctx, inputLen, outputLen);
	if(result != SUCCESSFULL_OPERATION)
		goto FAIL;

	*outputLen += ctx->blockSize;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t gcmClearContext(gcm_ctx_st* ctx)
{
	errno_t result;

	if(ctx == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = ctrClearContext(&ctx->ctr_ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = ghashClearContext(&ctx->ghash_ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = memset_s(ctx, sizeof(gcm_ctx_st), 0, sizeof(gcm_ctx_st));
FAIL:
	return result;
}

errno_t gcmCheckContext(gcm_ctx_st *ctx)
{
	errno_t result;

	if(ctx == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
		
	if(ctx->blockCipherCtx == NULL || ctx->blockCipher == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(ctx->blockSize != 8 && ctx->blockSize != 16) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(ctx->dir != DIR_ENCRYPTION && ctx->dir != DIR_DECRYPTION) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Nist recommend tag sizes Ref.: SP800-38D */
	if(ctx->tagSize != 16 && ctx->tagSize != 15 && ctx->tagSize != 14 && ctx->tagSize != 13 && ctx->tagSize != 12 && 
		ctx->tagSize != 8 && ctx->tagSize != 4) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = ctrCheckContext(&ctx->ctr_ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}
