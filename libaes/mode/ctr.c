#include "ctr.h"
#include <stdio.h>

errno_t ctrInit(ctr_ctx_st* ctx, uint8_t blockSize, uint8_t dir, uint8_t* iv, void* blockCipherCtx, errno_t blockCipher(const uint8_t*, uint8_t *, void*))
{
	errno_t result;

	if(ctx == NULL || blockCipherCtx == NULL || blockCipher == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(dir != DIR_ENCRYPTION && dir != DIR_DECRYPTION) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(blockSize != 8 && blockSize != 16) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	ctx->blockSize = blockSize;
	ctx->dir = dir;
	ctx->iv = iv;
	ctx->blockCipherCtx = blockCipherCtx;
	ctx->blockCipher = blockCipher;
	ctx->bufferOffset = 0;
	result = SUCCESSFULL_OPERATION;
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
errno_t ctrUpdate(ctr_ctx_st* ctx, const uint8_t* input, uint32_t inputLen, uint32_t inputOffset, uint8_t* output, uint32_t outputLen, uint32_t* outputOffset)
{
	errno_t result;
	uint32_t fullBlocks, remainingBytes;
	uint32_t availableSpace, necessarySpace;

	/* Check if context is valid */
	result = ctrCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Check if any pointer is NULL */
	result = checkIfValidParameters(input, output, outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Calculates the number of blocks to be processed */
	result = calculateFullBlocks(ctx->blockSize, ctx->bufferOffset, inputLen, &fullBlocks);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Calculates the number of bytes that will stay on the buffer */
	result = calculateRemainingBytes(ctx->blockSize, ctx->bufferOffset, inputLen, fullBlocks, &remainingBytes);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Calculates the space available in the output buffer */
	result = sub_s(outputLen, *outputOffset, &availableSpace);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Calculates the necessary space in the output buffer */
	result = mul_s(fullBlocks, ctx->blockSize, &necessarySpace);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	if(availableSpace < necessarySpace) {
		result = INVALID_OUTPUT_SIZE;
		goto FAIL;
	}
	
	if(fullBlocks == 0) {
		/* There isn't enough bytes to be processed. Copy the available bytes to the context buffer */
		memcpy(ctx->buffer + ctx->bufferOffset, input + inputOffset, inputLen);
		ctx->bufferOffset += (uint8_t)inputLen;
		result = SUCCESSFULL_OPERATION;
		goto SUCCESS;
	} else {
		uint8_t *encryptedIV = NULL;

		/* First block goes to buffer, remaining blocks are kept in input */
		memcpy(ctx->buffer + ctx->bufferOffset, input + inputOffset, ctx->blockSize - ctx->bufferOffset);
		inputLen -= ctx->blockSize - ctx->bufferOffset;
		inputOffset += ctx->blockSize - ctx->bufferOffset;

		/* Encrypts first block */
		encryptedIV = (uint8_t*) malloc(ctx->blockSize);
		if(encryptedIV == NULL) {
			result = INVALID_STATE;
			goto FAIL;
		}

		result = ctx->blockCipher(ctx->iv, encryptedIV, ctx->blockCipherCtx);
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL_CLEAN;
		}

		inc32(ctx->iv, ctx->blockSize);
		xor(encryptedIV, 0, ctx->buffer, 0, output + *outputOffset, 0, ctx->blockSize);
		*outputOffset += ctx->blockSize;
		fullBlocks--;

		/* Encrypts remaining blocks */
		while(fullBlocks > 0) {
			result = ctx->blockCipher(ctx->iv, encryptedIV, ctx->blockCipherCtx);
			if(result != SUCCESSFULL_OPERATION) {
				goto FAIL_CLEAN;
			}

			inc32(ctx->iv, ctx->blockSize);
			xor(encryptedIV, 0, input + inputOffset, 0, output + *outputOffset, 0, ctx->blockSize);
			*outputOffset += ctx->blockSize;
			inputOffset += ctx->blockSize;
			fullBlocks--;
		}

		/* Copy remaining bytes to buffer */
		memcpy(ctx->buffer, input + inputOffset, remainingBytes);
		ctx->bufferOffset = (uint8_t) remainingBytes;
		result = SUCCESSFULL_OPERATION;
FAIL_CLEAN:
		result |= memset_s(encryptedIV, sizeof(uint8_t) * ctx->blockSize, 0, sizeof(uint8_t) * ctx->blockSize);
		free(encryptedIV);
	}
FAIL:
SUCCESS:
	return result;
}

/* 
* Finishes operation and delete all sensitive data.
* input - Input to be encrypted or decrypted
* inputLen - Number of bytes to be processed
* inputOffset - Start index
* output - Result will be written to output
* outputLen - Output size not considering output offset
* outputOffset - Start index
* ctx - Context variable
*/
errno_t ctrFinal(ctr_ctx_st* ctx, const uint8_t* input, uint32_t inputLen, uint32_t inputOffset, uint8_t* output, uint32_t outputLen, uint32_t* outputOffset)
{
	errno_t result;
	uint32_t necessarySpace;
	uint8_t *encryptedIV = NULL;

	/* Check if context is valid */
	result = ctrCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Check if any pointer is NULL */
	result = checkIfValidParameters(input, output, outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Process all complete blocks */
	result = ctrUpdate(ctx, input, inputLen, inputOffset, output, outputLen, outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Calculates the necessary space in the output buffer */
	result = add_s(*outputOffset, ctx->bufferOffset, &necessarySpace);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(necessarySpace > outputLen) {
		result = INVALID_OUTPUT_SIZE;
		goto FAIL;
	}

	encryptedIV = (uint8_t*)malloc(sizeof(uint8_t) * ctx->blockSize);
	if(encryptedIV == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}

	/* Process remaining data from buffer */
	result = ctx->blockCipher(ctx->iv, encryptedIV, ctx->blockCipherCtx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_IV;
	}
	inc32(ctx->iv, ctx->blockSize);
	xor(encryptedIV, 0, ctx->buffer, 0, output + *outputOffset, 0, ctx->bufferOffset);
	*outputOffset += ctx->bufferOffset;
FAIL_IV:
	result |= memset_s(encryptedIV, sizeof(uint8_t) * ctx->blockSize, 0,  sizeof(uint8_t) * ctx->blockSize);
	free(encryptedIV);
FAIL:
	result |= memset_s(ctx->buffer, sizeof(uint8_t) *ctx->blockSize, 0, sizeof(uint8_t) *ctx->blockSize);
	result |= ctrClearContext(ctx);
	return result;
}

errno_t ctrClearContext(ctr_ctx_st *ctx)
{
	errno_t result;
	
	if(ctx == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = memset_s(ctx, sizeof(ctr_ctx_st), 0, sizeof(ctr_ctx_st));
FAIL:
	return result;
}

errno_t ctrCalculateOutputSize(ctr_ctx_st *ctx, uint32_t inputLen, uint32_t *outputLen)
{
	errno_t result;
	uint32_t fullBlocks;

	/* Check if context is valid */
	result = ctrCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(outputLen == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Calculates the number of complete blocks that can be processed */
	result = calculateFullBlocks(ctx->blockSize, ctx->bufferOffset, inputLen, &fullBlocks);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* It may overestimate output size. But it doesn't matter */
	result = add_s(fullBlocks, 1, &fullBlocks);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = mul_s(ctx->blockSize, fullBlocks, outputLen);
FAIL:
	return result;
}

errno_t ctrCheckContext(ctr_ctx_st *ctx)
{
	errno_t result = DEFAULT_ERROR;

	if(ctx == NULL || ctx->blockCipherCtx == NULL || ctx->blockCipher == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(ctx->dir != DIR_ENCRYPTION && ctx->dir != DIR_DECRYPTION) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(ctx->blockSize != 8 && ctx->blockSize != 16) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = SUCCESSFULL_OPERATION;

FAIL:
	return result;
}