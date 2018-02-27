#include "ecb.h"

errno_t ecbInit(ecb_ctx_st* ctx, uint32_t blockSize, uint32_t dir, void* blockCipherCtx, errno_t blockCipher(const uint8_t*, uint8_t *, void*), PaddingScheme ps)
{
	errno_t result = DEFAULT_ERROR;

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

	if(ps.addPadding == NULL || ps.checkPadding == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	ctx->blockSize = blockSize;
	ctx->dir = dir;
	ctx->blockCipherCtx = blockCipherCtx;
	ctx->blockCipher = blockCipher;
	ctx->ps = ps;
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
* outputOffset - Output start index
* ctx - Context variable
*/
errno_t ecbUpdate(ecb_ctx_st* ctx, const uint8_t* input, uint32_t inputLen, uint32_t inputOffset, uint8_t* output, uint32_t outputLen, uint32_t* outputOffset)
{
	errno_t result;
	uint32_t availableSpace, necessarySpace;
	uint32_t fullBlocks, remainingBytes;

	/* Check if context is valid */
	result = ecbCheckContext(ctx);
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
		/* There isn't enough bytes to be processed. Copy the available ones to the context buffer */
		memcpy(ctx->buffer + ctx->bufferOffset, input + inputOffset, inputLen);
		ctx->bufferOffset += inputLen;
		result = SUCCESSFULL_OPERATION;
	} else {
		/* First block goes to buffer, remaining blocks are kept in input */
		memcpy(ctx->buffer + ctx->bufferOffset, input + inputOffset, ctx->blockSize - ctx->bufferOffset);
		inputLen -= ctx->blockSize - ctx->bufferOffset;
		inputOffset += ctx->blockSize - ctx->bufferOffset;

		/* Encrypts first block */
		result = ctx->blockCipher(ctx->buffer, output + *outputOffset, ctx->blockCipherCtx);
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL;
		}

		*outputOffset += ctx->blockSize;		
		fullBlocks--;

		/* Encrypts remaining blocks */
		while(fullBlocks > 0) {
			result = ctx->blockCipher(input + inputOffset, output + *outputOffset, ctx->blockCipherCtx);
			if(result != SUCCESSFULL_OPERATION) {
				goto FAIL;
			}

			*outputOffset += ctx->blockSize;
			inputOffset += ctx->blockSize;
			fullBlocks--;
		}

		/* Copy remaining bytes to buffer */
		memcpy(ctx->buffer, input + inputOffset, remainingBytes);
		ctx->bufferOffset = remainingBytes;
		result = SUCCESSFULL_OPERATION;
	}
FAIL:
	return result;
}

/* 
* Finishes operation and delete all sensitive data.
* input - Input to be encrypted or decrypted
* inputLen - Number of bytes to be processed
* inputOffset - Start index
* output - Result will be written to output
* outputLen - Output size not considering output offset
* outputOffset - Output start index
* ctx - Context variable
*/
errno_t ecbFinal(ecb_ctx_st* ctx, const uint8_t* input, uint32_t inputLen, uint32_t inputOffset, uint8_t* output, uint32_t outputLen, uint32_t* outputOffset)
{
	errno_t result;

	/* Check if context is valid */
	result = ecbCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Check if any pointer is NULL */
	if(input == NULL || output == NULL || outputOffset == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	/* Process all complete blocks */
	result = ecbUpdate(ctx, input, inputLen, inputOffset, output, outputLen, outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	/* Process last block */
	if(ctx->dir == DIR_ENCRYPTION) {
		uint32_t lastBlockSize = 0;
		uint8_t* lastBlock;

		result = ctx->ps.addPadding(ctx->blockSize, ctx->buffer, ctx->bufferOffset, &lastBlock, &lastBlockSize);	
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL;
		}

		if(lastBlockSize % ctx->blockSize == 0) {
			result = ecbUpdate(ctx, lastBlock, lastBlockSize, 0, output, outputLen, outputOffset);
		} else {
			result = INVALID_STATE;
		}
		result |= memset_s(lastBlock, sizeof(uint8_t) * lastBlockSize, 0, sizeof(uint8_t) * lastBlockSize);
		free(lastBlock);
	} else if(ctx->dir == DIR_DECRYPTION) {
		result = ctx->ps.checkPadding(ctx->blockSize, output, outputOffset);
	}
FAIL:
	result |= memset_s(ctx->buffer, ctx->blockSize * sizeof(uint8_t), 0, ctx->blockSize * sizeof(uint8_t));
	result |= ecbClearContext(ctx);
	return result;
}


errno_t ecbCalculateOutputSize(ecb_ctx_st *ctx, uint32_t inputLen, uint32_t* outputLen) 
{
	errno_t result;
	uint32_t fullBlocks;

	/* Check if context is valid */
	result = ecbCheckContext(ctx);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(outputLen == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Calculates the number of complete blocks that can be processed */
	result = add_s(inputLen, ctx->bufferOffset, &fullBlocks);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = div_s(fullBlocks, ctx->blockSize, &fullBlocks);
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

errno_t ecbClearContext(ecb_ctx_st* ctx)
{
	errno_t result;
	
	if(ctx == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	result = memset_s(ctx, sizeof(ecb_ctx_st), 0, sizeof(ecb_ctx_st));
FAIL:
	return result;
}

errno_t ecbCheckContext(ecb_ctx_st *ctx)
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

	if(ctx->ps.addPadding == NULL || ctx->ps.checkPadding == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	result = SUCCESSFULL_OPERATION;

FAIL:
	return result;
}