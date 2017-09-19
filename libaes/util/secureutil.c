#include "secureutil.h"
#include <stdio.h>

errno_t add_s(uint32_t op1, uint32_t op2, uint32_t* res) {
	errno_t result;

	if(res == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(UINT_MAX - op1 < op2) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*res = op1 + op2;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t sub_s(uint32_t op1, uint32_t op2, uint32_t* res)
{
	errno_t result;

	if(res == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(op1 < op2) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	*res = op1 - op2;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t mul_s(uint32_t op1, uint32_t op2, uint32_t* res)
{
	errno_t result;
	if(res == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(op2 != 0 && op1 > UINT_MAX/op2) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	*res = op1 * op2;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t div_s(uint32_t op1, uint32_t op2, uint32_t* res)
{
	errno_t result;

	if(res == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	if(op2 == 0) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	*res = op1 / op2;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}


/* Secure parameters check */
errno_t checkIfValidParameters(const uint8_t* input, uint8_t* output, uint32_t* outputOffset)
{
	errno_t result;
	if(input == NULL || output == NULL || outputOffset == NULL) {
		result = INVALID_PARAMETER;
	} else {
		result = SUCCESSFULL_OPERATION;
	}
	return result;
}

errno_t calculateFullBlocks(uint32_t blockSize, uint32_t bufferOffset, uint32_t inputLen, uint32_t* fullBlocks)
{
	errno_t result;

	result = add_s(inputLen, bufferOffset, fullBlocks);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = div_s(*fullBlocks, blockSize, fullBlocks);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
FAIL:
	return result;
}
errno_t calculateRemainingBytes(uint32_t blockSize, uint32_t bufferOffset, uint32_t inputLen, uint32_t fullBlocks, uint32_t* remainingBytes)
{
	errno_t result;
	uint32_t aux;

	result = mul_s(blockSize, fullBlocks, remainingBytes);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = add_s(inputLen, bufferOffset, &aux);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	result = sub_s(aux, *remainingBytes, remainingBytes);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
FAIL:
	return result;
}

/* CERT Solution for memory sanitization. It should prevent compiler optimizations, but it isn't guaranteed to work. */
errno_t memset_s(void* v, size_t smax, uint8_t c, size_t n)
{
	errno_t result;
	volatile uint8_t *p = (uint8_t*) v;
	
	if((v == NULL && (n != 0 || smax != 0))|| smax > UINT_MAX || n > smax) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}

	while (smax-- && n--) {
		*p++ = c;
	}
	result = SUCCESSFULL_OPERATION;

FAIL:
	return result;
}

/* Secure resize */
errno_t resize_s(uint8_t** data, uint32_t currentSize, uint32_t newSize)
{
	errno_t result;
	uint32_t numberOfBytes;
	
	if(data == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	uint8_t *newdata = (uint8_t*) malloc(sizeof(uint8_t) * newSize);
	if(newdata == NULL && newSize > 0) {
		result = INVALID_STATE;
		goto FAIL;
	}
	/* Numbers of bytes to be copied */
	numberOfBytes = (newSize > currentSize) ? currentSize : newSize;
	
	/* Clear destination before copying data into it */
	result = memset_s(newdata, sizeof(uint8_t) * newSize, 0, sizeof(uint8_t) * newSize);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	memcpy(newdata, *data, numberOfBytes);
	
	/* Erase the old vector */
	result = memset_s(*data, sizeof(uint8_t) * currentSize, 0, sizeof(uint8_t) * currentSize);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	free(*data);
	
	*data = newdata;
	
FAIL:
SUCCESS:
	return result;
}
