#include "nullpadding.h"

void nullInit(PaddingScheme* ps) {
	ps->addPadding = addNullPadding;
	ps->checkPadding = checkNullPadding;
}

errno_t addNullPadding(uint32_t blockSize, uint8_t* input, uint32_t inputLen, uint8_t** output, uint32_t* outputLen) 
{
	errno_t result;
	uint8_t *paddedData = NULL;

	if(input == NULL || output == NULL || outputLen == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}

	paddedData = (uint8_t*) malloc(sizeof(uint8_t) * blockSize);
	if(paddedData == NULL) {
		result = INVALID_STATE;
		goto FAIL;
	}

	memcpy(paddedData, input, inputLen);
	*outputLen = inputLen;
	*output = paddedData;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t checkNullPadding(uint32_t blockSize, uint8_t* output, uint32_t* outputLen)
{
	errno_t error = SUCCESSFULL_OPERATION;
	return error;
}