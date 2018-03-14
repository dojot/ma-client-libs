#include "pkcs7padding.h"

void pkcs7Init(PaddingScheme* ps) {
	ps->addPadding = addPKCS7Padding;
	ps->checkPadding = checkPKCS7Padding;
}

errno_t addPKCS7Padding(uint32_t blockSize, uint8_t* input, uint32_t inputLen, uint8_t** output, uint32_t* outputLen) 
{
	errno_t result;
	uint32_t paddingValue;
	uint8_t *paddedData = NULL;

	/* Calculates the padding value */
	paddingValue = inputLen % blockSize;
	result = sub_s(blockSize, paddingValue, &paddingValue);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(paddingValue < blockSize) {
		*outputLen = blockSize;
		paddedData = (uint8_t*) malloc(sizeof(uint8_t) * blockSize);
	} else if(paddingValue == blockSize) {
		*outputLen = 2 * blockSize;
		paddedData = (uint8_t*) malloc(sizeof(uint8_t) * 2 * blockSize);
	}

	memcpy(paddedData, input, inputLen);
	memset(paddedData + inputLen, paddingValue, sizeof(uint8_t) * paddingValue);
	*output = paddedData;
	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

errno_t checkPKCS7Padding(uint32_t blockSize, uint8_t* output, uint32_t* outputLen)
{
	errno_t result;
	uint32_t i, limit, paddingValue;
	uint8_t res = 0x00;

	/* Calculates the padding value */
	result = sub_s(*outputLen, 1, &i);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	paddingValue = output[i];

	/* Calculates the smallest index with should be padding */
	result = sub_s(*outputLen, paddingValue, &limit);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}

	if(paddingValue <= 0 || paddingValue > blockSize) {
		result = INVALID_PADDING;
		goto FAIL;
	} else {
		/* Check the padding */
		while(i > limit) {
			res |= paddingValue ^ output[i];
			
			result = sub_s(i, 1, &i);
			if(result != SUCCESSFULL_OPERATION) {
				goto FAIL;
			}
		}

		if(res != 0x00) {
			result = INVALID_PADDING;
			goto FAIL;
		}
	}
FAIL:
	return result;
}