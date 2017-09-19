#include "CryptoAPI.h"

/* Secure channel states */
static aes_ctx_st aesLocal;
static aes_ctx_st aesExtern;
static gcm_ctx_st writeChannel;
static gcm_ctx_st readChannel;

/* Local copies of parameters */
uint8_t* keyLocal = NULL;
uint8_t* keyExtern = NULL;
uint8_t* ivLocal = NULL;
uint8_t* ivExtern = NULL;
uint8_t keyLength = 0;
uint8_t ivLength = 0;
uint8_t tagLength = 0;

errno_t initSecureChannel(uint8_t kLength, uint8_t iLength, uint8_t tLen, uint8_t *kLocal, uint8_t* kExtern, uint8_t* iLocal, uint8_t* iExtern)
{
	errno_t result;
	
	if(kLocal == NULL || kExtern == NULL || iLocal == NULL || iExtern == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	/* Clear previous values */
	result = clearSecureChannel();
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	tagLength = tLen;
	
	keyLength = kLength;
	keyLocal = (uint8_t*) malloc(sizeof(uint8_t) * keyLength);
	keyExtern = (uint8_t*) malloc(sizeof(uint8_t) * keyLength);
	
	ivLength = iLength;
	ivLocal = (uint8_t*) malloc(sizeof(uint8_t) * ivLength);
	ivExtern = (uint8_t*) malloc(sizeof(uint8_t) * ivLength);
	
	memcpy(keyLocal, kLocal, sizeof(uint8_t) * keyLength);	
	memcpy(keyExtern, kExtern, sizeof(uint8_t) * keyLength);
	memcpy(ivLocal, iLocal, sizeof(uint8_t) * ivLength);
	memcpy(ivExtern, iExtern, sizeof(uint8_t) * ivLength);
FAIL:
	return result;
}

errno_t clearSecureChannel()
{
	errno_t result;
	
	if(keyLocal != NULL)
		result = memset_s(keyLocal, keyLength, 0, keyLength);
	if(keyExtern != NULL)
		result |= memset_s(keyExtern, keyLength, 0, keyLength);
	if(ivLocal != NULL)
		result |= memset_s(ivLocal, ivLength, 0, ivLength);
	if(ivExtern != NULL)
		result |= memset_s(ivExtern, ivLength, 0, ivLength);
		
	free(keyLocal);
	free(keyExtern);
	free(ivLocal);
	free(ivExtern);
	
	keyLength = 0;
	ivLength = 0;
	keyLocal = NULL;
	keyExtern = NULL;
	ivLocal = NULL;
	ivExtern = NULL;
	
	return result;
}

errno_t initChannel()
{
	errno_t result;
	
	result = initWriteChannel();
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = initReadChannel();
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result |= aesClearContext(&aesLocal);
	result |= gcmClearContext(&writeChannel);
	result |= aesClearContext(&aesExtern);
	result |= gcmClearContext(&readChannel);
FAIL:
	return result;
}

/* Initializes client to server communication */
errno_t initWriteChannel() 
{
	errno_t result;
	
	result = aesInit(keyLocal, keyLength, DIR_ENCRYPTION, &aesLocal);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = gcmInit(&writeChannel, 16, DIR_ENCRYPTION, ivLocal, ivLength, tagLength, &aesLocal, aesProcessBlock);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = SUCCESSFULL_OPERATION;
	goto SUCCESS;
FAIL:
	result |= aesClearContext(&aesLocal);
	result |= gcmClearContext(&writeChannel);
SUCCESS:
	return result;
}

/* Initializes server to client communication */
errno_t initReadChannel() 
{
	errno_t result;
	
	/* Only using DIR_ENCRYPTION because of gcm mode */
	result = aesInit(keyExtern, keyLength, DIR_ENCRYPTION, &aesExtern);	
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	result = gcmInit(&readChannel, 16, DIR_DECRYPTION, ivExtern, ivLength, tagLength, &aesExtern, aesProcessBlock);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	result = SUCCESSFULL_OPERATION;
	goto SUCCESS;
FAIL:
	result |= aesClearContext(&aesExtern);
	result |= gcmClearContext(&readChannel);
SUCCESS:
	return result;
}

errno_t encryptToJS(uint8_t* aad, uint32_t aadLength, uint8_t* plaintext, uint32_t plaintextLength, uint8_t* ciphertext)
{
	errno_t result;
        int i;
        uint8_t* output;
        uint32_t outputLength, outputOffset = 0;

        if(ciphertext == NULL) {
                result = INVALID_PARAMETER;
                goto FAIL;
        }
        result = initWriteChannel();
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL;
        }

        /* Estimates the maximum size of the ciphertext considering the tag */
        result = gcmCalculateOutputSize(&writeChannel, plaintextLength, &outputLength);
        output = (uint8_t*) malloc(sizeof(uint8_t) * outputLength);
        if(output == NULL && outputLength != 0) {
                result = INVALID_STATE;
                goto FAIL;
        }

        /* Authenticates the AAD */
        if(aadLength > 0) {
                result = gcmUpdateAAD(&writeChannel, aad, aadLength, 0);
                if(result != SUCCESSFULL_OPERATION) {
                        goto FAIL_FREE;
                }
        }

        /* Encrypts the plaintext and appends the tag */
        result = gcmFinal(&writeChannel, plaintext, plaintextLength, 0, output, outputLength, &outputOffset);
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL_FREE;
        }

        result = resize_s(&output, outputLength, outputOffset);
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL_FREE;
        }
		memcpy(ciphertext, output, outputOffset);
        inc(ivLocal, ivLength);
        result = SUCCESSFULL_OPERATION;
        goto SUCCESS;

FAIL_FREE:
        result |= memset_s(output, outputOffset, 0, outputOffset);
        free(output);

FAIL:
SUCCESS:
        result |= memset_s(plaintext, plaintextLength, 0, plaintextLength);
        result |= memset_s(aad, aadLength, 0, aadLength);
        return result;
}

errno_t encryptTo(uint8_t* aad, uint32_t aadLength, uint8_t* plaintext, uint32_t plaintextLength, uint8_t** ciphertext, uint32_t* ciphertextLength)
{
	errno_t result;
	int i;
	uint8_t* output;
	uint32_t outputLength, outputOffset = 0;
	
	if(ciphertext == NULL || ciphertextLength == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	result = initWriteChannel();
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Estimates the maximum size of the ciphertext considering the tag */
	result = gcmCalculateOutputSize(&writeChannel, plaintextLength, &outputLength);
	output = (uint8_t*) malloc(sizeof(uint8_t) * outputLength);
	if(output == NULL && outputLength != 0) {
		result = INVALID_STATE;
		goto FAIL;
	}
	
	/* Authenticates the AAD */
	if(aadLength > 0) {
		result = gcmUpdateAAD(&writeChannel, aad, aadLength, 0);
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL_FREE;
		}
	}
	
	/* Encrypts the plaintext and appends the tag */
	result = gcmFinal(&writeChannel, plaintext, plaintextLength, 0, output, outputLength, &outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_FREE;
	}
	
	result = resize_s(&output, outputLength, outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_FREE;
	}
	
	*ciphertext = output;
	*ciphertextLength = outputOffset;
	inc(ivLocal, ivLength);
	result = SUCCESSFULL_OPERATION;
	goto SUCCESS;
	
FAIL_FREE:
	result |= memset_s(output, outputOffset, 0, outputOffset);
	free(output);
	
FAIL:
SUCCESS:
	result |= memset_s(plaintext, plaintextLength, 0, plaintextLength);
	result |= memset_s(aad, aadLength, 0, aadLength);
	return result;
}
	
errno_t decryptTo(uint8_t* aad, uint32_t aadLength, uint8_t* ciphertext, uint32_t ciphertextLength, uint8_t** plaintext, uint32_t* plaintextLength)
{
	uint8_t *output;
	uint32_t outputLength, outputOffset = 0;
	errno_t result;

	result = initReadChannel();
	if(result != SUCCESSFULL_OPERATION) {
	    printf("initReadChannel failed\n");
		goto FAIL;
	}
	
	/* Estimates the maximum size of the ciphertext considering the tag */
	result = gcmCalculateOutputSize(&readChannel, ciphertextLength, &outputLength);
	
	output = (uint8_t*) malloc(sizeof(uint8_t) * outputLength);
	if(output == NULL && outputLength != 0) {
		result = INVALID_STATE;
		printf("malloc failed\n");
		goto FAIL;
	}
	
	/* Authenticates the AAD */
	if(aad != NULL && aadLength > 0) {
		result = gcmUpdateAAD(&readChannel, aad, aadLength, 0);
		if(result != SUCCESSFULL_OPERATION) {
		    printf("gcmUpdateAAD failed\n");
			goto FAIL_FREE;
		}
	}
	
	/* Decrypts the ciphertext and removes the tag */
	result = gcmFinal(&readChannel, ciphertext, ciphertextLength, 0, output, outputLength, &outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
	    printf("gcmFinal failed\n");
		goto FAIL_FREE;
	}
	
	result = resize_s(&output, outputLength, outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
	    printf("resize_s failed\n");
		goto FAIL_FREE;
	}
	
	*plaintext = output;
	*plaintextLength = outputOffset;
	/* Initializes the server to client channel */
	inc(ivExtern, ivLength);
	goto SUCCESS;

FAIL_FREE:
	result |= memset_s(output, outputOffset, 0, outputOffset);
	free(output);

FAIL:
SUCCESS:
	result |= memset_s(ciphertext, ciphertextLength, 0, ciphertextLength);
	result |= memset_s(aad, aadLength, 0, aadLength);
	return result;
}

errno_t decryptToJS(uint8_t* aad, uint32_t aadLength, uint8_t* ciphertext, uint32_t ciphertextLength, uint8_t* plaintext)
{
	uint8_t *output;
	uint32_t outputLength, outputOffset = 0;
	errno_t result;

	result = initReadChannel();
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL;
	}
	
	/* Estimates the maximum size of the ciphertext considering the tag */
	result = gcmCalculateOutputSize(&readChannel, ciphertextLength, &outputLength);
	
	output = (uint8_t*) malloc(sizeof(uint8_t) * outputLength);
	if(output == NULL && outputLength != 0) {
		result = INVALID_STATE;
		goto FAIL;
	}
	
	/* Authenticates the AAD */
	if(aad != NULL && aadLength > 0) {
		result = gcmUpdateAAD(&readChannel, aad, aadLength, 0);
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL_FREE;
		}
	}
	
	/* Decrypts the ciphertext and removes the tag */
	result = gcmFinal(&readChannel, ciphertext, ciphertextLength, 0, output, outputLength, &outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_FREE;
	}
	
	result = resize_s(&output, outputLength, outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_FREE;
	}

	memcpy(plaintext, output, outputOffset);	
	/* Initializes the server to client channel */
	inc(ivExtern, ivLength);
	goto SUCCESS;

FAIL_FREE:
	result |= memset_s(output, outputOffset, 0, outputOffset);
	free(output);

FAIL:
SUCCESS:
	result |= memset_s(ciphertext, ciphertextLength, 0, ciphertextLength);
	result |= memset_s(aad, aadLength, 0, aadLength);
	return result;
}
