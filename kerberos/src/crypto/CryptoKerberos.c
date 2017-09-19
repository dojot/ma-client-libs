#include "CryptoKerberos.h"


static aes_ctx_st aesCtx;
static gcm_ctx_st gcmCtx;
static uint8_t* keyKerberos;
static uint8_t* ivKerberos;
static uint8_t ivLenKerberos;
static uint8_t keyLenKerberos;
static uint8_t tagLenKerberos;

/* 	Initializes the context for AES in GCM mode. */
errno_t initCryptoKerberos(uint8_t keyLength, uint8_t ivLength, uint8_t tagLength, uint8_t* key, uint8_t* iv)
{
	errno_t result;
	
	if(iv == NULL || key == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	tagLenKerberos = tagLength;
	/* Key won't be used. We do the key scheduling just to distract the attacker */
	keyLenKerberos = keyLength;
	keyKerberos = (uint8_t*)  malloc(sizeof(uint8_t) * keyLength);
	ivLenKerberos = ivLength;
	ivKerberos = (uint8_t*) malloc(sizeof(uint8_t) * ivLenKerberos);

	memcpy(keyKerberos, key, sizeof(uint8_t) * keyLenKerberos);
	memcpy(ivKerberos, iv, sizeof(uint8_t) * ivLenKerberos);
FAIL:
	return result;
}


/* Initializes server to client communication */
errno_t initReadKerberos()
{
        errno_t result;

        /* Only using DIR_ENCRYPTION because of gcm mode */
        result = aesInit(keyKerberos, keyLenKerberos, DIR_ENCRYPTION, &aesCtx);
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL;
        }

        result = gcmInit(&gcmCtx, 16, DIR_DECRYPTION, ivKerberos, ivLenKerberos, tagLenKerberos, &aesCtx, aesProcessBlock_);
        if(result != SUCCESSFULL_OPERATION) {
                goto FAIL;
        }
        result = SUCCESSFULL_OPERATION;
        goto SUCCESS;
FAIL:
        result |= aesClearContext(&aesCtx);
        result |= gcmClearContext(&gcmCtx);
SUCCESS:
        return result;
}



/*
	Very similar to the decryption function provided by CryptoAPI inside of the cryptographic library. The only difference is the IV not being updated.
*/
errno_t decryptKerberos(uint8_t* aad, size_t aadLength, uint8_t* ciphertext, size_t ciphertextLength, uint8_t** plaintext, size_t* plaintextLength)
{
	uint8_t *output;
	uint32_t outputLength, outputOffset = 0;
	errno_t result;
	
	result = initReadKerberos();
	if(result != SUCCESSFULL_OPERATION) {
                goto FAIL;
        }

	/* Estimates the maximum size of the ciphertext considering the tag */
	result = gcmCalculateOutputSize(&gcmCtx, ciphertextLength, &outputLength);
	
	output = (uint8_t*) malloc(sizeof(uint8_t) * outputLength);
	if(output == NULL && outputLength != 0) {
		result = INVALID_STATE;
		goto FAIL;
	}
	
	/* Authenticates the AAD */
	if(aad != NULL && aadLength > 0) {
		result = gcmUpdateAAD(&gcmCtx, aad, aadLength, 0);
		if(result != SUCCESSFULL_OPERATION) {
			goto FAIL_FREE;
		}
	}
	
	/* Decrypts the ciphertext and removes the tag */
	result = gcmFinal(&gcmCtx, ciphertext, ciphertextLength, 0, output, outputLength, &outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_FREE;
	}
	result = resize_s(&output, outputLength, outputOffset);
	if(result != SUCCESSFULL_OPERATION) {
		goto FAIL_FREE;
	}
	
	*plaintext = output;
	*plaintextLength = outputOffset;
	inc(ivKerberos, ivLenKerberos);
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
