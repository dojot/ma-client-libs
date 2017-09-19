#ifndef ERROR_CODES_
#define ERROR_CODES_

#define DIR_ENCRYPTION 0
#define DIR_DECRYPTION 1

/* Operation succeeded */
#define SUCCESSFULL_OPERATION 0

/* Error during encryption */
#define INVALID_OUTPUT_SIZE		1
#define INVALID_INPUT_SIZE		2
#define INVALID_PADDING			4
#define INVALID_TAG				8

#define INVALID_PARAMETER		16
#define INVALID_STATE			32

#define DEFAULT_ERROR			64
#define INVALID_MEMSET			128


#endif /* ERROR_CODES_ */