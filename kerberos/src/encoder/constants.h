#ifndef CONSTANTS_H
#define	CONSTANTS_H

#include "errno.h"

/* Status codes */
#define SUCCESSFULL_OPERATION		0
#define INVALID_OUTPUT_SIZE		1
#define INVALID_INPUT_SIZE		2
#define INVALID_PARAMETER		4
#define INVALID_STATE			8
#define INVALID_MEMSET			16	
#define INVALID_CSRNG			32
#define NETWORK_ERROR			64

/* Simulated boolean values */
#define     TRUE            1
#define     FALSE           0

/* Kerberos types default size */
#define ERROR_CODE_LENGTH	1
#define PRINCIPAL_NAME_LENGTH   16
#define NONCE_LENGTH            4
#define KEY_LENGTH		32
#define IV_LENGTH		12
#define MESSAGE_CODE_LENGTH	1

#endif /* CONSTANTS_H */ 
