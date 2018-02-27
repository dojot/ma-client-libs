#ifndef PADDING_
#define PADDING_

#include "../util/codes.h"
#include "../util/secureutil.h"

#include <stdlib.h>
#include <string.h>

#ifdef errno
	#include <errno.h>
#else
	#include "../util/errno.h"
#endif


typedef struct {
	errno_t (*addPadding)(uint32_t /* blockSize */, uint8_t* /* input */, uint32_t /* inputLen */, 
												uint8_t** /* output */, uint32_t* /* outputLen */);

	errno_t (*checkPadding)(uint32_t /* blockSize */, uint8_t* /* output */, uint32_t* /* outputLen */);
} PaddingScheme;

#endif /* PADDING_ */