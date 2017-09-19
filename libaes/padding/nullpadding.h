#ifndef NULL_PADDING_
#define NULL_PADDING_

#include "padding.h"

void nullInit(PaddingScheme* /* ps */);
errno_t checkNullPadding(uint32_t /* blockSize */, uint8_t* /* output */, uint32_t* /* outputLen */);
errno_t addNullPadding(uint32_t /* blockSize */, uint8_t* /* input */, uint32_t /* inputLen */, uint8_t** /* output*/, uint32_t* /* outputLen */);

#endif /* NULL_PADDING_ */