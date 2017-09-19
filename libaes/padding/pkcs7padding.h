#ifndef PKCS5_PADDING_
#define PKCS5_PADDING_

#include "padding.h"

void pkcs7Init(PaddingScheme* /* ps */);
errno_t addPKCS7Padding(uint32_t /* blockSize */, uint8_t* /* input */, uint32_t /* inputLen */, 
											uint8_t** /* output */,uint32_t* /* outputLen */);
errno_t checkPKCS7Padding(uint32_t /* blockSize */, uint8_t* /* output */, uint32_t* /* outputLen */);

#endif /* PKCS5_PADDING_ */