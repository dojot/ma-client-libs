#ifndef CRYPTO_
#define CRYPTO_

#include "mode/gcm.h"
#include "util/codes.h"

#include "util/cryptoutil.h"
#include "symmetric/aes.h"

/* Using the biggest length possible for the tag */
#define TAG_LEN 128

errno_t initReadChannel();
errno_t initWriteChannel();
errno_t initSecureChannel(uint8_t /* keyLength */, uint8_t /* ivLength */, uint8_t /* tagLen */, uint8_t* /* kLocal */, uint8_t* /* kExtern */, uint8_t* /* iLocal */, uint8_t* /* iExtern */);
errno_t encryptTo(uint8_t* /* aad */, uint32_t /* aadLength */, uint8_t* /* plaintext */, uint32_t /* plaintextLength */, uint8_t** /* ciphertext */, size_t* /* ciphertextLength */);
errno_t decryptTo(uint8_t* /* aad */, uint32_t /* aadLength */, uint8_t* /* ciphertext */, uint32_t /* ciphertextLength */, uint8_t** /* plaintext */, size_t* /* plaintextLength */);
errno_t clearSecureChannel();
errno_t encryptToJS(uint8_t* /* aad */, uint32_t /* aadLength */, uint8_t* /* plaintext */, uint32_t /* plaintextLength */, uint8_t* /* ciphertext */);
errno_t decryptToJS(uint8_t* /* aad */, uint32_t /* aadLength */, uint8_t* /* ciphertext */, uint32_t /* ciphertextLength */, uint8_t* /* plaintext */);
#endif /* CRYPTO_ */
