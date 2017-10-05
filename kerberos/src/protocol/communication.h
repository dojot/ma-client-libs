#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include "../encoder/constants.h"
#include "../encoder/errno.h"
#include "utils.h"

//#include <emscripten.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Max http reply size, should be enough to exchange all the kerberos messages */
#define MAX_HTTP_REPLY	1024

void send_message(uint8_t* /* encodedInput */, size_t /* encodedLength */, uint8_t* /* host */, uint8_t* /* path */);

#endif /* COMMUNICATION_H_ */
