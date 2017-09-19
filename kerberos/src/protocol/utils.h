#ifndef UTILS_
#define UTILS_

#include "../encoder/constants.h"
#include "../encoder/errno.h"
#include "protocol.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* 
 * Changes the specified pattern in the code by the data value.
 * It modifies the original string.
 */
char* updateCode(char* /* code */, char* /* pattern */, char* /* data */, int /* keepas */);

/* Convert a byte array to a string array. */
char* encodeAsArray(uint32_t /* length */, uint8_t* /* array */);

/* 
 * Calculates the difference between client and server time. 
 * Both, client time and server time are represented as offsets. Also,
 * they need to be valid IEEE754 double precision numbers 
 */
errno_t calculateOffset(uint8_t* /* serverTime */, uint8_t* /* timeOffset */);

/*
 * Get the current UTC time in timezone Z, which is used as a reference time.
 * This value is returned as a IEEE 754 double BIG_ENDIAN. The same encoding 
 * must be used at server side.
 */
void getUTC(uint8_t* /* timeOffset */);

/*
 * Get the current UTC time but adjusts it with the server offset.
 */
void getAdjustedUTC(uint8_t* /* timeOffset */, uint8_t* /* diffOffset */);

#endif /* UTILS_ */
