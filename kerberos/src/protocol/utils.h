#ifndef UTILS_
#define UTILS_

#include <stdint.h>

/* 
 * Calculates the difference between client and server time. 
 * Both, client time and server time are represented as offsets. Also,
 * they need to be valid IEEE754 double precision numbers 
 */
uint8_t calculateOffset(uint64_t serverTime, uint64_t* timeOffset) ;

/*
 * Get the current UTC time in timezone Z, which is used as a reference time.
 * This value is returned as a IEEE 754 double BIG_ENDIAN. The same encoding 
 * must be used at server side.
 */
void getUTC(uint64_t* currTime);

/*
 * Get the current UTC time but adjusts it with the server offset.
 */
void getAdjustedUTC(uint64_t offset, uint64_t* currTimeOffseted);

#endif /* UTILS_ */
