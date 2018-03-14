#include "utils.h"

#include "ma_comm_error_codes.h"
#include <time.h>


uint8_t calculateOffset(uint64_t serverTime, uint64_t* timeOffset) {

    if(!timeOffset) {
        return MA_COMM_INVALID_PARAMETER;
    }

    uint64_t clientTime = 0;
    getUTC(&clientTime);

    *timeOffset = serverTime - clientTime;

    return MA_COMM_SUCCESS;
}

void getUTC(uint64_t* currTime) {
        /* Get the number of milliseconds since midnight January 1, 1970 UTC */
        *currTime = ((uint64_t)time(NULL)) * 1000;
}

/* Adjust the offset to account for differences between local and remote host */
void getAdjustedUTC(uint64_t offset, uint64_t* currTimeOffseted) {
    getUTC(currTimeOffseted);
    *currTimeOffseted += offset;
}
