#include "utils.h"

void swap(uint8_t* array, uint32_t size)
{
	uint32_t i;

	for(i = 0; i < size/2; i++) {
		array[i] ^= array[size-i-1];
		array[size-i-1] ^= array[i];
		array[i] ^= array[size-i-1];
	}	
}

char* updateCode(char* code, char* pattern, char* data, int keep_as)
{
        char* newcode = malloc((strlen(code) + (strlen(data) - strlen(pattern)) + 1) * sizeof(char));
        char* nextptr = strstr(code, pattern);
        char* oldcode = code;
        memset(newcode, '\0', sizeof(char) * (strlen(code) + (strlen(data) - strlen(pattern)) + 1));
        while(nextptr != NULL) {
                *nextptr = '\0';
                strcat(newcode, oldcode);
		if(keep_as == 1) { strcat(newcode, "'"); }
                strcat(newcode, data);
		if(keep_as == 1) { strcat(newcode, "'"); }
                oldcode = nextptr + strlen(pattern);
                nextptr = strstr(nextptr + strlen(pattern), pattern);
                newcode = realloc(newcode, sizeof(char) * (strlen(newcode) + strlen(oldcode) + (strlen(data) - strlen(pattern)) + 1));
        }
        strcat(newcode, oldcode);
	free(code);
        return newcode;
}

char* encodeAsArray(uint32_t length, uint8_t* array)
{
	// [0x00,0x00]
	// 2 -> []
	// length * 4 -> every number is represented with 4 symbols
	// 1 * (length - 1) -> number of commas
	// 1 -> \0 to c string
	uint32_t i;
	char tmp[4];
	char* buffer = malloc(sizeof(char) * (2 + length * 4 + 1 * (length - 1) + 1));
	
	buffer[0] = '\0';
	strcat(buffer, "[");
	for(i = 0; i < length - 1; i++) {
		sprintf(tmp, "0x%02x", array[i]);
		strcat(buffer, tmp);
		strcat(buffer, ",");
	}
	sprintf(tmp, "0x%02x", array[i]);
	strcat(buffer, tmp);
	strcat(buffer, "]");
	return buffer;
}


errno_t calculateOffset(uint8_t* serverTime, uint8_t* timeOffset)
{
	errno_t result;
	
	if(serverTime == NULL || timeOffset == NULL) {
		result = INVALID_PARAMETER;
		goto FAIL;
	}
	
	uint8_t clientTime[TIME_LENGTH];
	getUTC(clientTime);
	swap(clientTime, TIME_LENGTH);
	swap(timeOffset, TIME_LENGTH);
	swap(serverTime, TIME_LENGTH);

	double server, client, diff;
	
	memcpy(&server, serverTime, TIME_LENGTH);
	memcpy(&client, clientTime, TIME_LENGTH);
	diff = server - client;
	memcpy(timeOffset, &diff, TIME_LENGTH);
	
	swap(timeOffset, TIME_LENGTH);
	swap(clientTime, TIME_LENGTH);
	swap(serverTime, TIME_LENGTH);

	result = SUCCESSFULL_OPERATION;
FAIL:
	return result;
}

void getUTC(uint8_t* timeOffset)
{
        /* Get the number of milliseconds since midnight January 1, 1970 UTC */
        uint64_t rawtime;

        rawtime = ((uint64_t)time(NULL)) * 1000;
        memset(timeOffset, 0, sizeof(uint8_t) * TIME_LENGTH);
        memcpy(timeOffset, &rawtime, sizeof(uint8_t) * TIME_LENGTH);
        swap(timeOffset, TIME_LENGTH);
}

/* Adjust the offset to account for differences between local and remote host */
void getAdjustedUTC(uint8_t* timeOffset, uint8_t* diffOffset)
{
	getUTC(timeOffset);
	swap(timeOffset, TIME_LENGTH);
	swap(diffOffset, TIME_LENGTH);

	double time, diff;
	
	memcpy(&time, timeOffset, TIME_LENGTH);
	memcpy(&diff, diffOffset, TIME_LENGTH);
	time += diff;
	memcpy(timeOffset, &time, TIME_LENGTH);
	
	swap(timeOffset, TIME_LENGTH);
	swap(diffOffset, TIME_LENGTH);
}
