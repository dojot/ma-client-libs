#include "logger.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

//by default logger is disabled
static uint8_t isLogEnabled = 0;

void logger_enable() {
	isLogEnabled = 1;
}

void logger_disable() {
	isLogEnabled = 0;
}

uint8_t logger_is_log_enabled() {
	return isLogEnabled;
}

void logger_write_message(const char* data, ...) {

    char buffer[MAX_LOG_SIZE];
    va_list list;
    uint32_t length = 0;
    uint8_t overflow = 0;

    memset(buffer, 0, MAX_LOG_SIZE);

    if (!isLogEnabled) {
        return;
    }

	// add log message
	va_start(list, data);

	// variable list to string
	length = vsnprintf(buffer, MAX_LOG_SIZE, data, list);

	// check buffer length
	if (length > MAX_LOG_SIZE) {
		overflow = 1;
	}

	va_end(list);

	// print
    printf("%s", buffer);
    if (overflow) {
    	printf("[CRITICAL] Logger buffer overflow.");
    }

}
