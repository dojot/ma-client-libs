#ifndef KERBEROS_SRC_LOGGER_LOGGER_H_
#define KERBEROS_SRC_LOGGER_LOGGER_H_

#include <stdint.h>

#define MAX_LOG_SIZE    1024

#define LOG(ARGS...) \
do { \
        if (logger_is_log_enabled()) \
            logger_write_message(ARGS); \
    } while (0);

void logger_enable();

void logger_disable();

uint8_t logger_is_log_enabled();

void logger_write_message(const char* data, ...);

#endif /* KERBEROS_SRC_LOGGER_LOGGER_H_ */
