#ifndef ERRNO_T
#define ERRNO_T

#include <stdint.h>

#ifndef errno
	#define errno_t uint8_t 
#else
	#include <errno.h>
#endif

#endif /* ERRNO_T */
