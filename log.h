#ifndef LOG_H_
#define LOG_H_

#include <errno.h>

//The errno values are postive integers in standard C and POSIX.
//So user defined errno or level must be negative.
#define ERROR_LEVEL -1
#define INFO_LEVEL  -2
#define DEBUG_LEVEL -3

#define MAX_LEVEL -4

//if en > 0, it's errno
//if en < 0, it's log level
int printlog(int en, char* format, ...);

int set_log_level(int en);

#endif
