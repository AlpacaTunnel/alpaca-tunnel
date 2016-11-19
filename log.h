#ifndef LOG_H_
#define LOG_H_

#include <errno.h>


/* Levels from Python
 * DEBUG       Detailed information, typically of interest only when diagnosing problems.
 * INFO        Confirmation that things are working as expected.
 * WARNING     An indication that something unexpected happened, or indicative of some problem in the near future (e.g. ‘disk space low’). The software is still working as expected.
 * ERROR       Due to a more serious problem, the software has not been able to perform some function.
 * CRITICAL    A serious error, indicating that the program itself may be unable to continue running.
*/

#define LOG_LEVEL_CRITICAL  50
#define LOG_LEVEL_ERROR     40
#define LOG_LEVEL_WARNING   30
#define LOG_LEVEL_INFO      20
#define LOG_LEVEL_DEBUG     10
#define LOG_LEVEL_NOTSET    0


#define CRITICAL(en, fmt, ...) log_critical(en, "(%s:%d) "fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define ERROR(en, fmt, ...) log_error(en, "(%s:%d) "fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define WARNING(fmt, ...) log_warning("(%s:%d) "fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define INFO(fmt, ...) log_info("(%s:%d) "fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define DEBUG(fmt, ...) log_debug("(%s:%d) "fmt, __FILE__, __LINE__, ##__VA_ARGS__)


// en: errno
// The errno values are postive integers in standard C and POSIX.
// So if there is no system error, set en = 0
int log_critical(int en, char* format, ...);
int log_error(int en, char* format, ...);

int log_warning(char* format, ...);
int log_info(char* format, ...);
int log_debug(char* format, ...);

int set_log_level(int en);
int set_log_color();
int set_log_time();


#endif
