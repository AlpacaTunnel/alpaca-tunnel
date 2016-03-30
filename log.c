#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static int global_log_level = ERROR_LEVEL;

int printlog(int en, char* format, ...)
{
    va_list arglist;
    time_t timer;
    char tm_buf[64];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(tm_buf, 64, "%Y-%m-%d %H:%M:%S", tm_info);
    if(en == 0)
    {
        printf("%s ", tm_buf);
        va_start(arglist, format);
        vprintf(format, arglist);
        va_end(arglist);
    }
    else if(en < 0)  //log level
    {
        if(en < global_log_level) //only print when level >= global_log_level
            return 0;

        printf("%s ", tm_buf);
        va_start(arglist, format);
        vprintf(format, arglist);
        va_end(arglist);
    }
    else  //errno defined by system
    {
        fprintf(stderr, "%s ", tm_buf);
        va_start(arglist, format);
        vfprintf(stderr, format, arglist);
        va_end(arglist);

        errno = en;
        perror(" ");
    }
    //fflush(NULL);

    return 0;
}

int set_log_level(int log_level)
{
    if(global_log_level > 0 || global_log_level < MAX_LEVEL)
    {
        printlog(0, "error set_log_level: log_level value may be wrong, default value ERROR_LEVEL will not changed\n");
        return -1;
    }

    global_log_level = log_level;
    return 0;
}
