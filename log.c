#include <stdarg.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>

#include "log.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"


static int global_log_level = LOG_LEVEL_INFO;
static int global_use_color = 0;
static int global_print_time = 0;


int print_time(FILE *stream)
{
    if(global_print_time == 0)
        return 0;

    char buffer[32];
    int millisec;
    struct tm* tm_info;
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
    
    millisec = lrint(tv.tv_usec / 1000.0); // Round to nearest millisec
    if(millisec >= 1000) // Allow for rounding up to nearest second
    {
        millisec -=1000;
        tv.tv_sec++;
    }
    
    tm_info = localtime(&tv.tv_sec);
    
    strftime(buffer, 32, "%Y-%m-%d %H:%M:%S", tm_info);
    printf("%s.%03d ", buffer, millisec);

    fflush(NULL);
    
    return 0;
}


int print_time_sec(FILE *stream)
{
    if(global_print_time == 0)
        return 0;

    time_t timer;
    char buffer[64];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(buffer, 64, "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(stream, "%s ", buffer);

    return 0;
}

int set_log_time()
{
    global_print_time = 1;
    return 0;
}

int set_log_color()
{
    global_use_color = 1;
    return 0;
}

int set_log_level(int log_level)
{
    global_log_level = log_level;
    return 0;
}

int log_critical(int en, char* format, ...)
{
    if(global_log_level > LOG_LEVEL_CRITICAL)
        return 0;

    print_time(stderr);
    if(global_use_color)
        fprintf(stderr, ANSI_COLOR_RED"[CRITICAL] ");
    else
        fprintf(stderr, "[CRITICAL] ");

    va_list arglist;
    va_start(arglist, format);
    vfprintf(stderr, format, arglist);
    va_end(arglist);

    if(en == 0)
        fprintf(stderr, "\n");
    else
    {
        fprintf(stderr, ": ");
        errno = en;
        perror("");
    }

    if(global_use_color)
        fprintf(stderr, ANSI_COLOR_RESET);
    
    fflush(NULL);

    return 0;
}

int log_error(int en, char* format, ...)
{
    if(global_log_level > LOG_LEVEL_ERROR)
        return 0;

    print_time(stderr);
    if(global_use_color)
        fprintf(stderr, ANSI_COLOR_RED"[ERROR] ");
    else
        fprintf(stderr, "[ERROR] ");

    va_list arglist;
    va_start(arglist, format);
    vfprintf(stderr, format, arglist);
    va_end(arglist);

    if(en == 0)
        fprintf(stderr, "\n");
    else
    {
        fprintf(stderr, ": ");
        errno = en;
        perror("");
    }

    if(global_use_color)
        fprintf(stderr, ANSI_COLOR_RESET);

    fflush(NULL);

    return 0;
}


int log_warning(char* format, ...)
{
    if(global_log_level > LOG_LEVEL_WARNING)
        return 0;
    
    print_time(stdout);
    if(global_use_color)
        fprintf(stdout, ANSI_COLOR_YELLOW"[WARNING] ");
    else
        fprintf(stdout, "[WARNING] ");

    va_list arglist;
    va_start(arglist, format);
    vfprintf(stdout, format, arglist);
    va_end(arglist);

    if(global_use_color)
        fprintf(stdout, ANSI_COLOR_RESET"\n");
    else
        fprintf(stdout, "\n");

    fflush(NULL);

    return 0;
}

int log_info(char* format, ...)
{
    if(global_log_level > LOG_LEVEL_INFO)
        return 0;
    
    print_time(stdout);
    fprintf(stdout, "[INFO] ");

    va_list arglist;
    va_start(arglist, format);
    vfprintf(stdout, format, arglist);
    va_end(arglist);

    fprintf(stdout, "\n");

    fflush(NULL);

    return 0;
}

int log_debug(char* format, ...)
{
    if(global_log_level > LOG_LEVEL_DEBUG)
        return 0;
    
    print_time(stdout);
    fprintf(stdout, "[DEBUG] ");

    va_list arglist;
    va_start(arglist, format);
    vfprintf(stdout, format, arglist);
    va_end(arglist);

    fprintf(stdout, "\n");

    fflush(NULL);
    
    return 0;
}

