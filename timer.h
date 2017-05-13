#ifndef TIMER_H_
#define TIMER_H_

#include <stdint.h>
#include <sys/timerfd.h>

#include "bool.h"


typedef struct 
{
    bool running;
    struct timespec init_time;
    struct timespec interval;
    struct timespec deadline;  // init_time + interval
} timer_ms_t;


int start_timer(timer_ms_t * timer, int interval);  // unit of interval: ms, 1200 means 1 second 200 ms
int stop_timer(timer_ms_t * timer);
int restart_timer(timer_ms_t * timer);
bool timer_elapsed(const timer_ms_t * timer);
uint32_t get_timer_left(const timer_ms_t * timer);

#endif
