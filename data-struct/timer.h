/*
 * A ms level timer.
*/

#ifndef TIMER_H_
#define TIMER_H_

#include <stdint.h>
#include <sys/timerfd.h>

#include "types.h"


typedef struct 
{
    bool running;
    struct timespec init_time;
    struct timespec interval;
    struct timespec deadline;  // init_time + interval
} timer_ms_t;


int timer_start(timer_ms_t * timer, int interval);  // unit of interval: ms, 1200 means 1 second 200 ms
int timer_stop(timer_ms_t * timer);
int timer_restart(timer_ms_t * timer);
bool timer_elapsed(const timer_ms_t * timer);
uint32_t timer_left(const timer_ms_t * timer);

#endif
