#include "timer.h"

/*
 * These timespec_* manipulation functions were taken from http://lxr.free-electrons.com/source/include/linux/time.h
 * and http://lxr.free-electrons.com/source/kernel/time/time.c. I can't find a header to include, so I copied them.
 *
 * And the timer was inspired by CycloneTCP, http://www.oryx-embedded.com/doc/tcp__timer_8c_source.html
*/

#define MSEC_PER_SEC    1000L
#define NSEC_PER_MSEC   1000000L
#define NSEC_PER_SEC    1000000000L
typedef long long s64;


static void timespec_set_normalized(struct timespec *ts, time_t sec, s64 nsec)
{
    while(nsec >= NSEC_PER_SEC)
    {
        /*
         * The following asm() prevents the compiler from
         * optimising this loop into a modulo operation. See
         * also __iter_div_u64_rem() in include/linux/time.h
         */
        asm("" : "+rm"(nsec));
        nsec -= NSEC_PER_SEC;
        ++sec;
    }
    while(nsec < 0)
    {
        asm("" : "+rm"(nsec));
        nsec += NSEC_PER_SEC;
        --sec;
    }
    ts->tv_sec = sec;
    ts->tv_nsec = nsec;
}


static inline int timespec_compare(const struct timespec *lhs, const struct timespec *rhs)
{
    if(lhs->tv_sec < rhs->tv_sec)
        return -1;
    if(lhs->tv_sec > rhs->tv_sec)
        return 1;
    return lhs->tv_nsec - rhs->tv_nsec;
}


static inline struct timespec timespec_add(struct timespec lhs, struct timespec rhs)
{
    struct timespec ts_delta;
    timespec_set_normalized(&ts_delta, lhs.tv_sec + rhs.tv_sec, lhs.tv_nsec + rhs.tv_nsec);
    return ts_delta;
}

/*
 * sub = lhs - rhs, in normalized form
 */
static inline struct timespec timespec_sub(struct timespec lhs, struct timespec rhs)
{
    struct timespec ts_delta;
    timespec_set_normalized(&ts_delta, lhs.tv_sec - rhs.tv_sec, lhs.tv_nsec - rhs.tv_nsec);
    return ts_delta;
}

static inline s64 timespec_to_ns(const struct timespec *ts)
{
    return ((s64) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

static inline uint32_t timespec_to_ms(const struct timespec *ts)
{
    return (uint32_t)(ts->tv_sec * MSEC_PER_SEC) + (uint32_t)(ts->tv_nsec / NSEC_PER_MSEC);
}


/********************** timer *********************/


int timer_start(timer_ms_t * timer, int interval)
{
    clock_gettime(CLOCK_REALTIME, &(timer->init_time));

    timer->interval.tv_sec = 0;
    timer->interval.tv_nsec = 0;
    timespec_set_normalized(&(timer->interval), 0, interval * NSEC_PER_MSEC);

    timer->deadline = timespec_add(timer->init_time, timer->interval);

    timer->running = true;

    return 0;
}


int timer_stop(timer_ms_t * timer)
{
    timer->running = false;
    return 0;
}


int timer_restart(timer_ms_t * timer)
{
    clock_gettime(CLOCK_REALTIME, &(timer->init_time));
    return 0;
}


bool timer_elapsed(const timer_ms_t * timer)
{
    if(!timer->running)
        return false;

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    if(timespec_compare(&(timer->deadline), &now) > 0)
        return false;
    else
        return true;
}

uint32_t timer_left(const timer_ms_t * timer)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct timespec left = timespec_sub(timer->deadline, now);
    return timespec_to_ms(&left);
}

