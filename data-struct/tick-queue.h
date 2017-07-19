/*
 * Thread-safe tick queue. Put data into queue with an interval, then get it after the interval.
*/


#ifndef TICK_QUEUE_H_
#define TICK_QUEUE_H_

#include <pthread.h>

#include "queue.h"
#include "timer.h"

#define TICK_PRECISION 5  // ms


struct tick_queue_node
{
    timer_ms_t ms_timer;  // queue priority is equal to timer
    void * data;
};

typedef struct tick_queue_node tick_queue_node_t;


typedef struct
{
    bool running;
    int tick_fd;
    struct itimerspec tick_interval;
    pthread_t ticker;  // tick thread, decrease interval in queue every TICK_PRECISION ms
    queue_t * queue;   // use a queue to store tick_queue_node
} tick_queue_t;


tick_queue_t * tick_queue_init();

int tick_queue_destroy(tick_queue_t * tq, void (*free_data)(void *));

int tick_queue_put(tick_queue_t * tq, void * data, uint32_t interval);  // unit of interval: ms

void * tick_queue_get(tick_queue_t * tq);


#endif
