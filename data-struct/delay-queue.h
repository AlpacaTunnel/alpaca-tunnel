/*
 * Thread-safe delay queue. Put data into queue with an interval, then get it after the interval.
 * The timer can be implemented with priority queue, but not so clear.
*/


#ifndef TICK_QUEUE_H_
#define TICK_QUEUE_H_

#include <pthread.h>

#include "queue.h"
#include "timer.h"

#define TICK_PRECISION 5  // ms


struct delay_queue_node
{
    timer_ms_t ms_timer;  // queue priority is equal to timer
    void * data;
};

typedef struct delay_queue_node delay_queue_node_t;


typedef struct
{
    bool running;
    int tick_fd;
    struct itimerspec tick_interval;
    pthread_t ticker;  // tick thread, decrease interval in queue every TICK_PRECISION ms
    queue_t * queue;   // use a queue to store delay_queue_node
} delay_queue_t;


delay_queue_t * delay_queue_init();

int delay_queue_destroy(delay_queue_t * tq, void (*free_data)(void *));

int delay_queue_put(delay_queue_t * tq, void * data, uint32_t delay);  // unit of delay: ms

void * delay_queue_get(delay_queue_t * tq);


#endif
