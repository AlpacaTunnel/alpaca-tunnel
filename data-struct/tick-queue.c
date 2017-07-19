#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "tick-queue.h"


void * tick_queue_ticker(void * arg)
{
    
    tick_queue_t * tq = (tick_queue_t *)arg;
    uint64_t fd_buf = 0;

    while(tq->running)
    {
        if(read(tq->tick_fd, &fd_buf, sizeof(uint64_t)) < 0)
        {
            perror("tick_queue_ticker: read tick_fd");
            continue;
        }

         // the priority is the timer's interval, so for every tick, should decrease all node's priority
        queue_decrease(tq->queue, TICK_PRECISION);
    }

    return NULL;
}


tick_queue_t * tick_queue_init()
{
    tick_queue_t * tq = (tick_queue_t *)malloc(sizeof(tick_queue_t));
    if(tq == NULL)
    {
        perror("tick_queue_init: malloc");
        return NULL;
    }

    tq->running = true;

    tq->queue = queue_init(QUEUE_TYPE_PRIO_ASC);
    if(tq->queue == NULL)
    {
        printf("tick_queue_init: queue_init failed\n");
        return NULL;
    }

    tq->tick_interval.it_value.tv_sec = 0;
    tq->tick_interval.it_value.tv_nsec = TICK_PRECISION * 1000000;
    tq->tick_interval.it_interval.tv_sec = 0;
    tq->tick_interval.it_interval.tv_nsec = TICK_PRECISION * 1000000;

    tq->tick_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if(tq->tick_fd == -1)
    {
        perror("tick_queue_init: timerfd_create");
        return NULL;
    }

    if(timerfd_settime(tq->tick_fd, 0, &tq->tick_interval, NULL) == -1)
    {
        perror("tick_queue_init: timerfd_settime");
        return NULL;
    }

    if(pthread_create(&tq->ticker, NULL, tick_queue_ticker, tq) != 0)
    {
        perror("tick_queue_init: create tick_queue_ticker"); 
        return NULL;
    }

    return tq;
}


int tick_queue_destroy(tick_queue_t * tq, void (*free_data)(void *))
{
    if(tq == NULL)
        return 0;

    tq->running = false;
    pthread_cancel(tq->ticker);
    close(tq->tick_fd);

    if(free_data)
    {
        // should dequeue all and free data
        queue_destroy(tq->queue, &free);
    }
    else
        queue_destroy(tq->queue, &free);

    free(tq);

    return 0;
}


int tick_queue_put(tick_queue_t * tq, void * data, uint32_t interval)
{
    if(!tq || !tq->running)
        return -1;

    tick_queue_node_t * node = (tick_queue_node_t *)malloc(sizeof(tick_queue_node_t));
    if(node == NULL)
    {
        perror("tick_queue_put: malloc");
        return -1;
    }

    timer_start(&node->ms_timer, interval);
    node->data = data;

    if(queue_put(tq->queue, node, interval) != 0)
    {
        printf("tick_queue_put: failed\n");
        free(node);
        return -1;
    }

    return 0;
}


void * tick_queue_get(tick_queue_t * tq)
{
    if(!tq || !tq->running)
        return NULL;

    tick_queue_node_t * node;

    while(true)
    {
        if(queue_look_first(tq->queue, (void **)&node, NULL) == 0)
            if(timer_elapsed(&node->ms_timer))
                break;

        nanosleep(&tq->tick_interval.it_interval, NULL);
    }

    void * data = NULL;
    if(queue_get(tq->queue, (void **)&node, NULL) == 0)
        data = node->data;

    free(node);

    return data;
}

