#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "delay-queue.h"


void * delay_queue_ticker(void * arg)
{
    
    delay_queue_t * dq = (delay_queue_t *)arg;
    uint64_t fd_buf = 0;

    while(dq->running)
    {
        if(read(dq->tick_fd, &fd_buf, sizeof(uint64_t)) < 0)
        {
            perror("delay_queue_ticker: read tick_fd");
            continue;
        }

         // the priority is the timer's interval, so for every tick, should decrease all node's priority
        queue_decrease(dq->queue, TICK_PRECISION);
    }

    return NULL;
}


delay_queue_t * delay_queue_init()
{
    delay_queue_t * dq = (delay_queue_t *)malloc(sizeof(delay_queue_t));
    if(dq == NULL)
    {
        perror("delay_queue_init: malloc");
        return NULL;
    }

    dq->running = true;

    dq->queue = queue_init(QUEUE_TYPE_PRIO_ASC);
    if(dq->queue == NULL)
    {
        printf("delay_queue_init: queue_init failed\n");
        return NULL;
    }

    dq->tick_interval.it_value.tv_sec = 0;
    dq->tick_interval.it_value.tv_nsec = TICK_PRECISION * 1000000;
    dq->tick_interval.it_interval.tv_sec = 0;
    dq->tick_interval.it_interval.tv_nsec = TICK_PRECISION * 1000000;

    dq->tick_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if(dq->tick_fd == -1)
    {
        perror("delay_queue_init: timerfd_create");
        return NULL;
    }

    if(timerfd_settime(dq->tick_fd, 0, &dq->tick_interval, NULL) == -1)
    {
        perror("delay_queue_init: timerfd_settime");
        return NULL;
    }

    if(pthread_create(&dq->ticker, NULL, delay_queue_ticker, dq) != 0)
    {
        perror("delay_queue_init: create delay_queue_ticker"); 
        return NULL;
    }

    return dq;
}


int delay_queue_destroy(delay_queue_t * dq, void (*free_data)(void *))
{
    if(dq == NULL)
        return 0;

    dq->running = false;
    pthread_cancel(dq->ticker);
    close(dq->tick_fd);

    if(free_data)
    {
        // should dequeue all and free data
        queue_destroy(dq->queue, &free);
    }
    else
        queue_destroy(dq->queue, &free);

    free(dq);

    return 0;
}


int delay_queue_put(delay_queue_t * dq, void * data, uint32_t delay)
{
    if(!dq || !dq->running)
        return -1;

    delay_queue_node_t * node = (delay_queue_node_t *)malloc(sizeof(delay_queue_node_t));
    if(node == NULL)
    {
        perror("delay_queue_put: malloc");
        return -1;
    }

    timer_start(&node->ms_timer, delay);
    node->data = data;

    if(queue_put(dq->queue, node, delay) != 0)
    {
        printf("delay_queue_put: failed\n");
        free(node);
        return -1;
    }

    return 0;
}


void * delay_queue_get(delay_queue_t * dq)
{
    if(!dq || !dq->running)
        return NULL;

    delay_queue_node_t * node;

    while(true)
    {
        if(queue_peek(dq->queue, (void **)&node, NULL) == 0)
            if(timer_elapsed(&node->ms_timer))
                break;

        nanosleep(&dq->tick_interval.it_interval, NULL);
    }

    void * data = NULL;
    if(queue_get(dq->queue, (void **)&node, NULL) == 0)
        data = node->data;

    free(node);

    return data;
}

