#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "queue.h"


/*
 * Should free/destroy previous resource if fail.
 * But no harm if didn't.
*/
queue_t * queue_init(int type)
{
    if(type < 0 || type > 3)
    {
        printf("queue_init: wrong type: %d\n", type);
        return NULL;
    }

    queue_t * queue = (queue_t *)malloc(sizeof(queue_t));
    if(queue == NULL)
    {
        perror("queue_init: malloc");
        return NULL;
    }

    queue->list = dll_init();
    if(queue->list == NULL)
    {
        printf("queue_init: dll_init failed\n");
        return NULL;
    }

    queue->mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if(queue->mutex == NULL)
    {
        printf("queue_init: malloc failed\n");
        return NULL;
    }

    if(pthread_mutex_init(queue->mutex, NULL) != 0)
    {
        perror("queue_init: pthread_mutex_init");
        return NULL;
    }

    queue->cond = (pthread_cond_t *)malloc(sizeof(pthread_cond_t));
    if(queue->cond == NULL)
    {
        printf("queue_init: malloc failed\n");
        return NULL;
    }

    if(pthread_cond_init(queue->cond, NULL) != 0)
    {
        perror("queue_init: pthread_cond_init");
        return NULL;
    }

    queue->size = 0;
    queue->type = type;

    return queue;
}


int queue_destroy(queue_t * queue, void (*free_data)(void *))
{
    if(queue == NULL)
        return 0;

    pthread_mutex_destroy(queue->mutex);
    pthread_cond_destroy(queue->cond);
    free(queue->mutex);
    free(queue->cond);

    if(free_data)
    {
        // should dequeue all and free data
        dll_destroy(queue->list, &free);
    }
    else
        dll_destroy(queue->list, &free);

    free(queue);

    return 0;
}


bool queue_is_empty(const queue_t * queue)
{
    if(!queue || dll_is_empty(queue->list))
        return true;
    else
        return false;
}


static int queue_node_compair_asc(void * one, void * two)
{
    return ((queue_node_t *)one)->priority - ((queue_node_t *)two)->priority;
}


static int queue_node_compair_des(void * one, void * two)
{
    return ((queue_node_t *)two)->priority - ((queue_node_t *)one)->priority;
}


static int queue_sort_asc(queue_t * queue)
{
    if(queue->sorted)
        return 0;
    else
    {
        queue->sorted = true;
        return dll_sort(queue->list, &queue_node_compair_asc);
    }
}


static int queue_sort_des(queue_t * queue)
{
    if(queue->sorted)
        return 0;
    else
    {
        queue->sorted = true;
        return dll_sort(queue->list, &queue_node_compair_des);
    }
}


int queue_put(queue_t * queue, void * data, int priority)
{
    if(queue == NULL)
        return -1;

    queue_node_t * node = (queue_node_t *)malloc(sizeof(queue_node_t));
    if(node == NULL)
    {
        perror("queue_put: malloc");
        return -1;
    }

    if(pthread_mutex_lock(queue->mutex) != 0)
    {
        perror("queue_put: pthread_mutex_lock");
        free(node);
        return -1;
    }

    node->priority = priority;
    node->data = data;

    int rc = 0;
    if(queue->type == QUEUE_TYPE_FIFO || queue->type == QUEUE_TYPE_PRIO_ASC)
        rc = dll_append(queue->list, node);
    else
        rc = dll_insert(queue->list, node);

    if(rc != 0)
    {
        printf("queue_put: failed\n");
        free(node);
        if(pthread_mutex_unlock(queue->mutex) != 0)
            perror("queue_put: pthread_mutex_unlock");
        return -1;
    }

    queue->size++;
    queue->sorted = false;

    pthread_cond_signal(queue->cond);

    if(pthread_mutex_unlock(queue->mutex) != 0)
        perror("queue_put: pthread_mutex_unlock");

    return 0;
}


int queue_get(queue_t * queue, void ** data, int * priority)
{
    if(queue == NULL)
        return -1;

    if(pthread_mutex_lock(queue->mutex) != 0)
    {
        perror("queue_get: pthread_mutex_lock");
        return -1;
    }

    while(dll_is_empty(queue->list))
        pthread_cond_wait(queue->cond, queue->mutex);

    if(queue->type == QUEUE_TYPE_PRIO_ASC)
        queue_sort_asc(queue);

    if(queue->type == QUEUE_TYPE_PRIO_DES)
        queue_sort_des(queue);

    queue_node_t * node = dll_shift(queue->list);

    if(priority)
        *priority = node->priority;
    if(data)
        *data = node->data;

    free(node);
    queue->size--;

    if(pthread_mutex_unlock(queue->mutex) != 0)
        perror("queue_get: pthread_mutex_unlock");

    return 0;
}


int queue_look_first(queue_t * queue, void ** data, int * priority)
{
    if(queue == NULL)
        return -1;

    if(pthread_mutex_lock(queue->mutex) != 0)
    {
        perror("queue_get: pthread_mutex_lock");
        return -1;
    }

    while(dll_is_empty(queue->list))
        pthread_cond_wait(queue->cond, queue->mutex);

    if(queue->type == QUEUE_TYPE_PRIO_ASC)
        queue_sort_asc(queue);

    if(queue->type == QUEUE_TYPE_PRIO_DES)
        queue_sort_des(queue);

    queue_node_t * node = dll_shift(queue->list);

    if(priority)
        *priority = node->priority;
    if(data)
        *data = node->data;

    dll_insert(queue->list, node);

    if(pthread_mutex_unlock(queue->mutex) != 0)
        perror("queue_get: pthread_mutex_unlock");

    return 0;
}


static int queue_priority_change(queue_t * queue, int p, int action)
{
    if(queue == NULL)
        return -1;

    if(pthread_mutex_lock(queue->mutex) != 0)
    {
        perror("pthread_mutex_lock");
        return -1;
    }

    dll_t * tmp_list = (dll_t *)malloc(sizeof(dll_t));
    if(tmp_list == NULL)
    {
        perror("queue_reduce: malloc");
        if(pthread_mutex_unlock(queue->mutex) != 0)
            perror("pthread_mutex_unlock");
        return -1;
    }

    while(!dll_is_empty(queue->list))
    {
        queue_node_t * node = dll_shift(queue->list);

        if(action == 0)
            node->priority -= p;
        else
            node->priority += p;

        dll_append(tmp_list, node);
    }

    dll_destroy(queue->list, NULL);
    queue->list = tmp_list;

    if(pthread_mutex_unlock(queue->mutex) != 0)
        perror("pthread_mutex_unlock");

    return 0;
}


int queue_decrease(queue_t * queue, int p)
{
    return queue_priority_change(queue, p, 0);
}


int queue_increase(queue_t * queue, int p)
{
    return queue_priority_change(queue, p, 1);
}

