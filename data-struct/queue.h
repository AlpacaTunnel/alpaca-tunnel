/*
 * Thread-safe queue.
*/


#ifndef QUEUE_H_
#define QUEUE_H_

#include <pthread.h>

#include "types.h"
#include "linked-list.h"


#define QUEUE_TYPE_FIFO 0
#define QUEUE_TYPE_LIFO 1
#define QUEUE_TYPE_PRIO_ASC 2  // ascending order, lower priority first
#define QUEUE_TYPE_PRIO_DES 3  // descending order, higher priority first


struct queue_node
{
    int priority;
    void * data;
};

typedef struct queue_node queue_node_t;


typedef struct
{
    int type;
    bool sorted;  // set to ture after sort(); set to false after enqueue
    int size;     // current size of nodes
    pthread_mutex_t * mutex;
    pthread_cond_t * cond;
    dll_t * list;  // use a doubly linked list to store queue_node
} queue_t;


queue_t * queue_init(int type);

int queue_destroy(queue_t * queue, void (*free_data)(void *));

bool queue_is_empty(const queue_t * queue);

int queue_put(queue_t * queue, void * data, int priority);

int queue_get(queue_t * queue, void ** data, int * priority);

int queue_look_first(queue_t * queue, void ** data, int * priority);  // take a look at the first node, but don't get anything.

int queue_decrease(queue_t * queue, int p);  // decrease the priority of all nodes by p, better to call before queue_get()

int queue_increase(queue_t * queue, int p);  // increase the priority of all nodes by p, better to call before queue_get()


#endif
