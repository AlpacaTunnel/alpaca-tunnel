/*
 * Doubly linked list
*/


#ifndef LINKED_LIST_H_
#define LINKED_LIST_H_

#include "types.h"


struct dll_node
{
    void * data;
    struct dll_node * prev;
    struct dll_node * next;
};

typedef struct dll_node dll_node_t;


typedef struct
{
    int size;
    dll_node_t * head;
    dll_node_t * tail;
    int (*compare)(void *one, void *two);
} dll_t;


dll_t * dll_init();

int dll_destroy(dll_t * list, void (*free_data)(void *));  // if NO need to free the data, set free_data to NULL. you can put stdlib free() if it's malloc()

bool dll_is_empty(const dll_t * list);

int dll_insert(dll_t * list, void * data);  // insert into head

int dll_append(dll_t * list, void * data);  // append to tail

void * dll_shift(dll_t * list);  // shift from head

void * dll_pop(dll_t * list);  // pop from tail

int dll_sort(dll_t * list, int (*compare)(void *one, void *two));  // compare() on the void * data type


#endif
