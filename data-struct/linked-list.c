#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "linked-list.h"


dll_t * dll_init()
{
    dll_t * list = (dll_t *)malloc(sizeof(dll_t));
    if(list == NULL)
    {
        perror("dll_append: malloc failed");
        return NULL;
    }

    list->size = 0;
    list->head = NULL;
    list->tail = NULL;
    list->compare = NULL;

    return list;
}


int dll_destroy(dll_t * list, void (*free_data)(void *))
{
    if(!list)
        return 0;

    dll_node_t * tmp = list->head;
    while(tmp)
    {
        list->head = list->head->next;
        if(free_data)
            free_data(tmp->data);
        free(tmp);
        tmp = list->head;
    }

    list->head = NULL;
    list->tail = NULL;

    free(list);

    return 0;
}


bool dll_is_empty(const dll_t * list)
{
    if(!list || !list->head || !list->tail)
        return true;
    else
        return false;
}


int dll_insert(dll_t * list, void * data)
{
    if(!list)
        return -1;

    dll_node_t * node = (dll_node_t *)malloc(sizeof(dll_node_t));
    if(node == NULL)
    {
        perror("dll_append: malloc failed");
        return -1;
    }

    node->prev = NULL;
    node->next = list->head;
    node->data = data;

    if(list->head)
        list->head->prev = node;

    list->head = node;

    // list is empty
    if(!list->tail)
        list->tail = node;

    list->size++;

    return 0;
}


int dll_append(dll_t * list, void * data)
{
    if(!list)
        return -1;

    dll_node_t * node = (dll_node_t *)malloc(sizeof(dll_node_t));
    if(node == NULL)
    {
        perror("dll_append: malloc failed");
        return -1;
    }

    node->prev = list->tail;
    node->next = NULL;
    node->data = data;

    if(list->tail)
        list->tail->next = node;

    list->tail = node;

    // list is empty
    if(!list->head)
        list->head = node;

    list->size++;

    return 0;
}


void * dll_shift(dll_t * list)
{
    if(dll_is_empty(list))
        return NULL;

    dll_node_t * head = list->head;

    list->head = head->next;
    if(head->next)
        head->next->prev= NULL;
    
    void * data = head->data;

    // list is empty
    if(!list->head)
        list->tail = NULL;

    free(head);
    list->size--;

    return data;
}


void * dll_pop(dll_t * list)
{
    if(dll_is_empty(list))
        return NULL;

    dll_node_t * tail = list->tail;

    list->tail = tail->prev;
    if(tail->prev)
        tail->prev->next = NULL;

    void * data = tail->data;

    // list is empty
    if(!list->tail)
        list->head = NULL;

    free(tail);
    list->size--;

    return data;
}


/*
 * taken from https://stackoverflow.com/questions/7685/merge-sort-a-linked-head/3032553#3032553
*/
static dll_node_t * merge_sort_list_recursive(dll_t * list, dll_node_t * head, int (*compare)(dll_t *, dll_node_t *, dll_node_t *))
{
    // Trivial case.
    if(!head || !head->next)
        return head;

    dll_node_t  *right  = head,
                *temp   = head,
                *last   = head,
                *result = 0,
                *next   = 0,
                *tail   = 0;

    // Find halfway through the head (by running two pointers, one at twice the speed of the other).
    while(temp && temp->next)
    {
        last = right;
        right = right->next;
        temp = temp->next->next;
    }

    // Break the head in two. (prev pointers are broken here, but we fix later)
    last->next = 0;

    // Recurse on the two smaller heads:
    head = merge_sort_list_recursive(list, head, compare);
    right = merge_sort_list_recursive(list, right, compare);

    // Merge:
    while(head || right)
    {
        // Take from empty heads, or compare:
        if(!right)
        {
            next = head;
            head = head->next;
        }
        else if(!head)
        {
            next = right;
            right = right->next;
        }
        else if(compare(list, head, right) < 0)
        {
            next = head;
            head = head->next;
        }
        else
        {
            next = right;
            right = right->next;
        }

        if(!result)
            result=next;
        else
            tail->next=next;

        next->prev = tail;  // Optional.
        tail = next;
    }
    return result;
}


static int dll_compare(dll_t * list, dll_node_t *one, dll_node_t *two)
{
    return list->compare(one->data, two->data);
}


int dll_sort(dll_t * list, int (*compare)(void *one, void *two))
{
    if(dll_is_empty(list))
        return 0;

    list->compare = compare;

    list->head = merge_sort_list_recursive(list, list->head, &dll_compare);

    // get the new tail
    dll_node_t * tmp = list->head;
    while(tmp)
    {
        list->tail = tmp;
        tmp = tmp->next;
    }

    return 0;
}

