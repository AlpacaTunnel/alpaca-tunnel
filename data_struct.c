#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "data_struct.h"
#include "log.h"


bool str_is_empty(const char * str)
{
    return str[0] == '\0';
}


bool str_equal(const char * str1, const char * str2)
{
    if(strcmp(str1, str2) == 0)
        return true;
    else
        return false;
}


bool strn_equal(const char * str1, const char * str2, int n)
{
    if(strncmp(str1, str2, n) == 0)
        return true;
    else
        return false;
}


bit_array_t* bit_array_create(uint32_t size)
{
    if(size == 0 || size > BIT_ARRAY_MAX_SIZE)
    {
        ERROR(0, "bit_array_create: size is illegal: %d.", size);
        return NULL;
    }

    bit_array_t * ba = (bit_array_t *)malloc(sizeof(bit_array_t));
    if(ba == NULL)
    {
        ERROR(errno, "bit_array_create: malloc failed");
        return NULL;
    }
    else
        bzero(ba, sizeof(bit_array_t));

    ba->size = size;
    uint32_t unit_num = (size + BIT_ARRAY_UNIT_SIZE - 1) / BIT_ARRAY_UNIT_SIZE;
    ba->array = (bit_array_unit *)malloc(unit_num);
    if(ba->array == NULL)
    {
        ERROR(errno, "bit_array_create: malloc failed");
        free(ba);
        return NULL;
    }
    else
        bzero(ba->array, unit_num);

    return ba;
}

int bit_array_destroy(bit_array_t *ba)
{
    if(ba == NULL)
        return 0;

    if(ba->array != NULL)
        free(ba->array);
    ba->array = NULL;
    free(ba);
    ba = NULL;

    return 0;
}

int bit_array_copy(bit_array_t *dst, bit_array_t *src)
{
    if(dst == NULL || src == NULL)
    {
        ERROR(0, "bit_array_copy: dst or src is NULL.");
        return -1;
    }
    if(dst->size != src->size)
    {
        ERROR(0, "bit_array_copy: dst->size != src->size.");
        return -1;
    }
    uint32_t unit_num = (dst->size + BIT_ARRAY_UNIT_SIZE - 1) / BIT_ARRAY_UNIT_SIZE;
    memcpy(dst->array, src->array, unit_num);

    return 0;
}

int bit_array_clearall(bit_array_t *ba)
{
    int i;
    uint32_t unit_num = (ba->size + BIT_ARRAY_UNIT_SIZE - 1) / BIT_ARRAY_UNIT_SIZE;
    for(i=0; i<unit_num; i++)
        ba->array[i] = 0;

    return 0;
}

int bit_array_setall(bit_array_t *ba)
{
    int i;
    uint32_t unit_num = (ba->size + BIT_ARRAY_UNIT_SIZE - 1) / BIT_ARRAY_UNIT_SIZE;
    for(i=0; i<unit_num; i++)
        ba->array[i] = ~0;

    return 0;
}

int bit_array_set(bit_array_t *ba, uint32_t index)
{
    if(index > ba->size)
    {
        ERROR(0, "bit_array_set: index is larger than size: %d.", index);
        return -1;
    }

    uint32_t array_index = index / BIT_ARRAY_UNIT_SIZE;
    uint32_t bit_index = index % BIT_ARRAY_UNIT_SIZE;
    ba->array[array_index] |= (1 << bit_index);

    return 0;
}

int bit_array_clear(bit_array_t *ba, uint32_t index)
{
    if(index > ba->size)
    {
        ERROR(0, "bit_array_clear: index is larger than size: %d.", index);
        return -1;
    }

    uint32_t array_index = index / BIT_ARRAY_UNIT_SIZE;
    uint32_t bit_index = index % BIT_ARRAY_UNIT_SIZE;
    ba->array[array_index] &= (~(1 << bit_index));

    return 0;
}

int bit_array_get(bit_array_t *ba, uint32_t index)
{
    if(index > ba->size)
    {
        ERROR(0, "bit_array_get: index is larger than size: %d.", index);
        return -1;
    }

    uint32_t array_index = index / BIT_ARRAY_UNIT_SIZE;
    uint32_t bit_index = index % BIT_ARRAY_UNIT_SIZE;
    int v = (ba->array[array_index] >> bit_index) & 1 ;

    return v;
}

int binary_search(const int64_t arr[], int start, int end, int64_t key)
{
    int mid;
    while (start <= end) 
    {
        mid = start + (end - start) / 2;
        if (arr[mid] < key)
            start = mid + 1;
        else if (arr[mid] > key)
            end = mid - 1;
        else
            return mid;
    }
    return -1;
}


void bubble_sort(int64_t arr[], int len)
{
    uint32_t i, j, temp;
    for (i = 0; i < len-1; i++)
        for (j = 0; j < len-1-i; j++)
            if (arr[j] > arr[j+1])
            {
                temp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = temp;
            }
}

int min(int x, int y)
{
    return x < y ? x : y;
}

void merge_sort(int64_t arr[], int len)
{
    int64_t * a = arr;
    int64_t * b = (int64_t*) malloc(len * sizeof(int64_t));
    if(b == NULL)
    {
        ERROR(errno, "merge_sort: malloc failed");
        return;
    }
    int64_t * mark_b = b;

    int seg, start;
    for(seg = 1; seg < len; seg += seg)
    {
        for(start = 0; start < len; start += seg + seg)
        {
            int low = start, mid = min(start + seg, len), high = min(start + seg + seg, len);
            int k = low;
            int start1 = low, end1 = mid;
            int start2 = mid, end2 = high;
            while(start1 < end1 && start2 < end2)
                if(a[start1] < a[start2])
                {
                    b[k] = a[start1];
                    k++; start1++;
                }
                else
                {
                    b[k] = a[start2];
                    k++; start2++;
                }
            while(start1 < end1)
            {
                b[k] = a[start1];
                k++; start1++;
            }
            while(start2 < end2)
            {
                b[k] = a[start2];
                k++; start2++;
            }
        }
        int64_t* temp = a;
        a = b;
        b = temp;
        // at the end, a always holds the sorted array
    }

    if(a != arr)
        for(int i = 0; i < len; i++)
            arr[i] = a[i];
    
    free(mark_b);
}


ll_node_t * ll_append(ll_node_t ** first, void * data)
{
    ll_node_t * new = (ll_node_t *)malloc(sizeof(ll_node_t));
    if(new == NULL)
    {
        ERROR(errno, "ll_append: malloc failed");
        return NULL;
    }
    new->data = data;
    new->next = NULL;

    if (*first == NULL)
        *first = new;
    else
    {
        ll_node_t * tmp = *first;
        while(tmp->next != NULL)
            tmp = tmp->next;

        // append new to the last
        tmp->next = new;
    }
    
    return new;
}

void * ll_shift(ll_node_t ** first)
{
    if(*first == NULL)
        return NULL;

    // get first node
    ll_node_t * tmp = *first;
    *first = (*first)->next;
    void * data = tmp->data;
    free(tmp);

    return data;
}

int ll_free(ll_node_t ** first)
{
    if(*first == NULL)
        return 0;

    ll_node_t * tmp;
    while(*first)
    {
        tmp = *first;
        *first = (*first)->next;
        free(tmp->data);
        free(tmp);
    }

    return 0;
}


bool ll_is_empty(const ll_node_t * first)
{
    return first == NULL;
}


void * ll_get_next(ll_node_t * first, ll_node_t ** saveptr)
{
    if(first != NULL)
        *saveptr = first;

    if(ll_is_empty(*saveptr))
        return NULL;
    else
    {
        void * data = (*saveptr)->data;
        *saveptr = (*saveptr)->next;
        return data;
    }
}


int ll_array_init(ll_node_t ** head, uint size)
{
    // head is always the first node and cannot be borrowed.
    size++;

    ll_node_t * base = (ll_node_t *)malloc(size * sizeof(ll_node_t));
    if(base == NULL)
    {
        ERROR(errno, "ll_array_init: malloc failed");
        return -1;
    }

    for(int i = 0; i < size; ++i)
    {
        ll_node_t * next = base + (i + 1) % size;
        base[i].next = next;
        base[i].data = NULL;
    }

    *head = base;

    return 0;
}

int ll_array_destory(ll_node_t * head)
{
    if(head != NULL)
        free(head);

    return 0;
}

ll_node_t * ll_array_borrow(ll_node_t * head)
{
    if(head == NULL)
        return NULL;

    if(head == head->next)
    {
        ERROR(0, "ll_array_borrow: list is empty!");
        return NULL;
    }
    
    // first is the head
    ll_node_t * second = head->next;
    ll_node_t * third = second->next;

    head->next = third;

    return second;
}

int ll_array_return(ll_node_t * head, ll_node_t * node)
{
    if(head == NULL || node == NULL)
        return -1;

    // first is the head
    ll_node_t * second = head->next;
    
    head->next = node;
    node->next = second;

    return 0;
}

int ll_array_load_data(ll_node_t * head, uint array_size, uintptr_t data_base, uint unit_size)
{
    if(head == NULL || data_base == 0 || array_size == 0 || unit_size == 0)
        return -1;

    for(int i = 0; i < array_size; ++i)
    {
        ll_node_t * node = head + i;
        void * data = (void *)(data_base + i * unit_size);
        node->data = data;
    }
    return 0;
}


int pq_init(prior_q_t * queue, int size)
{
    size++;  // when front == rear, it occupies an empty node
    pq_node_t * base = (pq_node_t *)malloc((size) * sizeof(pq_node_t));
    if(base == NULL)
    {
        ERROR(errno, "pq_init: malloc failed");
        return -1;
    }

    for(int i = 0; i < size; ++i)
    {
        base[i].priority = 0;
        base[i].data = NULL;
    }

    queue->base = (uintptr_t)base;
    queue->size = size;
    queue->front = 0;
    queue->rear = 0;

    return 0;
}

int pq_destory(prior_q_t * queue)
{
    if(queue == NULL)
        return 0;

    // for(int i = 0; i < queue->size; ++i)
    //    free(queue->base[i].data);

    free((pq_node_t*)(queue->base));

    return 0;
}

int pq_enq(prior_q_t * queue, pq_node_t * node)
{
    if(queue == NULL)
        return -1;

    int after_rear = (queue->rear + 1) % queue->size;
    if(after_rear == queue->front) // queue is full
    {
        DEBUG("enqueue failed, queue is full");
        return -1;
    }

    pq_node_t * rear_node = (pq_node_t*)(queue->base + queue->rear * sizeof(pq_node_t));
    rear_node->priority = node->priority;
    rear_node->data = node->data;

    // change the index after data is ready. so the pq_sort() can sort the new and right data.
    queue->rear = after_rear;

    return 0;
}

int pq_deq(prior_q_t * queue, pq_node_t * node)
{
    if(queue->front == queue->rear) // empty
        return -1;

    // Copy the front node to another memory
    // Don't return the front node, because in multi-thread environment, once queue->front changes,
    // the node it points may be overwritten.
    pq_node_t * front_node = (pq_node_t *)(queue->base + queue->front * sizeof(pq_node_t));
    node->priority = front_node->priority;
    node->data = front_node->data;

    // change the index after data is copied.
    queue->front = (queue->front + 1) % queue->size;

    return 0;
}

int pq_reduce(prior_q_t * queue, int p)
{
    if(queue->front == queue->rear) // empty
        return -1;

    int len = (queue->rear - queue->front + queue->size) % queue->size;
    pq_node_t * base = (pq_node_t *)(queue->base);

    for(int i = 0; i < len; i++)
        base[(i + queue->front) % queue->size].priority -= p;

    return 0;
}

int pq_look_first(prior_q_t * queue, pq_node_t * node)
{
    if(queue->front == queue->rear) // empty
        return -1;

    pq_node_t * front_node = (pq_node_t *)(queue->base + queue->front * sizeof(pq_node_t));
    node->priority = front_node->priority;
    node->data = front_node->data;

    return 0;
}

int pq_sort(prior_q_t * queue, int order)
{
    if(queue == NULL)
        return -1;

    // during sorting, rear pointer may change, because there may be new data.
    // so calculate len first.
    int len = (queue->rear - queue->front + queue->size) % queue->size;

    if(len <= 1)
        return 0;
    
    pq_node_t * a = (pq_node_t *)malloc(len * sizeof(pq_node_t));
    if(a == NULL)
    {
        ERROR(errno, "pq_sort: malloc failed");
        return -1;
    }

    pq_node_t * b = (pq_node_t *)malloc(len * sizeof(pq_node_t));
    if(b == NULL)
    {
        ERROR(errno, "pq_sort: malloc failed");
        free(a);
        return -1;
    }

    // for simplicity, copy all nodes to an array first
    pq_node_t * base = (pq_node_t *)(queue->base);
    for(int i = 0; i < len; i++)
        a[i] = base[(i + queue->front) % queue->size];

    int seg, start;
    for(seg = 1; seg < len; seg += seg)
    {
        for(start = 0; start < len; start += seg + seg)
        {
            int low = start, mid = min(start + seg, len), high = min(start + seg + seg, len);
            int k = low;
            int start1 = low, end1 = mid;
            int start2 = mid, end2 = high;
            while(start1 < end1 && start2 < end2)
                if(a[start1].priority < a[start2].priority)
                {
                    b[k] = a[start1];
                    k++; start1++;
                }
                else
                {
                    b[k] = a[start2];
                    k++; start2++;
                }
            while(start1 < end1)
            {
                b[k] = a[start1];
                k++; start1++;
            }
            while(start2 < end2)
            {
                b[k] = a[start2];
                k++; start2++;
            }
        }
        pq_node_t * temp = a;
        a = b;
        b = temp;
        // at the end, a always holds the sorted array
    }

    // copy the sorted array back
    for(int i = 0; i < len; i++)
        base[(i + queue->front) % queue->size] = a[i];

    free(a);
    free(b);

    return 0;
}

