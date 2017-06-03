#ifndef DATA_STRUCT_H_
#define DATA_STRUCT_H_

/* handle bit array, search, sort, list, etc... */

#include <stdint.h>

#include "bool.h"

#define BIT_ARRAY_MAX_SIZE (1<<24)
#define BIT_ARRAY_UNIT_SIZE 8
//#define BIT_ARRAY_UNIT_MASK 0xFF
typedef uint8_t bit_array_unit;

typedef struct 
{
    bit_array_unit *array;
    uint32_t size;
} bit_array_t;


// linked list node
struct ll_node
{
    void * data;
    struct ll_node * next;
};

typedef struct ll_node ll_node_t;


// doubly linked list node
struct dll_node
{
    void * data;
    struct dll_node * prev;
    struct dll_node * next;
};

typedef struct dll_node dll_node_t;


// priority queue node
typedef struct
{
    int priority;
    void * data;
} pq_node_t;


/*
 * All the pointers are pointed to type pq_node_t.
 * Only when queue is empty, front == rear
*/
typedef struct
{
    int order;    // 0: lower priority first, 1: higher priority first
    bool sorted;  // set to ture after sort; set to false after enqueue
    int size;     // max node number
    int front;    // front node, dequeue from here, a relative node index
    int rear;     // rear node, enqueue into here, a relative node index
    uintptr_t base;     // base pointer, the memory address when malloc the queue, a ABSOLUTE pointer
} prior_q_t;


bool str_is_empty(const char * str);
bool str_equal(const char * str1, const char * str2);
bool strn_equal(const char * str1, const char * str2, int n);


//must call at first
bit_array_t* bit_array_create(uint32_t size);
//must call at the end
int bit_array_destroy(bit_array_t *ba);
int bit_array_copy(bit_array_t *dst, bit_array_t *src);

int bit_array_clearall(bit_array_t *ba);
int bit_array_setall(bit_array_t *ba);

/*
  return -1: error
  return 0: empty
  return 1: occupy
*/
int bit_array_set(bit_array_t *ba, uint32_t index);
int bit_array_clear(bit_array_t *ba, uint32_t index);
int bit_array_get(bit_array_t *ba, uint32_t index);


int binary_search(const int64_t arr[], int start, int end, int64_t key);
void bubble_sort(int64_t arr[], int len);
void merge_sort(int64_t arr[], int len);


ll_node_t * ll_append(ll_node_t ** first, void * data);
void * ll_shift(ll_node_t ** first);
int ll_free(ll_node_t ** first);
bool ll_is_empty(const ll_node_t * first);
void * ll_get_next(ll_node_t * first, ll_node_t ** saveptr); // use the function just like strtok_r()


/*
 * The ll_array is self made malloc! must load data with another array after init.
*/
int ll_array_init(ll_node_t ** head, uint size);  // use an array to init the list! actually, this array is a random accessed list with pre allocated spaces.
int ll_array_destory(ll_node_t * head);  // free the array
ll_node_t * ll_array_borrow(ll_node_t * node);  // remove a node form the list, but memory not freed.
int ll_array_return(ll_node_t * head, ll_node_t * node);  // insert the node into the list. don't return twice!!

/* 
 * point the data in ll_node to the ralated address of data array
 * array_size MUST be the same as the size of ll_array_init(), and the data array size MUST be array_size!
*/
int ll_array_load_data(ll_node_t * head, uint array_size, uintptr_t data_base, uint unit_size);


int pq_init(prior_q_t * queue, int size);
int pq_sort(prior_q_t * queue, int order);  // user MUST call sort before dequeue!!!
int pq_enq(prior_q_t * queue, pq_node_t * node);
int pq_deq(prior_q_t * queue, pq_node_t * node);
int pq_reduce(prior_q_t * queue, int p);  // reduce the priority of all nodes by p, better to call before sort
int pq_increase(prior_q_t * queue, int p);  // increase the priority of all nodes by p, better to call before sort
int pq_look_first(prior_q_t * queue, pq_node_t * node);  // take a look at the first node, don't change anything.
int pq_destory(prior_q_t * queue);


#endif
