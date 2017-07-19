#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>


#include "data-struct/data-struct.h"



/**************************** test linked list *********************************************/


int comp(void * one, void * two)
{
    return strcmp((char*)one, (char*)two);
}


int test_dll()
{
    dll_t * list = dll_init();

    if(dll_is_empty(list))
        printf("dll_is_empty\n");

    char * c1 = (char*)malloc(100);
    memcpy(c1, "c1", 5);
    dll_append(list, c1);
    printf("dll_append: %s\n", c1);
    if(dll_is_empty(list))
        printf("dll_is_empty\n");

    char * c2 = "c2";
    dll_insert(list, c2);
    printf("dll_insert: %s\n", c2);
    if(dll_is_empty(list))
        printf("dll_is_empty\n");

    dll_insert(list, "a1");
    dll_insert(list, "a2");
    dll_insert(list, "12");
    dll_insert(list, "c12");
    dll_insert(list, "d12");

    printf("list size: %d\n", list->size);

    dll_sort(list, &comp);
    printf("dll_sort\n");

    while(!dll_is_empty(list))
    {
        printf("dll_pop: %s\n", (char*)dll_pop(list));
    }

    printf("dll_shift: %s\n", (char*)dll_shift(list));
    if(dll_is_empty(list))
        printf("dll_is_empty\n");


    printf("dll_pop: %s\n", (char*)dll_pop(list));
    if(dll_is_empty(list))
        printf("dll_is_empty\n");


    char * c3 = "c3";
    dll_insert(list, c3);
    printf("dll_insert: %s\n", c3);
    if(dll_is_empty(list))
        printf("dll_is_empty\n");


    // dll_destroy(list, NULL);
    // list = NULL;
    // printf("dll_destroy\n");


    printf("dll_shift: %s\n", (char*)dll_shift(list));
    if(dll_is_empty(list))
        printf("dll_is_empty\n");

    printf("dll_pop: %s\n", (char*)dll_pop(list));
    if(dll_is_empty(list))
        printf("dll_is_empty\n");

    dll_destroy(list, NULL);
    printf("dll_destroy\n");

    if(dll_is_empty(list))
        printf("dll_is_empty\n");

    return 0;
}




/**************************** test queue *********************************************/

void *queue_thread1(void *arg)
{
    queue_t * q = (queue_t *)arg;

    // queue_node_t * t1 = (queue_node_t *)malloc(sizeof(queue_node_t));
    // char * c = (char *)malloc(10);
    char * c = "ccccc";

    // t1->data = c;
    // sleep(1);

    queue_put(q, c, 0);
    queue_put(q, "a1", 1);
    queue_put(q, "a4", 30);
    sleep(2);
    queue_put(q, "a3", 20);
    queue_put(q, "a2", 10);
    printf("1 put: %s\n", c);

    return NULL;
}

void *queue_thread4(void *arg)
{
    queue_t * q = (queue_t *)arg;

    // queue_node_t * t1 = (queue_node_t *)malloc(sizeof(queue_node_t));
    // char * c = (char *)malloc(10);
    char * c = "dddd";

    // t1->data = c;
    sleep(1);

    queue_put(q, c, 110);
    queue_put(q, "d1", 11);
    queue_put(q, "d4", 33);
    queue_put(q, "d3", 120);
    queue_put(q, "d2", 10);
    printf("1 put: %s\n", c);

    return NULL;
}

void *queue_thread2(void *arg)
{
    queue_t * q = (queue_t *)arg;
    sleep(3);

    // queue_node_t * t1 = (queue_node_t *)malloc(sizeof(queue_node_t));
    char * c;// = (char *)malloc(100);
    int rc, p;

    queue_decrease(q, 2);
    rc = queue_look_first(q, (void **)&c, &p);
    printf("2 look: %s, %d\n", c, p);

    while(true)
    {
        rc = queue_get(q, (void **)&c, &p);
        // rc = queue_get(q, (void **)&c, NULL);
        if(rc == 0)
            printf("2 get: %s, %d\n", c, p);
        else
            printf("queue_get failed\n");
        sleep(1);
    }
    
    return NULL;
}

void *queue_thread3(void *arg)
{
    
    queue_t * q = (queue_t *)arg;
    sleep(4);

    // queue_node_t * t1 = (queue_node_t *)malloc(sizeof(queue_node_t));
    char * c = (char *)malloc(100);

    int rc, p;
    while(true)
    {
        rc = queue_get(q, (void **)&c, &p);
        // rc = queue_get(q, (void **)&c, NULL);
        if(rc == 0)
            printf("3 get: %s, %d\n", c, p);
        else
            printf("queue_get failed\n");
        sleep(1);
    }
    
    return NULL;
}


int test_queue()
{
    pthread_t p1, p2, p3, p4;

    queue_t *q = queue_init(QUEUE_TYPE_PRIO_DES);
    // queue_t *q = queue_init(QUEUE_TYPE_LIFO);
    // queue_destroy(q, NULL);

    pthread_create(&p1, NULL, queue_thread1, q);
    pthread_create(&p2, NULL, queue_thread2, q);
    pthread_create(&p3, NULL, queue_thread3, q);
    pthread_create(&p4, NULL, queue_thread4, q);

    pthread_join(p1, NULL);
    pthread_join(p2, NULL);
    pthread_join(p3, NULL);
    pthread_join(p4, NULL);

    return 0;
}

/**************************** test queue *********************************************/

/**************************** test tick_queue *********************************************/



int test_tick_queue()
{
    tick_queue_t * q = tick_queue_init();
    // printf("%s\n", (char*)tick_queue_get(q));

    tick_queue_put(q, "tick217", 217);
    tick_queue_put(q, "tick73", 73);
    tick_queue_put(q, "tick170", 170);
    while(true)
        printf("%s\n", (char*)tick_queue_get(q));
    return 0;
}


/**************************** test tick_queue *********************************************/


int main(void)
{
    // test_dll();
    test_queue();
    // test_tick_queue();

    return 0;
}

