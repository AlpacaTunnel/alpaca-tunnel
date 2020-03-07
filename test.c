#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>


#include "data-struct/data-struct.h"
#include "log.h"
#include "route.h"
#include "monitor.h"
#include "signal.h"



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
    rc = queue_peek(q, (void **)&c, &p);
    printf("2 peek: %s, %d\n", c, p);

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

/**************************** test delay_queue *********************************************/



int test_delay_queue()
{
    delay_queue_t * q = delay_queue_init();
    // printf("%s\n", (char*)delay_queue_get(q));

    delay_queue_put(q, "tick217", 217);
    delay_queue_put(q, "tick73", 73);
    delay_queue_put(q, "tick170", 170);
    while(true)
        printf("%s\n", (char*)delay_queue_get(q));
    return 0;
}


/**************************** test delay_queue *********************************************/


/**************************** test monitor *********************************************/


void printabc(void * arg)
{
    char * a = (char *)arg;
    ERROR(0, "a is: %s\n", a);
    return;
}


int test_monitor()
{
    monitor_t * m = monitor_file_start("/tmp/abc", 3, NULL, NULL);
    // monitor_file_stop(m);

    monitor_t * r = monitor_route_start(4, 3, printabc, "route ipv4");
    // monitor_route_stop(r);

    monitor_t * c = cronjob_start(3, printabc, "cronjob");
    // cronjob_stop(c);

    while(true)
        sleep(1);

    return 0;
}


/**************************** test monitor *********************************************/



/**************************** test monitor *********************************************/


void printabc2(void * arg)
{
    char * a = (char *)arg;
    ERROR(0, "a is: %s\n", a);
    return;
}


int test_signal()
{
    signal_init();
    signal_install(SIGINT, printabc, "sigint");
    signal_install(SIGINT, printabc, "sigint");
    signal_install(SIGTERM, printabc, "sigterm");

    while(true)
        sleep(1);

    return 0;
}


/**************************** test monitor *********************************************/




/**************************** test forwarding_table *********************************************/

int test_forwarding_table()
{
    forwarding_table_t * table = forwarding_table_init(5);
    forwarding_table_put(table, 123, 456, 253);
    forwarding_table_put(table, 121, 456, 251);

    uint16_t next;
    next = forwarding_table_get(table, 121, 456); printf("%d\n", next);
    next = forwarding_table_get(table, 123, 456); printf("%d\n", next);

    forwarding_table_put(table, 124, 456, 254);
    forwarding_table_put(table, 125, 456, 255);
    forwarding_table_put(table, 120, 456, 250);

    next = forwarding_table_get(table, 123, 456); printf("%d\n", next);
    // forwarding_table_clear(table);
    next = forwarding_table_get(table, 123, 456); printf("%d\n", next);

    next = forwarding_table_get(table, 121, 456); printf("%d\n", next);
    forwarding_table_put(table, 129, 45, 259);
    forwarding_table_put(table, 127, 45, 257);
    forwarding_table_put(table, 128, 45, 258);
    next = forwarding_table_get(table, 123, 456); printf("%d\n", next);
    next = forwarding_table_get(table, 124, 456); printf("%d\n", next);
    next = forwarding_table_get(table, 121, 456); printf("%d\n", next);
    next = forwarding_table_get(table, 128, 45); printf("%d\n", next);
    sleep(100);

    return 0;
}

/**************************** test forwarding_table *********************************************/

int main(void)
{
    set_log_level(LOG_LEVEL_DEBUG);
    set_log_time();
    set_log_color();

    // test_dll();
    // test_queue();
    // test_delay_queue();
    // test_forwarding_table();
    test_monitor();
    // test_signal();

    return 0;
}

