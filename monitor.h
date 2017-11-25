/*
 * Monitor file, route, etc and trigger action.
 */


#ifndef MONITOR_H_
#define MONITOR_H_

#include <stdint.h>
#include <pthread.h>


#define MONITOR_PATH_MAX_LEN 1024

// #define MONITOR_TYPE_FILE 0
// #define MONITOR_TYPE_ROUTE 1
#define MONITOR_TYPE_ROUTE_IPV4 4
#define MONITOR_TYPE_ROUTE_IPV6 6


typedef struct
{
    int type;
    uint event_cnt;
    pthread_t monitor_td;
    pthread_t trigger_td;
    uint trigger_interval;
    void (*trigger)(void *);
    void * trigger_arg;
    char file_dir[MONITOR_PATH_MAX_LEN];
    char file_name[MONITOR_PATH_MAX_LEN];
    int route_family; // 4 or 6
} monitor_t;


// call trigger() every trigger_interval seconds, just like crontab
monitor_t * cronjob_start(uint trigger_interval, void (*trigger)(void *), void * trigger_arg);
int cronjob_stop(monitor_t * monitor);

// trigger_interval: 0 instantly, else check if trigger every $interval seconds
monitor_t * monitor_file_start(const char * file_path, uint trigger_interval, void (*trigger)(void *), void * trigger_arg);
int monitor_file_stop(monitor_t * monitor);

monitor_t * monitor_route_start(int family, uint trigger_interval, void (*trigger)(void *), void * trigger_arg);
int monitor_route_stop(monitor_t * monitor);


#endif
