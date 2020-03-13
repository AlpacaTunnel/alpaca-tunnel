#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <linux/rtnetlink.h>


#include "data-struct/data-struct.h"
#include "log.h"
#include "route.h"
#include "monitor.h"


void* monitor_file_thread(void *arg);
void* monitor_route_thread(void *arg);
void* cronjob_thread(void *arg);


void* monitor_trigger_thread(void *arg)
{
    monitor_t * monitor = (monitor_t *)arg;

    int sleep_time = 0;
    if(monitor->trigger_interval > 0)
        sleep_time = monitor->trigger_interval;
    else
        sleep_time = 1;

    int pre = monitor->event_cnt;
    while(true)
    {
        if(pre != monitor->event_cnt)
        {
            if(monitor->trigger_interval > 0 && monitor->trigger)
                monitor->trigger(monitor->trigger_arg);
            pre = monitor->event_cnt;
        }
        sleep(sleep_time);
    }

    return NULL;
}


monitor_t * cronjob_start(uint32_t trigger_interval, void (*trigger)(void *), void * trigger_arg)
{
    if(trigger_interval < 1)
    {
        ERROR(0, "trigger_interval must be largger than 1");
        return NULL;
    }

    monitor_t * monitor = (monitor_t *)malloc(sizeof(monitor_t));
    if(monitor == NULL)
    {
        ERROR(errno, "monitor_init: malloc");
        return NULL;
    }

    bzero(monitor, sizeof(monitor_t));

    monitor->trigger_interval = trigger_interval;
    monitor->trigger = trigger;
    monitor->trigger_arg = trigger_arg;

    DEBUG("Cronjob start: %d", &(monitor->trigger));

    if(pthread_create(&monitor->trigger_td, NULL, cronjob_thread, monitor) != 0)
    {
        ERROR(errno, "monitor_init: create cronjob_thread");
        free(monitor);
        return NULL;
    }

    return monitor;
}


int cronjob_stop(monitor_t * monitor)
{
    DEBUG("Cronjob stopped: %d", &(monitor->trigger));
    pthread_cancel(monitor->trigger_td);
    free(monitor);
    return 0;
}


void* cronjob_thread(void *arg)
{
    monitor_t * monitor = (monitor_t *)arg;

    while(true)
    {
        if(monitor->trigger)
            monitor->trigger(monitor->trigger_arg);
        sleep(monitor->trigger_interval);
    }

    return NULL;
}


monitor_t * monitor_file_start(const char * file_path, uint32_t trigger_interval, void (*trigger)(void *), void * trigger_arg)
{
    monitor_t * monitor = (monitor_t *)malloc(sizeof(monitor_t));
    if(monitor == NULL)
    {
        ERROR(errno, "monitor_init: malloc");
        return NULL;
    }

    bzero(monitor, sizeof(monitor_t));

    monitor->trigger_interval = trigger_interval;
    monitor->trigger = trigger;
    monitor->trigger_arg = trigger_arg;

    strncpy(monitor->file_dir, file_path, MONITOR_PATH_MAX_LEN);
    int path_len = strlen(file_path);
    while(file_path[path_len] != '/' && path_len >= 0)
    {
        monitor->file_dir[path_len] = '\0';
        path_len--;
    }
    strncpy(monitor->file_name, &file_path[path_len+1], MONITOR_PATH_MAX_LEN);

    if(strlen(monitor->file_dir) == 0)
        monitor->file_dir[0] = '.';

    DEBUG("Monitor dir: %s", monitor->file_dir);
    DEBUG("Monitor name: %s", monitor->file_name);

    if(pthread_create(&monitor->monitor_td, NULL, monitor_file_thread, monitor) != 0)
    {
        ERROR(errno, "monitor_init: create monitor_file_thread");
        free(monitor);
        return NULL;
    }

    if(pthread_create(&monitor->trigger_td, NULL, monitor_trigger_thread, monitor) != 0)
    {
        ERROR(errno, "monitor_init: create monitor_trigger_thread");
        free(monitor);
        return NULL;
    }

    return monitor;
}


int monitor_file_stop(monitor_t * monitor)
{
    if(monitor == NULL)
        return 0;

    DEBUG("File monitor stopped: %s%s", monitor->file_dir, monitor->file_name);

    pthread_cancel(monitor->monitor_td);
    pthread_cancel(monitor->trigger_td);
    free(monitor);
    return 0;
}


void* monitor_file_thread(void *arg)
{
    monitor_t * monitor = (monitor_t *)arg;

    int event_size = sizeof(struct inotify_event);
    int buf_len = 1024 * (event_size + 16);
    int msg_len=0, fd=0, wd=0;
    char buffer[buf_len];

    fd = inotify_init();
    if(fd < 0)
    {
        ERROR(errno, "inotify_init");
        return NULL;
    }

    wd = inotify_add_watch(fd, monitor->file_dir, IN_MODIFY | IN_CREATE | IN_DELETE);

    while(true)
    {
        int i = 0;
        msg_len = read(fd, buffer, buf_len);
        if(msg_len < 0)
        {
            ERROR(errno, "read inotify");
            return NULL;
        }

        while(i < msg_len)
        {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if(event->len)
            {
                if(str_equal(event->name, monitor->file_name))
                {
                    // only monitor file, not dir
                    if(event->mask & IN_ISDIR)
                    {
                        if(event->mask & IN_CREATE)
                            WARNING("Monitoring file but dir with the same name has been created (ignore it): %s", event->name);
                        else if(event->mask & IN_MODIFY)
                            WARNING("Monitoring file but dir with the same name has been modified (ignore it): %s", event->name);
                        else if(event->mask & IN_DELETE)
                            WARNING("Monitoring file but dir with the same name has been deleted (ignore it): %s", event->name);
                    }
                    else
                    {
                        if(event->mask & IN_CREATE)
                            DEBUG("Monitor file has been created: %s", event->name);
                        else if(event->mask & IN_MODIFY)
                            DEBUG("Monitor file has been modified: %s", event->name);
                        else if(event->mask & IN_DELETE)
                            DEBUG("Monitor file has been deleted: %s", event->name);

                        monitor->event_cnt++;
                        if(monitor->trigger_interval <= 0 && monitor->trigger)
                            monitor->trigger(monitor->trigger_arg);
                    }
                }
            }
            i += event_size + event->len;
        }
    }

    (void)inotify_rm_watch(fd, wd);
    (void)close(fd);
    return NULL;
}


monitor_t * monitor_route_start(int family, uint32_t trigger_interval, void (*trigger)(void *), void * trigger_arg)
{
    monitor_t * monitor = (monitor_t *)malloc(sizeof(monitor_t));
    if(monitor == NULL)
    {
        ERROR(errno, "monitor_init: malloc");
        return NULL;
    }

    bzero(monitor, sizeof(monitor_t));

    monitor->trigger_interval = trigger_interval;
    monitor->trigger = trigger;
    monitor->trigger_arg = trigger_arg;

    if(family != MONITOR_TYPE_ROUTE_IPV4 && family != MONITOR_TYPE_ROUTE_IPV6)
    {
        ERROR(0, "Monitor route error, unknown family: %d. Only MONITOR_TYPE_ROUTE_IPV4/MONITOR_TYPE_ROUTE_IPV6 allowed.", family);
        return NULL;
    }
    monitor->route_family = family;

    if(family == MONITOR_TYPE_ROUTE_IPV4)
        DEBUG("Monitor IPv4 route.");
    if(family == MONITOR_TYPE_ROUTE_IPV6)
        DEBUG("Monitor IPv6 route.");

    if(pthread_create(&monitor->monitor_td, NULL, monitor_route_thread, monitor) != 0)
    {
        ERROR(errno, "monitor_init: create monitor_route_thread");
        free(monitor);
        return NULL;
    }

    if(pthread_create(&monitor->trigger_td, NULL, monitor_trigger_thread, monitor) != 0)
    {
        ERROR(errno, "monitor_init: create monitor_trigger_thread");
        free(monitor);
        return NULL;
    }

    return monitor;
}


int monitor_route_stop(monitor_t * monitor)
{
    if(monitor == NULL)
        return 0;

    if(monitor->route_family == MONITOR_TYPE_ROUTE_IPV4)
        DEBUG("Route monitor stopped: IPv4");
    if(monitor->route_family == MONITOR_TYPE_ROUTE_IPV6)
        DEBUG("Route monitor stopped: IPv6");

    pthread_cancel(monitor->monitor_td);
    pthread_cancel(monitor->trigger_td);
    free(monitor);
    return 0;
}


void* monitor_route_thread(void *arg)
{
    monitor_t * monitor = (monitor_t *)arg;

    char buf[8192];
    rtnl_handle_t rth;
    rth.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    bzero(&rth.local, sizeof(rth.local));
    rth.local.nl_family = AF_NETLINK;
    rth.local.nl_pid = getpid()+1;

    if(monitor->route_family == MONITOR_TYPE_ROUTE_IPV4)
        rth.local.nl_groups = RTMGRP_NOTIFY | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE | RTMGRP_IPV4_IFADDR;
    if(monitor->route_family == MONITOR_TYPE_ROUTE_IPV6)
        rth.local.nl_groups = RTMGRP_NOTIFY | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;

    if(bind(rth.fd, (struct sockaddr*) &rth.local, sizeof(rth.local)) < 0)
    {
        ERROR(errno, "rtnl_handle_t bind");
        return NULL;
    }

    while(true)
        if(recv(rth.fd, buf, sizeof(buf), 0))
        {
            if(monitor->route_family == MONITOR_TYPE_ROUTE_IPV4)
                DEBUG("Monitor route family changed: IPv4");
            if(monitor->route_family == MONITOR_TYPE_ROUTE_IPV6)
                DEBUG("Monitor route family changed: IPv6");

            monitor->event_cnt++;
            if(monitor->trigger_interval <= 0 && monitor->trigger)
                monitor->trigger(monitor->trigger_arg);
        }

    close(rth.fd);
    return NULL;
}

