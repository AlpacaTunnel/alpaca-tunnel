/*
 * The forwarding_table should use a data struct that fits for a lot of searching, so I choose sorted array here.

 * When inserting new route item, the oldest should be deleted. How to find the oldest?
 * Let's use a counter, for each search the total counter increases by 1, then the one with the smallest counter is the oldest one.
 * The counter is actually timestamp, though it does not increase every second.
 * At SEQ_LEVEL_1-speed (16000pbs), a uint64_t counter is enough and won't overflow forever.

 * caller should watch if ip route/rule has changed.
 * on receiving RTMGRP_NOTIFY, these two tables must be reset.

 * route table: clear
 * ip_dst      ip_src      gw_id
 * 2.2.2.2     10.1.1.2    1.1
 * 3.3.3.3     10.1.2.2    1.2
 * ...

 * link_list: re-collect info
 * if_index    name        ipaddr       mask
 * 1           lo          127.0.0.1   255
 * 2           eth0        10.16.1.2   16777215
 * 3
 * 4           alptun1     10.5.2.2    65535

 * rtnetlink's args are in network byte order, so are the parameters & data in this file

*/


#ifndef ROUTE_H_
#define ROUTE_H_

#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>


#define ROUTE_TYPE_IPV4 0
#define ROUTE_TYPE_IPV6 1


typedef struct
{
    uint16_t gw_id;
    uint32_t ip_dst;
    uint32_t ip_src;
    uint64_t ip_cat;   // concatenate ip_dst and ip_src, ip_cat = ip_dst << 32 + ip_src
    uint64_t counter;  // the latest counter of current route item
} route_item_t;


typedef struct
{
    int type;
    uint32_t size;
    uint64_t counter;  // the latest counter of all route items
    route_item_t * array;
    pthread_mutex_t * mutex;
} forwarding_table_t;


struct if_info
{
    struct if_info *next;
    int index;
    uint32_t addr;
    uint32_t mask;
    uint32_t ptp; //P_t_P, Point-to-Point peer addr.
    char name[IFNAMSIZ];
};
typedef struct if_info if_info_t;


typedef struct
{
    int fd;
    struct sockaddr_nl  local;
    struct sockaddr_nl  peer;
} rtnl_handle_t;


forwarding_table_t * forwarding_table_init(uint32_t size);
int forwarding_table_destroy(forwarding_table_t * table);
int forwarding_table_clear(forwarding_table_t * table);
uint16_t forwarding_table_get(forwarding_table_t * table, uint32_t ip_dst, uint32_t ip_src);
int forwarding_table_put(forwarding_table_t * table, uint32_t ip_dst, uint32_t ip_src, uint16_t gw_id);


int clear_if_info(if_info_t *info);
int collect_if_info(if_info_t **first);

//given an IP, return the iif's index
int get_ipiif(uint32_t ip, if_info_t *if_list);

//given an IP, return the iif's mask
uint32_t get_ipmask(uint32_t ip, if_info_t *if_list);

//given an IP, return the if's index if the IP is a local IP(the IP is in if_list)
int get_ipif_local(uint32_t ip, if_info_t *if_list);

//given a string, return the if's index if the string is a interface name(the name is in if_list)
int get_strif_local(const char * name, if_info_t *if_list);


//return gateway or 0
uint32_t get_sys_iproute(uint32_t ip_dst, uint32_t ip_src, if_info_t *if_list);

// dev: the index of the oif
int add_sys_iproute(uint32_t ip_dst, uint32_t mask, uint32_t gateway, int dev, int table);
int del_sys_iproute(uint32_t ip_dst, uint32_t mask, uint32_t gateway, int dev, int table);

// return the number in /etc/iproute2/rt_tables
int get_rt_table(const char * table);

// gw_dev: the index of the gateway interface
int chnroute_add(char * data_path, uint32_t gw_ip, int table, int gw_dev);
int chnroute_del(char * data_path, int table);


#endif
