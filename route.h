#ifndef ROUTE_H_
#define ROUTE_H_

#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

//rtnetlink's args are in network byte order, so are the parameters & data in this file

/*
on receiving RTMGRP_NOTIFY, these two tables will be reset.
route table: clear
ip_dst      ip_src      next_hop_id
2.2.2.2     10.1.1.2    1.1
3.3.3.3     10.1.2.2    1.2
...

link_list: re-collect info
if_index    name        ipaddr       mask
1           lo          127.0.0.1   255
2           eth0        10.16.1.2   16777215
3
4           alptun1     10.5.2.2    65535

*/

struct route_item
{
    uint16_t next_hop_id;
    uint32_t ip_dst;
    uint32_t ip_src;
};

struct if_info
{
    struct if_info *next;
    int index;
    uint32_t addr;
    uint32_t mask;
    uint32_t ptp; //P_t_P, Point-to-Point peer addr.
    char name[IFNAMSIZ];
};

struct rtnl_handle
{
    int fd;
    struct sockaddr_nl  local;
    struct sockaddr_nl  peer;
};


#define RT_TB_SIZE 1024

int clear_route();
int add_route(uint16_t next_hop_id, uint32_t ip_dst, uint32_t ip_src);
uint16_t get_route(uint32_t ip_dst, uint32_t ip_src);

int clear_if_info(struct if_info *info);
int collect_if_info(struct if_info **first);

//given an IP, return the iif's index
int get_ipiif(uint32_t ip);
//given an IP, return the iif's mask
uint32_t get_ipmask(uint32_t ip);
//given an IP, return the if's index if the IP is a local IP
int get_ipif_local(uint32_t ip);

//return gateway or 0
uint32_t get_sys_iproute(uint32_t ip_dst, uint32_t ip_src, int iif_index);


/* get next hop id form route_table or system route table
 * return value:
 * 1 : local or link dst, should write to tunnel interface
 * >1: the ID of other tunnel server
*/
uint16_t get_next_hop_id(uint32_t ip_dst, uint32_t ip_src);


#endif
