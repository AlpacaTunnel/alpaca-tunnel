#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <bits/sockaddr.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ifaddrs.h>

#include "route.h"
#include "log.h"


#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static pthread_spinlock_t route_spin;
static int route_spin_inited = 0;

//rt_tb_index points to the latest route_item_t
static int rt_tb_index = 0;
static struct route_item_t route_table[RT_TB_SIZE];

int init_route_spin()
{
    if(0 == route_spin_inited)
    {
        if(pthread_spin_init(&route_spin, PTHREAD_PROCESS_PRIVATE) != 0)
        {
            ERROR(errno, "pthread_spin_init");
            return -1;
        }
        route_spin_inited = 1;
    }
    return 0;
}

int destroy_route_spin()
{
    if(1 == route_spin_inited)
    {
        if(pthread_spin_destroy(&route_spin) != 0)
        {
            ERROR(errno, "pthread_spin_destroy");
            return -1;
        }
        route_spin_inited = 0;
    }
    return 0;
}

int lock_route_spin()
{
    if(pthread_spin_lock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_lock");
        return -1;
    }
    return 0;
}

int unlock_route_spin()
{
    if(pthread_spin_unlock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_unlock");
        return -1;
    }
    return 0;
}

int clear_route()
{
    if(pthread_spin_lock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_lock");
        return -1;
    }

    int i = 0;
    for(i = 0; i < RT_TB_SIZE; i++)
    {
        route_table[i].next_hop_id = 0;
        route_table[i].ip_dst = 0;
        route_table[i].ip_src = 0;
    }
    rt_tb_index = 0;
    
    if(pthread_spin_unlock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_unlock");
        return -1;
    }

    return 0;
}

int add_route(uint16_t next_hop_id, uint32_t ip_dst, uint32_t ip_src)
{
    if(pthread_spin_lock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_lock");
        return -1;
    }

    rt_tb_index = (rt_tb_index + 1) % RT_TB_SIZE;
    route_table[rt_tb_index].next_hop_id = next_hop_id;
    route_table[rt_tb_index].ip_dst = ip_dst;
    route_table[rt_tb_index].ip_src = ip_src;

    if(pthread_spin_unlock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_unlock");
        return -1;
    }

    return 0;
}

uint16_t get_route(uint32_t ip_dst, uint32_t ip_src)
{
    //struct timespec start, stop;
    //clock_gettime(CLOCK_REALTIME, &start);

    int i;
    for(i = rt_tb_index; i != (rt_tb_index+1) % RT_TB_SIZE; i = (i-1+RT_TB_SIZE) % RT_TB_SIZE)
        if(ip_dst == route_table[i].ip_dst && ip_src == route_table[i].ip_src)
            return route_table[i].next_hop_id;
        
    //clock_gettime(CLOCK_REALTIME, &stop);
    //printf("took %lu\n", stop.tv_sec - start.tv_sec);
    //printf("took %lu\n", stop.tv_nsec - start.tv_nsec);
    
    //if not found, return 0
    return 0;
}

int get_ipif_local(uint32_t ip, struct if_info_t *if_list)
{
    struct if_info_t *p = if_list;
    while(p)
    {
        if(p->addr == ip)
            return p->index;
        p = p->next;
    }

    return 0;
}

int get_strif_local(const char * name, struct if_info_t *if_list)
{
    struct if_info_t *p = if_list;
    while(p)
    {
        if(strcmp(p->name, name) == 0)
            return p->index;
        p = p->next;
    }

    return 0;
}

int get_ipiif(uint32_t ip, struct if_info_t *if_list)
{
    struct if_info_t *p = if_list;
    while(p)
    {
        if(p->ptp == ip)
            return p->index;
        if((p->addr & p->mask) == (ip & p->mask))
            return p->index;
        p = p->next;
    }

    return 0;
}

uint32_t get_ipmask(uint32_t ip, struct if_info_t *if_list)
{
    struct if_info_t *p = if_list;
    while(p)
    {
        if(p->ptp == ip)
            return p->mask;
        if((p->addr & p->mask) == (ip & p->mask))
            return p->mask;
        p = p->next;
    }

    return 0;
}

int clear_if_info(struct if_info_t *info)
{
    if(NULL == info)
        return 0;
    
    if(pthread_spin_lock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_lock");
        return -1;
    }

    struct if_info_t *p;
    while(info)
    {
        p = info;
        info = info->next;
        free(p);
    }

    if(pthread_spin_unlock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_unlock");
        return -1;
    }

    return 0;
}

int collect_if_info(struct if_info_t **first)
{
    if(pthread_spin_lock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_lock");
        return -1;
    }

    struct ifaddrs *ifaddr, *ifa;
    if(getifaddrs(&ifaddr) == -1) 
    {
        ERROR(errno, "collect_if_info: getifaddrs");
        return -1;
    }
    int index = 0;
    struct if_info_t *p = NULL;
    struct if_info_t *last = NULL;
    *first = NULL;
    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        index = if_nametoindex(ifa->ifa_name);
        if(0 == index)
        {
            ERROR(errno, "collect_if_info: if_nametoindex");
            continue;
        }
        if(NULL == ifa->ifa_addr || AF_INET != ifa->ifa_addr->sa_family)
            continue;

        p = malloc(sizeof(struct if_info_t));

        if(NULL == *first)
            *first = p;
        else
            last->next = p;

        p->index = index;
        strncpy(p->name, ifa->ifa_name, IFNAMSIZ);
        struct sockaddr_in *s1;
        s1 = (struct sockaddr_in *)ifa->ifa_addr;
        p->addr = s1->sin_addr.s_addr;
        s1 = (struct sockaddr_in *)ifa->ifa_netmask;
        p->mask = s1->sin_addr.s_addr;
        if(IFF_POINTOPOINT & ifa->ifa_flags)
        {
            s1 = (struct sockaddr_in *)ifa->ifa_ifu.ifu_dstaddr;
            p->ptp = s1->sin_addr.s_addr;
        }
        else
            p->ptp = 0;

        p->next = NULL;
        last = p;
    }

    freeifaddrs(ifaddr);

    if(pthread_spin_unlock(&route_spin) != 0)
    {
        ERROR(errno, "pthread_spin_unlock");
        return -1;
    }

    return 0;
}

uint32_t get_sys_iproute(uint32_t ip_dst, uint32_t ip_src, struct if_info_t *if_list)
{
    //ip rou get 4.4.4.4 from 10.7.0.2 iif ppptun2
    //ip_dst & ip_src are in network byte order
    
    if(0 == ip_dst || 0 == ip_src || 0 == ~ip_dst || 0 == ~ip_src)
        return 0;

    //link or local
    if(get_ipiif(ip_dst, if_list))
        return ip_dst;

    // buffer to hold the RTNETLINK request
    struct 
    {
        struct nlmsghdr nl;
        struct rtmsg    rt;
        char            buf[8192];
    } rt_req;

    struct rtnl_handle_t rth;
    struct nlmsghdr *nlp;
    struct rtmsg *rtp;
    struct rtattr *rtap;
    rth.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    bzero(&rth.local, sizeof(rth.local));
    rth.local.nl_family = AF_NETLINK;
    rth.local.nl_pid = getpid();
    //rth.local.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY;
    rth.local.nl_groups = 0;
    bind(rth.fd, (struct sockaddr*) &rth.local, sizeof(rth.local));

    bzero(&rt_req, sizeof(rt_req));

    rt_req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    rt_req.nl.nlmsg_flags = NLM_F_REQUEST ;
    rt_req.nl.nlmsg_type = RTM_GETROUTE;

    // set the routing message header
    rt_req.rt.rtm_family = AF_INET;
    //rt_req.rt.rtm_table = RT_TABLE_MAIN;
    rt_req.rt.rtm_table = 0;

    int len;
    rt_req.rt.rtm_dst_len = 32;
    len = RTA_LENGTH(32);
    rtap = NLMSG_TAIL(&rt_req.nl);
    rtap->rta_type = RTA_DST;
    rtap->rta_len = len;
    memcpy(RTA_DATA(rtap), &ip_dst, sizeof(ip_dst));
    rt_req.nl.nlmsg_len = NLMSG_ALIGN(rt_req.nl.nlmsg_len) + RTA_ALIGN(len);

    rt_req.rt.rtm_src_len = 32;
    len = RTA_LENGTH(32);
    rtap = NLMSG_TAIL(&rt_req.nl);
    rtap->rta_type = RTA_SRC;
    rtap->rta_len = len;
    memcpy(RTA_DATA(rtap), &ip_src, sizeof(ip_src));
    rt_req.nl.nlmsg_len = NLMSG_ALIGN(rt_req.nl.nlmsg_len) + RTA_ALIGN(len);

    //if ip_src is local IP, don't send iif_index, else send:
    if(0 == get_ipif_local(ip_src, if_list))
    {
        len = RTA_LENGTH(32);
        rtap = NLMSG_TAIL(&rt_req.nl);
        rtap->rta_type = RTA_IIF;
        rtap->rta_len = len;
        int iif_index = get_ipiif(ip_src, if_list);
        memcpy(RTA_DATA(rtap), &iif_index, sizeof(iif_index));
        rt_req.nl.nlmsg_len = NLMSG_ALIGN(rt_req.nl.nlmsg_len) + RTA_ALIGN(len);
    }

    //send msg
    struct msghdr msg;
    struct iovec iov;
    int rtn;

    bzero(&rth.peer, sizeof(rth.peer));
    rth.peer.nl_family = AF_NETLINK;

    // initialize & create the struct msghdr supplied
    // to the sendmsg() function
    bzero(&msg, sizeof(msg));
    msg.msg_name = (void *) &rth.peer;
    msg.msg_namelen = sizeof(rth.peer);

    // place the pointer & size of the RTNETLINK
    // message in the struct msghdr
    iov.iov_base = (void *) &rt_req;
    iov.iov_len = rt_req.nl.nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // send the RTNETLINK message to kernel
    rtn = sendmsg(rth.fd, &msg, 0);


    //------------===================------------------------


    // would it miss the message and block here?
    rtn = recv(rth.fd, rt_req.buf, sizeof(rt_req.buf), 0);

    nlp = (struct nlmsghdr *) rt_req.buf;
    struct in_addr *dst = NULL;
    struct in_addr *gw = NULL;
    //int *oif = NULL;

    for( ; NLMSG_OK(nlp, rtn); nlp=NLMSG_NEXT(nlp, rtn))
    {
        // get route entry header
        rtp = (struct rtmsg *) NLMSG_DATA(nlp);

        rtap = (struct rtattr *) RTM_RTA(rtp);
        int rtl = RTM_PAYLOAD(nlp);
        for( ; RTA_OK(rtap, rtl); rtap=RTA_NEXT(rtap,rtl))
        {
            switch(rtap->rta_type)
            {
                case RTA_DST:
                    dst = RTA_DATA(rtap);
                    break;

                case RTA_GATEWAY:
                    gw = RTA_DATA(rtap);
                    break;

                case RTA_OIF:
                    //oif = RTA_DATA(rtap);
                    break;
                
                default:
                    break;
            }
        }
    }

    close(rth.fd);
    if((NULL == dst) || (dst->s_addr != ip_dst))
        return 0;

    if(gw)
        return gw->s_addr; //return next_hop_ip, in network byte order
    else
        return 0;
        //return -(*oif);
}

/*
 * action = 0, add
 * action = 1, del
*/
int set_sys_iproute(uint32_t ip_dst, uint32_t mask, uint32_t gateway, int dev, int table, int action)
{
    if(action == 0 && gateway == 0 && dev == 0)
        return -1;

    int nlmsg_type = NLMSG_NOOP;
    if(action == 0)
        nlmsg_type = RTM_NEWROUTE;
    else if(action == 1)
        nlmsg_type = RTM_DELROUTE;

    // buffer to hold the RTNETLINK request
    struct 
    {
        struct nlmsghdr nl;
        struct rtmsg    rt;
        char            buf[8192];
    } rt_req;

    struct rtnl_handle_t rth;
    struct rtattr *rtap;
    int rtl;

    rth.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    bzero(&rth.local, sizeof(rth.local));
    rth.local.nl_family = AF_NETLINK;
    rth.local.nl_pid = getpid();
    rth.local.nl_groups = 0;
    bind(rth.fd, (struct sockaddr*) &rth.local, sizeof(rth.local));

    bzero(&rt_req, sizeof(rt_req));

    rtl = sizeof(struct rtmsg);

    // add first attrib:
    // set destination IP addr and increment the RTNETLINK buffer size
    rtap = (struct rtattr *) rt_req.buf;
    rtap->rta_type = RTA_DST;
    rtap->rta_len = sizeof(struct rtattr) + sizeof(ip_dst);
    memcpy(((char *)rtap) + sizeof(struct rtattr), &ip_dst, sizeof(ip_dst));
    rtl += rtap->rta_len;

    // add second attrib: set oif index
    rtap = (struct rtattr *) (((char *)rtap) + rtap->rta_len);
    rtap->rta_type = RTA_OIF;
    rtap->rta_len = sizeof(struct rtattr) + sizeof(dev);
    memcpy(((char *)rtap) + sizeof(struct rtattr), &dev, sizeof(dev));
    rtl += rtap->rta_len;

    // add third attrib: set gateway
    rtap = (struct rtattr *) (((char *)rtap) + rtap->rta_len);
    rtap->rta_type = RTA_GATEWAY;
    rtap->rta_len = sizeof(struct rtattr) + sizeof(gateway);
    memcpy(((char *)rtap) + sizeof(struct rtattr), &gateway, sizeof(gateway));
    rtl += rtap->rta_len;

    rt_req.nl.nlmsg_len = NLMSG_LENGTH(rtl);
    rt_req.nl.nlmsg_type = nlmsg_type;
    rt_req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;

    // set the routing message header
    rt_req.rt.rtm_family = AF_INET;
    rt_req.rt.rtm_table = table;
    // rt_req.rt.rtm_table = 0;

    rt_req.rt.rtm_protocol = RTPROT_STATIC;
    rt_req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
    rt_req.rt.rtm_type = RTN_UNICAST;
    // set the network prefix size
    rt_req.rt.rtm_dst_len = mask;

    //send msg
    struct msghdr msg;
    struct iovec iov;

    bzero(&rth.peer, sizeof(rth.peer));
    rth.peer.nl_family = AF_NETLINK;

    // initialize & create the struct msghdr supplied to the sendmsg() function
    bzero(&msg, sizeof(msg));
    msg.msg_name = (void *) &rth.peer;
    msg.msg_namelen = sizeof(rth.peer);

    // place the pointer & size of the RTNETLINK message in the struct msghdr
    iov.iov_base = (void *) &rt_req;
    iov.iov_len = rt_req.nl.nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // send the RTNETLINK message to kernel
    sendmsg(rth.fd, &msg, 0);

    close(rth.fd);
 
    return 0;
}


int add_sys_iproute(uint32_t ip_dst, uint32_t mask, uint32_t gateway, int dev, int table)
{
    return set_sys_iproute(ip_dst, mask, gateway, dev, table, 0);
}


int del_sys_iproute(uint32_t ip_dst, uint32_t mask, uint32_t gateway, int dev, int table)
{
    return set_sys_iproute(ip_dst, mask, gateway, dev, table, 1);
}

