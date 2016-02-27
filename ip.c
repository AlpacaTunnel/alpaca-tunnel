#include "ip.h"
#include "log.h"

#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


static uint16_t global_ipv4_mask_fragoff;

int16_t inet_ptons(char *a)
{
    if(a == NULL)
        return 0;
    uint8_t n1, n2;
    char *c = strdup(a);
    char delim[] = ".";
    char *a1 = strtok(c, delim);
    char *a2 = strtok(NULL, delim);
    if(a2 == NULL)
        return 0;

    int i;
    for(i=0; i<strlen(a1); i++)
        if(isdigit(a1[i]))
            continue;
        else
            return 0;
    for(i=0; i<strlen(a2); i++)
        if(isdigit(a2[i]))
            continue;
        else
            return 0;

    n1 = atoi(a1);
    n2 = atoi(a2);

    return ( n1 * 256 + n2 );
}

int hostname_to_ip(char *hostname , char *ip)
{
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
 
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;
 
    int rv = getaddrinfo(hostname, "http", &hints, &servinfo);
    if(rv != 0) 
    {
        printlog(errno, "getaddrinfo: %s: %s\n", hostname, gai_strerror(rv));
        return -1;
    }
 
    // loop through all the results and connect to the first we can
    for(p=servinfo; p!=NULL; p=p->ai_next) 
    {
        h = (struct sockaddr_in *)p->ai_addr;
        strcpy(ip, inet_ntoa(h->sin_addr));
    }

    freeaddrinfo(servinfo); // all done with this structure
    return 0;
}

uint16_t do_csum(uint16_t old_sum, uint32_t old_ip, uint32_t new_ip)
{
    if(0 == old_sum)    //only in one case: UDP checksum not calculated; otherwise, checksum cann't be 0.
        return 0;

    old_ip = ~old_ip;
    old_ip = (old_ip >> 16) + (old_ip & 0x0000FFFF);
    old_ip = (old_ip >> 16) + (old_ip & 0x0000FFFF);

    new_ip = ~new_ip;
    new_ip = (new_ip >> 16) + (new_ip & 0x0000FFFF);
    new_ip = (new_ip >> 16) + (new_ip & 0x0000FFFF);

    uint32_t new_sum = 0x00010000 | (old_sum - 0x00000001);   //move one bit to left. old_sum must be bigger than 0.
    new_sum = new_sum - old_ip + new_ip;
    new_sum = (new_sum >> 16) + (new_sum & 0x0000FFFF);
    new_sum = (new_sum >> 16) + (new_sum & 0x0000FFFF);
    return new_sum;
}

int ip_dnat(byte* ip_load, uint32_t new_ip)
{
    uint16_t csum = 0;
    struct iphdr ip_h;
    memcpy(&ip_h, ip_load, IPV4_HEAD_LEN);
    if(ip_h.daddr == new_ip)
        return 0;
    memcpy(&ip_load[IPV4_OFFSET_DADDR], &new_ip, 4);
    csum = do_csum(ip_h.check, ip_h.daddr, new_ip);
    memcpy(&ip_load[IPV4_OFFSET_CSUM], &csum, 2);     //recalculated ip checksum
    //if packet is fragmented, can only recaculate the first fragment.
    //Because the following packets don't have a layer 4 header!
    global_ipv4_mask_fragoff = htons(IPV4_MASK_FRAGOFF);
    if(6 == ip_h.protocol && (global_ipv4_mask_fragoff & ip_h.frag_off) == 0 )    //tcp
    {
        int csum_off = 4*ip_h.ihl + 16;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.daddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated tcp checksum
    }
    else if(17 == ip_h.protocol && (global_ipv4_mask_fragoff & ip_h.frag_off) == 0 )  //udp
    {
        int csum_off = 4*ip_h.ihl + 6;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.daddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated udp checksum
    }
    return 0;
}

int ip_snat(byte* ip_load, uint32_t new_ip)
{
    uint16_t csum = 0;
    struct iphdr ip_h;
    memcpy(&ip_h, ip_load, IPV4_HEAD_LEN);
    if(ip_h.saddr == new_ip)
        return 0;
    memcpy(&ip_load[IPV4_OFFSET_SADDR], &new_ip, 4);
    csum = do_csum(ip_h.check, ip_h.saddr, new_ip);
    memcpy(&ip_load[IPV4_OFFSET_CSUM], &csum, 2);     //recalculated ip checksum
    //if packet is fragmented, can only recaculate the first fragment.
    //Because the following packets don't have a layer 4 header!
    global_ipv4_mask_fragoff = htons(IPV4_MASK_FRAGOFF);
    if(6 == ip_h.protocol && (global_ipv4_mask_fragoff & ip_h.frag_off) == 0 )    //tcp
    {
        int csum_off = 4*ip_h.ihl + 16;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.saddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated tcp checksum
    }
    else if(17 == ip_h.protocol && (global_ipv4_mask_fragoff & ip_h.frag_off) == 0 )  //udp
    {
        int csum_off = 4*ip_h.ihl + 6;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.saddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated udp checksum
    }
    return 0;
}
