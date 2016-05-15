#ifndef IP_H_
#define IP_H_

#include "aes.h"

#include <stdint.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

//strlen of ipv4 address, including two quotation marks, must be larger than 16
#define IPV4_LEN 32
#define IPV4_HEAD_LEN 20
#define IPV4_OFFSET_SADDR 12
#define IPV4_OFFSET_DADDR 16
#define TCP_HEAD_LEN 40
#define UDP_HEAD_LEN 20
#define IPV4_OFFSET_CSUM 10
#define IPV4_MASK_FRAGOFF 0x1FFF  //in host byte order


struct ip_dot_decimal_t   //in network byte order
{
    byte a;
    byte b;
    byte c;
    byte d;
} __attribute__((packed));

struct tcp_info_t
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t init_seq;
    uint32_t seq;
    uint32_t ack_seq;
};

int16_t inet_ptons(char *a);   //convert 15.255 to 4095
int hostname_to_ip(char *hostname , char *ip);
uint16_t do_csum(uint16_t old_sum, uint32_t old_ip, uint32_t new_ip);
int ip_dnat(byte* ip_load, uint32_t new_ip);
int ip_snat(byte* ip_load, uint32_t new_ip);


#endif
