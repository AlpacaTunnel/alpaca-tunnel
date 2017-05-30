#ifndef IP_H_
#define IP_H_

#include <stdint.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "aes.h"

#define IPV4_LEN 32  //strlen of ipv4 address, including two quotation marks, must be larger than 16, "255.255.255.255"
#define IP_LEN 64  // enouth space for IPv4 and IPv6, "ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:192.168.158.190"
#define IPV4_HEAD_LEN 20
#define IPV4_OFFSET_SADDR 12
#define IPV4_OFFSET_DADDR 16
#define TCP_HEAD_LEN 40
#define UDP_HEAD_LEN 20
#define IPV4_OFFSET_CSUM 10
#define IPV4_MASK_FRAGOFF 0x1FFF  //in host byte order

#define TUN_NETMASK 0xFFFF0000
#define TUN_MASK_LEN 16
#define ETH_MTU 1500

#define TCPMSS_MIN 60
#define TCPMSS_MAX 1400
#define TCPMSS 1300


struct ip_dot_decimal_s   //in network byte order
{
    byte a;
    byte b;
    byte c;
    byte d;
} __attribute__((packed));
typedef struct ip_dot_decimal_s ip_dot_decimal_t;

typedef struct
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t init_seq;
    uint32_t seq;
    uint32_t ack_seq;
} tcp_info_t;

uint16_t inet_ptons(const char *a);   //convert 15.255 to 4095
int hostname_to_ip(const char *hostname , char *ip);
uint16_t do_csum(uint16_t old_sum, uint32_t old_ip, uint32_t new_ip);
int ip_dnat(byte* ip_load, uint32_t new_ip);
int ip_snat(byte* ip_load, uint32_t new_ip);


#endif
