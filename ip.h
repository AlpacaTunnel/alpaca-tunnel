#ifndef IP_H_
#define IP_H_

#include <stdint.h>

#include "data-struct/data-struct.h"


#define IP_LEN 64  // enouth space for IPv4 and IPv6, "ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:192.168.158.190"


struct ip_dot_decimal_s   // in network byte order
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
