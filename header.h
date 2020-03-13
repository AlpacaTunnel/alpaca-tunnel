/*
 * This file defines the header in Header_format.png
*/


#ifndef HEADER_H_
#define HEADER_H_

// #include <stdint.h>
#include <arpa/inet.h>
#include "data-struct/data-struct.h"


// reserved ID: 0.0, 0.1, 255.255, any server/client cann't use.
#define HEAD_MAX_ID 65535
#define HEAD_ID_MAX_LEN 7  // max text len, 254.254

#define HEADER_LEN 16  // must be the same as AES_BLOCKLEN
#define HEAD_ICV_LEN 16
#define HEAD_MORE_FALSE 0
#define HEAD_MORE_TRUE  1
#define HEAD_TYPE_DATA  0
#define HEAD_TYPE_MSG   1
#define HEAD_TYPE_DUP   2
#define HEAD_TYPE_RETR  3
#define HEAD_FRAG_FALSE 0
#define HEAD_FRAG_TRUE  1

#define HEAD_TTL_MIN 0
#define HEAD_TTL_MAX 15
#define HEAD_MAX_PATH 15
#define MAX_FORWARDER_CNT 3  // pi_a is 2 bits, can hold only 4 forwarders, and pi==0 is reserved, so only 3 forwarders left

#define PATH_LIFE_TIME 10  // if abs(last_time - path_array[i].last_time) > PATH_LIFE_TIME, don't send to this peeraddr
#define PEER_LIFE_TIME 60  // if abs(now - path_array[i].last_time_local) > PEER_LIFE_TIME, don't send any pkt to peer

#define HEADER_MAGIC 1990

// tunnel MTU must not be greater than 1440
#define TUN_MTU_MAX 1440
#define TUN_MTU_MIN 68

// the ID is 0.0 to 255.255, so the network must be 16 bits long. x.y.a.b/16
#define TUN_NETMASK 0xFFFF0000
#define TUN_MASK_LEN 16



/*
  type: 0, L3 package
  type: 1, message
*/

struct type_len_m_s
{
    uint8_t     more  : 1;     // more heaer after
    uint16_t    len   : 11;
    uint8_t     type  : 4;
} __attribute__((packed));

union type_len_m_u
{
    struct type_len_m_s  bit;
    uint16_t             u16;
};

/*
struct uint4_t
{
    uint8_t value : 4;
} __attribute__((packed));

struct pi_s
{
    uint8_t b : 2;
    uint8_t a : 2;
} __attribute__((packed));

union pi_u
{
    struct pi_s     bit;
    struct uint4_t  u4;
};
*/

struct ttl_pi_sd_s
{
    uint8_t     reserved   : 6;
    bool        di         : 1;    // dest inside flag
    bool        si         : 1;    // source inside flag
    uint8_t     pi_b       : 2;    // path index set by forwarder
    uint8_t     pi_a       : 2;    // path index set by sender(origin)
    uint8_t     ttl        : 4;
} __attribute__((packed));

union ttl_pi_sd_u
{
    struct ttl_pi_sd_s  bit;
    uint16_t            u16;
};


struct time_magic_s
{
    uint16_t magic  : 12;   // magic number, if not match, group may be wrong
    uint32_t time   : 20;
} __attribute__((packed));

union time_magic_u
{
    struct time_magic_s  bit;
    uint32_t             u32;
};


struct seq_rand_s
{
    uint16_t rand  : 12;
    uint32_t seq   : 20;
} __attribute__((packed));

union seq_rand_u
{
    struct seq_rand_s  bit;
    uint32_t           u32;
};


/*
  all data in header are stored in network bit/byte order.
*/

struct tunnel_header_s
{
    union type_len_m_u   type_len_m;
    union ttl_pi_sd_u    ttl_pi_sd;
    uint16_t             src_id;
    uint16_t             dst_id;
    union time_magic_u   time_magic;
    union seq_rand_u     seq_rand;
} __attribute__((packed));

typedef struct tunnel_header_s tunnel_header_t;

// convert byte order from host to network
void header_hton(tunnel_header_t * header);

// convert byte order from network to host
void header_ntoh(tunnel_header_t * header);


#endif
