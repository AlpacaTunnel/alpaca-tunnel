/*
 * This file defines the header in Header_format.png
*/


#ifndef HEADER_H_
#define HEADER_H_

#define HEADER_LEN 16
#define ICV_LEN 16
#define HEAD_MORE_FALSE 0
#define HEAD_MORE_TRUE  1
#define HEAD_TYPE_DATA  0
#define HEAD_TYPE_MSG   1
#define HEAD_TYPE_DUP   2
#define HEAD_TYPE_RETR  3
#define HEAD_FRAG_FALSE 0
#define HEAD_FRAG_TRUE  1

#define TIMER_TYPE_MID 0
#define TIMER_TYPE_LAST 1

#define TTL_MAX 0xF
#define TTL_MIN 0

#define HEADER_MAGIC 1990

/*
  type: 0, L3 package
  type: 1, message
*/

struct type_len_m_s
{
    uint type  : 4;
    uint len   : 11;
    uint more  : 1;     // more heaer after
} __attribute__((packed));

union type_len_m_u
{
    struct type_len_m_s  bit;
    uint16_t             u16;
};

struct uint4_t
{
    uint value : 4;
} __attribute__((packed));

struct pi_s
{
    uint a : 2;
    uint b : 2;
} __attribute__((packed));

union pi_u
{
    struct pi_s  bit;
    struct uint4_t      u4;
};


struct ttl_pi_sd_s
{
    uint        ttl        : 4;
    uint        pi_a       : 2;    // path index
    uint        pi_b       : 2;    // path index
    bool        si         : 1;    // source inside flag
    bool        di         : 1;    // dest inside flag
    uint        reserved   : 6;
} __attribute__((packed));

union ttl_pi_sd_u
{
    struct ttl_pi_sd_s  bit;
    uint16_t            u16;
};


struct time_magic_s
{
    uint32_t time   : 20;
    uint     magic  : 12;   // magic number, if not match, group may be wrong
} __attribute__((packed));

union time_magic_u
{
    struct time_magic_s  bit;
    uint32_t             u32;
};


struct seq_rand_s
{
    uint32_t seq   : 20;
    uint     rand  : 12;
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


#endif
