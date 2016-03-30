#ifndef HEADER_H_
#define HEADER_H_

//this file define the header in Header_format.png

#define HEADER_LEN 16
#define ICV_LEN 16
#define HEAD_MORE_FALSE 0
#define HEAD_MORE_TRUE  1
#define HEAD_TYPE_DATA  0
#define HEAD_TYPE_MSG   1
#define HEAD_FRAG_FALSE 0
#define HEAD_FRAG_TRUE  1

#define TIMER_TYPE_MID 0
#define TIMER_TYPE_LAST 1

#define TTL_MAX 0xF
#define TTL_MIN 0

/*
  type: 0, data
  type: 1, ack_msg
*/

struct m_type_len_t
{
    uint m:1;
    uint type:4;
    uint len:11;
} __attribute__((packed));

typedef union
{
    struct m_type_len_t bit;
    uint16_t u16;
} m_type_len_u;

struct ttl_flag_random_t
{
    uint ttl:4;
    bool src_inside:1;
    bool dst_inside:1;
    uint random:10;     //random is not random, it's better be 0, to verify group.
} __attribute__((packed));

typedef union
{
    struct ttl_flag_random_t bit;
    uint16_t u16;
} ttl_flag_random_u;

struct seq_frag_off_t
{
    uint32_t seq:24;
    uint frag:1;
    uint off:7;
} __attribute__((packed));

typedef union
{
    struct seq_frag_off_t bit;
    uint32_t u32;
} seq_frag_off_u;

/*
  all data in header are stored in network bit/byte order.
*/

struct tunnel_header_t
{
    m_type_len_u m_type_len;
    ttl_flag_random_u ttl_flag_random;
    uint16_t src_id;
    uint16_t dst_id;
    uint32_t time;
    seq_frag_off_u seq_frag_off;
} __attribute__((packed));


/*
  ack_type: 0, middle packet lost
  ack_type: 1, last packet recived
*/
struct ack_msg_t
{
    uint16_t src_id;
    uint16_t dst_id;
    uint32_t ack_type;
    uint32_t timestamp;
    uint32_t seq;
} __attribute__((packed));

#endif
