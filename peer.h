#ifndef SECRET_H_
#define SECRET_H_

#include <stdio.h>
#include <sys/socket.h>

#include "data-struct/data-struct.h"
#include "aes.h"
#include "ip.h"


typedef struct
{
    uint32_t time_pre;
    uint32_t time_now;
    bit_array_t * ba_pre;
    bit_array_t * ba_now;
    uint64_t dup_cnt;     // if packet is duplicate, cnt++
    uint64_t delay_cnt;   // if packet is within MAX_DELAY_TIME, cnt++
    uint64_t replay_cnt;  // if packet is replay, cnt++
    uint64_t jump_cnt;    // if packet time is faster, cnt++
    uint32_t time_min;    // min timestamp recived during monitor
    uint32_t time_max;    // max timestamp recived during monitor
    uint64_t involve_cnt; // if dst_id let src_id replayed or jumped, dst_id cnt++; avoid bigger_id attack others
} flow_profile_t;


typedef struct
{
    bool dynamic;  // If the addr is written in secret.txt, it's static. Otherwise it's dynamic.
    uint last_time;  // // latest timestamp in this path
    struct sockaddr_in peeraddr;   // peer IP:Port
} path_profile_t;


/* read `man 7 ip` for peeraddr struct details:

struct sockaddr_in
{
    sa_family_t    sin_family; // address family: AF_INET
    in_port_t      sin_port;   // port in network byte order 
    struct in_addr sin_addr;   // internet address
};

// Internet address.
struct in_addr
{
    uint32_t       s_addr;     // address in network byte order 
};

*/


// data struct of peers in memory.
typedef struct
{
    uint16_t id;
    bool valid;
    bool discard;  // used when update profiles, identify whether a peer is deleted or not
    // bool restricted;  // if true, only recive data of this peer from the ip in secret.txt
    bool dup;   // when set, packet will be double sent.
    uint64_t recv_pkt_cnt;  // may be usefull for statistics?
    uint64_t send_pkt_cnt;  // may be usefull for statistics?
    uint32_t local_seq;
    tcp_info_t * tcp_info;  // not used yet
    flow_profile_t * flow_src;
    pthread_mutex_t * flow_lock;  // acquire the lock before set the flow_src
    byte psk[2*AES_TEXT_LEN];
    path_profile_t * path_array;  // an array of all peeraddr, path[0] is always used when forwarder_id == dst_id
    uint last_time; // latest timestamp in peer's header
    uint32_t vip;   // virtual client ip
} peer_profile_t;


peer_profile_t ** init_peer_table();
int update_peer_table(peer_profile_t ** peer_table, FILE * secrets_file);
int destroy_peer_table(peer_profile_t ** peer_table);
int reset_peer_table_flow(peer_profile_t ** peer_table);


#endif
