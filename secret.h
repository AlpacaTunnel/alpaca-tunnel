#ifndef SECRET_H_
#define SECRET_H_

#include <stdio.h>

#include "aes.h"
#include "ip.h"
#include "bool.h"
#include "data_struct.h"

#define SEQ_LEVEL_1 16000   //enough for 100Mbps TCP
#define TCP_SESSION_CNT 100
#define TIMER_CNT 20  //for every peer, only open CNT FD
#define PATH_LIFE 10  // if abs(last_time - path_array[i].last_time) > PATH_LIFE, don't send to this peeraddr
#define MAX_PATH 15

typedef struct
{
    uint32_t time_pre;
    uint32_t time_now;
    uint64_t dup_cnt;     //if packet is duplicate, cnt++
    uint64_t delay_cnt;   //if packet is within MAX_DELAY_TIME, cnt++
    uint64_t replay_cnt;  //if packet is replay, cnt++
    uint64_t jump_cnt;  //if packet time is faster, cnt++
    uint32_t time_min;  //min timestamp recived during monitor
    uint32_t time_max;  //max timestamp recived during monitor
    //uint32_t sys_time;
    bit_array_t * ba_pre;
    bit_array_t * ba_now;
} flow_profile_t;

typedef struct
{
    uint last_time;
    struct sockaddr_in peeraddr;   //peer IP
} addr_profile_t;

//data struct of peers in memory.
typedef struct
{
    uint16_t id;
    bool valid;
    bool discard;  //used when update profiles, identify whether a peer is deleted or not
    bool restricted;  // if true, only recive data of this peer from the ip in secret file
    bool dup;   //when set, packet will be double sent.
    uint16_t srtt;
    uint64_t total_pkt_cnt;
    uint32_t local_seq;
    uint32_t * pkt_index_array_pre;  //store the indexes of sent packets in global buf
    uint32_t * pkt_index_array_now;
    tcp_info_t * tcp_info;
    int tcp_cnt;
    flow_profile_t * flow_src;
    uint64_t involve_cnt; //if dst_id let src_id replayed or jumped, dst_id cnt++; avoid bigger_id attack others
    byte psk[2*AES_TEXT_LEN];
    addr_profile_t * path_array;  // an array of all peeraddr
    uint last_time; // latest timestamp in peer's header
    int port;   //peer port
    uint32_t vip;   //virtual client ip
    uint32_t rip;   //real client ip, will be NATed to vip
} peer_profile_t;

peer_profile_t ** init_peer_table(FILE * secrets_file, int max_id);
int update_peer_table(peer_profile_t ** peer_table, FILE * secrets_file, int max_id);
int destroy_peer_table(peer_profile_t ** peer_table, int max_id);
peer_profile_t * add_peer();
int delete_peer(peer_profile_t * p);


#endif
