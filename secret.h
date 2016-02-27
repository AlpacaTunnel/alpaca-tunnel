#ifndef SECRET_H_
#define SECRET_H_

#include "aes.h"
#include "data_struct.h"

#include <stdio.h>

#ifndef BOOL_T_
#define BOOL_T_
    typedef enum { false, true } bool;
#endif

#define SEQ_LEVEL_1 1000000

//for flows that dst_id==0 or src_id==0, flow profiles are stored in peer_profile.
//for flows that dst_id!=0 and src_id!=0, flow profiles are stored in a common hash.
struct flow_profile_t
{
    uint32_t time_pre;
    uint32_t time_now;
    uint64_t dup_cnt;     //if packet is duplicate, cnt++
    uint64_t delay_cnt;   //if packet is within MAX_DELAY_TIME, cnt++
    uint64_t replay_cnt;  //if packet is replay, cnt++
    uint64_t jump_cnt;  //if packet time is faster, cnt++
    uint32_t time_min;
    uint32_t time_max;
    //uint32_t sys_time;
    struct bit_array_t * ba_pre;
    struct bit_array_t * ba_now;
};

//data struct of peers in memory.
struct peer_profile_t
{
    uint16_t id;
    bool valid;
    bool discard;
    bool restricted;
    bool dup;   //when set, packet will be double sent.
    uint16_t srtt;
    struct flow_profile_t * flow_src;  //for flow that dst==0, src->0
    uint64_t involve_cnt; //if dst_id let src_id replayed or jumped, dst_id cnt++; avoid bigger_id attach others
    //struct flow_profile_t * flow_dst;  //for flow that src==0, 0->dst
    byte psk[2*AES_TEXT_LEN];
    struct sockaddr_in *peeraddr;   //peer IP
    int port;   //peer port
    uint32_t vip;   //virtual client ip
    uint32_t rip;   //real client ip, will be NATed to vip
};

struct peer_profile_t** init_peer_table(FILE *secrets_file, int max_id);
int update_peer_table(struct peer_profile_t** peer_table, FILE *secrets_file, int max_id);
int destroy_peer_table(struct peer_profile_t **peer_table, int max_id);
struct peer_profile_t* add_peer();
int delete_peer(struct peer_profile_t* p);

int shrink_line(char *line);


#endif
