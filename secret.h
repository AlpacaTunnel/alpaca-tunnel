#ifndef SECRET_H_
#define SECRET_H_

#include "aes.h"
#include "data_struct.h"

#include <stdio.h>

#ifndef BOOL_T_
#define BOOL_T_
    typedef enum { false, true } bool;
#endif

#define SEQ_LEVEL_1 16000   //enough for 100Mbps TCP
#define TCP_SESSION_CNT 100
#define TIMER_CNT 20  //for every peer, only open CNT FD


struct flow_profile_t
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
    struct bit_array_t * ba_pre;
    struct bit_array_t * ba_now;
};

//ack info for every pkt
struct ack_info_t
{
    uint8_t type;  //mid lost or last recived
    uint8_t cnt;  //ack msg send cnt
    uint16_t src_id;
    uint16_t dst_id;
    uint32_t timestamp;
    uint32_t seq;
    int fd;
};

struct timer_info_t
{
    int fd_max_cnt; //max number of allowed timefd to create, avoid too many timerfd open, and also avoid sending too many msg when network is congested.  
    uint32_t time_pre;
    uint32_t time_now;
    uint32_t max_ack_pre;
    uint32_t max_ack_now;
    uint32_t ack_array_size;   //size of the following array, should eq to max pkt seq(SEQ_LEVEL_1)
    struct ack_info_t * ack_array_pre;  //array that stores all timerfd of pre second, for each pkt, there is an ack_info_t
    struct ack_info_t * ack_array_now;  //array that stores all timerfd of the latest second
};

//data struct of peers in memory.
struct peer_profile_t
{
    uint16_t id;
    bool valid;
    bool discard;  //used when update profiles, identify whether a peer is deleted or not
    bool restricted;
    bool dup;   //when set, packet will be double sent.
    uint16_t srtt;
    uint64_t total_pkt_cnt;
    uint32_t local_seq;
    uint32_t * pkt_index_array_pre;  //store the indexes of sent packets in global buf
    uint32_t * pkt_index_array_now;
    struct timer_info_t * timer_info;
    struct tcp_info_t * tcp_info;
    int tcp_cnt;
    struct flow_profile_t * flow_src;
    uint64_t involve_cnt; //if dst_id let src_id replayed or jumped, dst_id cnt++; avoid bigger_id attack others
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
int close_all_timerfd(struct ack_info_t timerfd[], int num);

int shrink_line(char *line);


#endif
