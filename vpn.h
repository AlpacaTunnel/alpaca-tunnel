#ifndef VPN_H_
#define VPN_H_

#include <stdint.h>
#include <pthread.h>

#include "route.h"
#include "config.h"
#include "policy.h"


#define VPN_MODE_CLIENT 0
#define VPN_MODE_SERVER 1


struct packet_profile
{
    int                 type;
    uint16_t            src_id;
    uint16_t            dst_id;
    bool                is_forward;  // for packets that received and then forward out
    uint32_t            timestamp;
    uint32_t            seq;
    int                 send_fd;
    int                 write_fd;
    int                 timer_fd;
    int                 len;
    bool                dup;
    struct sockaddr_in  inner_dst_addr;  // used to check route table loop
    struct sockaddr_in  inner_src_addr;  // used to check route table loop
    struct sockaddr_in  outer_dst_addr;  // only used when dup send pkt
    struct sockaddr_in  outer_src_addr;  // if forward == true, this is the recv peeraddr, used to check split horizon
    byte *              buf_packet;
};

typedef struct packet_profile packet_profile_t;


struct vpn_context
{
    int                     mode;
    bool                    running;
    bool                    allow_p2p;
    int                     tunfd;
    int                     sockfd;
    if_info_t               tunif;
    if_info_t *             if_list;
    uint16_t                self_id;
    pthread_mutex_t *       time_seq_lock;
    peer_profile_t **       peer_table;
    uint32_t                local_time;
    queue_t *               send_q;
    queue_t *               write_q;
    delay_queue_t *         delay_q;
    byte *                  buf_group_psk;
    int                     forwarder_cnt;
    uint16_t *              forwarders;
    forwarding_table_t *    forwarding_table;
    char                    exe_path[PATH_LEN];
    char                    json_path[PATH_LEN];
    char                    secrets_path[PATH_LEN];
    char                    secret_dir[PATH_LEN];
    char                    config_dir[PATH_LEN];
};

typedef struct vpn_context vpn_context_t;


packet_profile_t * new_pkt();
void delete_pkt(packet_profile_t * pkt);

vpn_context_t * vpn_context_init();
int vpn_context_destory(vpn_context_t * vpn_ctx);

void* pkt_delay_dup(void *arg);
void* server_read(void *arg);
void* server_recv(void *arg);
void* server_write(void *arg);
void* server_send(void *arg);


#endif
