#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


#include "log.h"
#include "vpn.h"


// #define ACK_WRITE_DELAY 100  // ms
#define UDP_DUP_DELAY   100  // ms

#define ETH_MTU 1500

// length of aes key must be 128, 192 or 256
#define AES_KEY_LEN 128

#define FORWARDING_TABLE_SIZE 10240
#define SEQ_LEVEL_1 16000   // enough for 100Mbps TCP


enum {pkt_none, pkt_write, pkt_send} packet_type = pkt_none;


void thread_clean_callback(void *arg)
{
    
    DEBUG("Entering thread_clean_callback, which should only happen when process exits.");
    DEBUG("This message means there is a thread exited during process runing.");
    return;
}


packet_profile_t * new_pkt()
{
    packet_profile_t * pkt = (packet_profile_t *)malloc(sizeof(packet_profile_t));
    if(pkt == NULL)
    {
        perror("new_pkt: malloc");
        return NULL;
    }

    bzero(pkt, sizeof(packet_profile_t));

    pkt->buf_packet = (byte *)malloc(ETH_MTU);
    if(pkt->buf_packet == NULL)
    {
        perror("new_pkt: malloc");
        free(pkt);
        return NULL;
    }

    return pkt;
}

void delete_pkt(packet_profile_t * pkt)
{
    if(pkt == NULL)
        return;

    if(pkt->buf_packet)
        free(pkt->buf_packet);

    free(pkt);
}


vpn_context_t * vpn_context_init()
{
    vpn_context_t * vpn_ctx = (vpn_context_t *)malloc(sizeof(vpn_context_t));
    if(vpn_ctx == NULL)
    {
        ERROR(errno, "vpn_ctx_init: malloc");
        return NULL;
    }
    bzero(vpn_ctx, sizeof(vpn_context_t));

    vpn_ctx->forwarding_table = forwarding_table_init(FORWARDING_TABLE_SIZE);
    if(vpn_ctx->forwarding_table == NULL)
    {
        ERROR(0, "forwarding_table_init");
        return NULL;
    }
    vpn_ctx->time_seq_lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if(pthread_mutex_init(vpn_ctx->time_seq_lock, NULL) != 0)
    {
        ERROR(errno, "pthread_mutex_init");
        return NULL;
    }

    vpn_ctx->send_q = queue_init(QUEUE_TYPE_FIFO);
    vpn_ctx->write_q = queue_init(QUEUE_TYPE_FIFO);
    vpn_ctx->delay_q = delay_queue_init();

    vpn_ctx->buf_group_psk = (byte *)malloc(2 * AES_KEY_LEN);
    bzero(vpn_ctx->buf_group_psk, 2 * AES_KEY_LEN);
    memcpy(vpn_ctx->buf_group_psk, "FUCKnimadeGFW!", 2 * AES_KEY_LEN);

    vpn_ctx->forwarders = (uint16_t *)malloc((MAX_FORWARDER_CNT+1) * sizeof(uint16_t));

    return vpn_ctx;
}


int vpn_context_destory(vpn_context_t * vpn_ctx)
{
    forwarding_table_destroy(vpn_ctx->forwarding_table);
    
    pthread_mutex_destroy(vpn_ctx->time_seq_lock);

    queue_destroy(vpn_ctx->send_q, NULL);
    queue_destroy(vpn_ctx->write_q, NULL);
    delay_queue_destroy(vpn_ctx->delay_q, NULL);

    return 0;
}


/* get gw_id form route_table or system route table
 * return 0 if not found. actually, will never return 0.
*/
uint16_t get_dst_id(forwarding_table_t * forwarding_table, uint32_t ip_dst, uint32_t ip_src, if_info_t * if_list, uint32_t local_addr, uint local_mask)
{
    // ip_dst is in tunif's subnet
    if((ip_dst & local_mask) == (local_addr & local_mask))
        return (uint16_t)ntohl(ip_dst);

    uint16_t gw_id = forwarding_table_get(forwarding_table, ip_dst, ip_src);
    if(0 == gw_id)
    {
        uint32_t gw_ip = get_sys_iproute(ip_dst, ip_src, if_list);

        // gw_ip is in tunif's subnet.
        // it's always true, since pkt is sent to the tunnel, it's gateway must be in the subnet.
        if((gw_ip & local_mask) == (local_addr & local_mask))
        {
            gw_id = (uint16_t)ntohl(gw_ip);
            forwarding_table_put(forwarding_table, ip_dst, ip_src, gw_id);
        }
    }
    return gw_id;
}


void* pkt_delay_dup(void *arg)
{
    vpn_context_t * vpn_ctx = (vpn_context_t *)arg;
    struct sockaddr_in peeraddr;
    byte * buf_write = (byte *)malloc(TUN_MTU_MAX);
    byte * buf_send = (byte *)malloc(ETH_MTU);
    for(int i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    int sockfd = 0;
    int tunfd = 0;
    int len = 0;
    uint16_t dst_id = 0;

    while(vpn_ctx->running)
    {
        packet_profile_t * pkt;
        pkt = delay_queue_get(vpn_ctx->delay_q);
        if(pkt == NULL)
            continue;

        if(pkt->type == pkt_write)
        {
            // DEBUG("write delayed ack");
            tunfd = pkt->write_fd;
            len = pkt->len;
            dst_id = pkt->dst_id;
            memcpy(buf_write, pkt->buf_packet, len);
            
            if(write(tunfd, buf_write, len) < 0)
                ERROR(errno, "tunif %s write error of dst_id %d.%d", vpn_ctx->tunif.name, dst_id/256, dst_id%256);
        }

        if(pkt->type == pkt_send)
        {
            // DEBUG("send delayed pkt");
            sockfd = pkt->send_fd;
            len = pkt->len;

            dst_id = pkt->dst_id;
            peeraddr = pkt->outer_dst_addr;
            memcpy(buf_send, pkt->buf_packet, len);

            int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
            if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr)) < 0 )
                ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", vpn_ctx->tunif.name, dst_id/256, dst_id%256);
        }

        delete_pkt(pkt);
    }

    free(buf_write);
    free(buf_send);
    return NULL;
}


void* server_read(void *arg)
{
    pthread_cleanup_push(thread_clean_callback, NULL);
    tunnel_header_t header_send;
    vpn_context_t * vpn_ctx = (vpn_context_t *)arg;
    peer_profile_t ** peer_table = vpn_ctx->peer_table;
    uint16_t src_id, dst_id, bigger_id;
    struct iphdr ip_h;
    uint16_t len_load, nr_aes_block;
    byte * buf_load = (byte *)malloc(TUN_MTU_MAX);
    byte * buf_send = (byte *)malloc(ETH_MTU);
    byte * buf_psk;
    bzero(buf_load, TUN_MTU_MAX);

    while(vpn_ctx->running)
    {
        len_load = read(vpn_ctx->tunfd, buf_load, TUN_MTU_MAX);
        if(len_load < 0 )
        {
            ERROR(errno, "read tunif %s", vpn_ctx->tunif.name);
            continue;
        }

        memcpy(&ip_h, buf_load, sizeof(struct iphdr));

        if(ip_h.version != 4)
        {
            DEBUG("read not supported IP version: %d", ip_h.version);
            continue;
        }

        dst_id = get_dst_id(vpn_ctx->forwarding_table, ip_h.daddr, ip_h.saddr, vpn_ctx->if_list, vpn_ctx->tunif.addr, vpn_ctx->tunif.mask);
        src_id = vpn_ctx->self_id;
        // INFO("==========>>>dst_id: %d, src_id: %d", dst_id, src_id);

        if(NULL == peer_table[dst_id] || 0 == dst_id || vpn_ctx->self_id == dst_id)
        {
            DEBUG("tunif %s read packet to peer %d.%d: invalid peer!", vpn_ctx->tunif.name, dst_id/256, dst_id%256);
            continue;
        }

        //dst addr is in the same network with vpn_ctx->tunif
        bool dst_inside = ((ip_h.daddr & vpn_ctx->tunif.mask) == (vpn_ctx->tunif.addr & vpn_ctx->tunif.mask));
        //src addr is in the same network with vpn_ctx->tunif
        bool src_inside = ((ip_h.saddr & vpn_ctx->tunif.mask) == (vpn_ctx->tunif.addr & vpn_ctx->tunif.mask));
        //src addr is local tunif
        bool src_local = (ip_h.saddr == vpn_ctx->tunif.addr);
        
        // not supported now: read packet in tunif's subnet but ID mismatch
        if(src_inside != src_local)
        {
            DEBUG("tunif %s read packet from other peer, ignore it!", vpn_ctx->tunif.name);
            continue;
        }
        else if(!dst_inside && !src_inside) // not supported now: outside IP to outside IP
        {
            DEBUG("tunif %s read packet from outside net to outside net, ignore it!", vpn_ctx->tunif.name);
            continue;
        }  

        if(src_inside)
        {
            header_send.ttl_pi_sd.bit.si = true;
            ip_snat(buf_load, peer_table[src_id]->vip);
        }
        else
        {
            header_send.ttl_pi_sd.bit.si = false;
        }

        if(dst_inside)
        {
            header_send.ttl_pi_sd.bit.di = true;
            ip_dnat(buf_load, peer_table[dst_id]->vip);
        }
        else
        {
            header_send.ttl_pi_sd.bit.di = false;
        }

        bigger_id = dst_id > src_id ? dst_id : src_id;
        if(NULL == peer_table[bigger_id])
        {
            DEBUG("tunif %s read packet of invalid peer: %d.%d!", vpn_ctx->tunif.name, bigger_id/256, bigger_id%256);
            continue;
        }

        buf_psk = peer_table[bigger_id]->psk;

        header_send.dst_id = htons(dst_id);
        header_send.src_id = htons(src_id);

        header_send.type_len_m.bit.type = HEAD_TYPE_DATA;
        header_send.type_len_m.bit.len = len_load;
        header_send.type_len_m.bit.more = HEAD_MORE_FALSE;
        header_send.type_len_m.u16 = htons(header_send.type_len_m.u16);

        header_send.ttl_pi_sd.bit.pi_a = 0;
        header_send.ttl_pi_sd.bit.pi_b = 0;
        header_send.ttl_pi_sd.bit.ttl = HEAD_TTL_MAX;
        header_send.ttl_pi_sd.u16 = htons(header_send.ttl_pi_sd.u16);

        uint32_t now = time(NULL);
        header_send.time_magic.bit.time = now;
        header_send.time_magic.bit.magic = HEADER_MAGIC;
        header_send.time_magic.u32 = htonl(header_send.time_magic.u32);

        if(pthread_mutex_lock(vpn_ctx->time_seq_lock) != 0)
        {
            ERROR(errno, "pthread_mutex_lock");
            continue;
        }

        if(vpn_ctx->local_time == now)
            peer_table[dst_id]->local_seq++;
        else
        {
            peer_table[dst_id]->local_seq = 0;
            vpn_ctx->local_time = now;
        }
        header_send.seq_rand.bit.seq = peer_table[dst_id]->local_seq;

        if(pthread_mutex_unlock(vpn_ctx->time_seq_lock) != 0)
        {
            ERROR(errno, "pthread_mutex_unlock");
            continue;
        }

        if(peer_table[dst_id]->local_seq > SEQ_LEVEL_1)
        {
            DEBUG("local_seq beyond limit, drop this packet to dst_id: %d.%d.", dst_id/256, dst_id%256);
            continue;
        }

        header_send.seq_rand.u32 = htonl(header_send.seq_rand.u32);

        memcpy(buf_send, &header_send, HEADER_LEN);

        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
        int i;
        for(i=0; i<nr_aes_block; i++)
            encrypt(buf_send+HEADER_LEN+HEAD_ICV_LEN+i*AES_TEXT_LEN, buf_load+i*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);

        bool dup = should_pkt_dup(buf_load);
        int len = HEADER_LEN + HEAD_ICV_LEN + nr_aes_block*AES_TEXT_LEN;

        packet_profile_t * pkt = new_pkt();

        pkt->src_id = vpn_ctx->self_id;
        pkt->dst_id = dst_id;
        pkt->is_forward = false;
        pkt->inner_dst_addr.sin_addr.s_addr = ip_h.daddr;
        pkt->inner_src_addr.sin_addr.s_addr = ip_h.saddr;
        pkt->send_fd = vpn_ctx->sockfd;
        pkt->dup = dup;
        pkt->len = len;
        pkt->timestamp = now;
        pkt->seq = peer_table[dst_id]->local_seq;
        memcpy(pkt->buf_packet, buf_send, len);

        queue_put(vpn_ctx->send_q, pkt, 0);

        continue;
    }

    free(buf_load);
    free(buf_send);
    pthread_cleanup_pop(0);
    return NULL;
}


void* server_send(void *arg)
{
    pthread_cleanup_push(thread_clean_callback, NULL);
    vpn_context_t * vpn_ctx = (vpn_context_t *)arg;
    peer_profile_t ** peer_table = vpn_ctx->peer_table;

    struct sockaddr_in peeraddr;
    byte * buf_send = (byte *)malloc(ETH_MTU);
    byte buf_header[HEADER_LEN];
    tunnel_header_t header_send;
    for(int i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    byte * buf_psk;
    int sockfd = 0;
    int len = 0;
    uint16_t dst_id = 0, src_id = 0, bigger_id = 0;

    while(vpn_ctx->running)
    {
        packet_profile_t * pkt;
        queue_get(vpn_ctx->send_q, (void **)&pkt, NULL);
        
        sockfd = pkt->send_fd;
        len = pkt->len;
        bool dup = pkt->dup;
        bool is_forward = pkt->is_forward;
        // in not set explicitly, the values of outer_src_addr/inner_dst_addr/inner_src_addr is 0
        struct sockaddr_in outer_src_addr = pkt->outer_src_addr;
        struct sockaddr_in inner_dst_addr = pkt->inner_dst_addr;
        struct sockaddr_in inner_src_addr = pkt->inner_src_addr;
        dst_id = pkt->dst_id;
        src_id = pkt->src_id;
        memcpy(buf_send, pkt->buf_packet, len);  // header and ICV are not encryped
        memcpy(&header_send, buf_send, HEADER_LEN);

        delete_pkt(pkt);

        header_send.seq_rand.u32 = ntohl(header_send.seq_rand.u32);
        header_send.seq_rand.bit.rand = random();
        header_send.seq_rand.u32 = htonl(header_send.seq_rand.u32);
        bigger_id = dst_id > src_id ? dst_id : src_id;
        buf_psk = peer_table[bigger_id]->psk;

        // from server to clients. if first_path is dynamic, dst_id is client
        if(dst_id > src_id && peer_table[dst_id]->path_array[0].dynamic &&
                abs(time(NULL) - peer_table[dst_id]->last_time_local) > PEER_LIFE_TIME)
        {
            DEBUG("did NOT receive any packets from %d.%d for %d seconds, drop its packets", dst_id/256, dst_id%256, PEER_LIFE_TIME);
            continue;
        }

        bool is_pkt_loop = false;
        if(vpn_ctx->forwarder_cnt > 0 && dst_id < src_id)  // send to forwarders
        {
            // check loop: consider 2 forwarders, forwarded pkt sent into tunnel again
            for(int i = 0; i < vpn_ctx->forwarder_cnt; i++)
            {
                int forwarder_id = vpn_ctx->forwarders[i];
                peeraddr = peer_table[forwarder_id]->path_array[0].peeraddr;
                if(peeraddr.sin_addr.s_addr == 0)
                    continue;

                if(peeraddr.sin_addr.s_addr == inner_dst_addr.sin_addr.s_addr || peeraddr.sin_addr.s_addr == inner_src_addr.sin_addr.s_addr)
                {
                    ERROR(0, "tunif %s read packet that caused routing table loop, check your route!", vpn_ctx->tunif.name);
                    is_pkt_loop = true;
                    break;
                }
            }

            if(is_pkt_loop)
                continue;

            for(int i = 0; i < vpn_ctx->forwarder_cnt; i++)
            {
                int forwarder_id = vpn_ctx->forwarders[i];
                if(forwarder_id == 0 || forwarder_id == 1 || forwarder_id == vpn_ctx->self_id || peer_table[forwarder_id] == NULL)
                {
                    DEBUG("forwarder not valid: %d.%d", forwarder_id/256, forwarder_id%256);
                    continue;
                }

                peeraddr = peer_table[forwarder_id]->path_array[0].peeraddr;  // only forward to first path (got from secret.txt)
                if(peeraddr.sin_addr.s_addr == 0)
                {
                    WARNING("forwarder address not avaliable: %d.%d", forwarder_id/256, forwarder_id%256);
                    continue;
                }

                // check for each forwarder, allow a client access two forwarders at the same time, also allow loop among 3 forwarders (until TTL expire)
                if(peeraddr.sin_addr.s_addr == outer_src_addr.sin_addr.s_addr)
                {
                    DEBUG("split horizon: tunif %s recv packet from %d.%d to %d.%d: next peer is %d.%d, dst addr equals src addr!", 
                        vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, dst_id/256, dst_id%256);
                    continue;
                }

                header_send.ttl_pi_sd.u16 = ntohs(header_send.ttl_pi_sd.u16);
                if(is_forward)  // pkt received from socket
                {
                    int j = header_send.ttl_pi_sd.bit.pi_b + i;
                    if(j > MAX_FORWARDER_CNT)
                        j = MAX_FORWARDER_CNT;
                    header_send.ttl_pi_sd.bit.pi_b = j;  // if forwarded more than once, cann't beyond MAX_FORWARDER_CNT
                }
                else  // pkt read from tunif
                {
                    if(forwarder_id == dst_id)
                    {
                        header_send.ttl_pi_sd.bit.pi_a = 0;  // path index 0 is reserved. when pi==0, it's always the src_id's addr, not forwarder's.
                        header_send.ttl_pi_sd.bit.pi_b = 0;
                    }
                    else
                    {
                        header_send.ttl_pi_sd.bit.pi_a = i + 1;
                        header_send.ttl_pi_sd.bit.pi_b = 0;
                    }
                }
                header_send.ttl_pi_sd.u16 = htons(header_send.ttl_pi_sd.u16);

                memcpy(buf_header, &header_send, HEADER_LEN);
                encrypt(buf_send, buf_header, vpn_ctx->buf_group_psk, AES_KEY_LEN);  // encrypt header with group PSK
                encrypt(buf_send+HEADER_LEN, buf_header, buf_psk, AES_KEY_LEN);  // encrypt header to generate icv

                int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
                if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr)) < 0 )
                    ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", vpn_ctx->tunif.name, dst_id/256, dst_id%256);
            }
        }
        else  // send directly to peer, don't change path index
        {
            memcpy(buf_header, &header_send, HEADER_LEN);
            encrypt(buf_send, buf_header, vpn_ctx->buf_group_psk, AES_KEY_LEN);  // encrypt header with group PSK
            encrypt(buf_send+HEADER_LEN, buf_header, buf_psk, AES_KEY_LEN);  // encrypt header to generate icv

            for(int pi = 0; pi <= HEAD_MAX_PATH; pi++)
            {
                peeraddr = peer_table[dst_id]->path_array[pi].peeraddr;
                if(peeraddr.sin_addr.s_addr == 0)
                    continue;

                if(peeraddr.sin_addr.s_addr == inner_dst_addr.sin_addr.s_addr || peeraddr.sin_addr.s_addr == inner_src_addr.sin_addr.s_addr)
                {
                    ERROR(0, "tunif %s read packet that caused routing table loop, check your route!", vpn_ctx->tunif.name);
                    is_pkt_loop = true;
                    break;
                }
            }

            if(is_pkt_loop)
                continue;

            for(int pi = 0; pi <= HEAD_MAX_PATH; pi++)
            {
                peeraddr = peer_table[dst_id]->path_array[pi].peeraddr;
                if(peeraddr.sin_addr.s_addr == 0)
                    continue;

                // at the very beginning, both last_time are 0
                uint path_last_time = peer_table[dst_id]->path_array[pi].last_time;
                uint peer_last_time = peer_table[dst_id]->last_time;
                if(abs(peer_last_time - path_last_time) > PATH_LIFE_TIME)
                {
                    if(peer_table[dst_id]->path_array[pi].dynamic)
                        peer_table[dst_id]->path_array[pi].peeraddr.sin_addr.s_addr = 0;
                    continue;
                }

                if(peeraddr.sin_addr.s_addr == outer_src_addr.sin_addr.s_addr)
                {
                    DEBUG("split horizon: tunif %s recv packet from %d.%d to %d.%d: next peer is %d.%d, dst addr equals src addr!", 
                        vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, dst_id/256, dst_id%256);
                    continue;
                }

                int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
                if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr)) < 0 )
                    ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", vpn_ctx->tunif.name, dst_id/256, dst_id%256);
            }
        }

        if(dup)  // add to pkt_delay_dup for delay
        {
            packet_profile_t * pkt = new_pkt();

            pkt->type = pkt_send;
            pkt->send_fd = sockfd;
            pkt->len = len;
            pkt->dst_id = dst_id;
            for(int pi = 0; pi <= HEAD_MAX_PATH; pi++)
            {
                if(peer_table[dst_id]->path_array[pi].peeraddr.sin_addr.s_addr != 0)
                {
                    pkt->outer_dst_addr = peer_table[dst_id]->path_array[pi].peeraddr;
                    memcpy(pkt->buf_packet, buf_send, len);
                    delay_queue_put(vpn_ctx->delay_q, pkt, UDP_DUP_DELAY);
                    break;  // only duplicate to first available path
                }
            }
        }

        continue;
    }

    free(buf_send);
    pthread_cleanup_pop(0);
    return NULL;
}


void* server_write(void *arg)
{
    vpn_context_t * vpn_ctx = (vpn_context_t *)arg;
    pthread_cleanup_push(thread_clean_callback, NULL);

    byte * buf_write = (byte *)malloc(TUN_MTU_MAX);
    int tunfd = 0;
    int len = 0;
    uint16_t dst_id = 0;

    while(vpn_ctx->running)
    {
        packet_profile_t * pkt;
        queue_get(vpn_ctx->write_q, (void **)&pkt, NULL);

        tunfd = pkt->write_fd;
        len = pkt->len;
        dst_id = pkt->dst_id;
        memcpy(buf_write, pkt->buf_packet, len);
        delete_pkt(pkt);

        if(write(tunfd, buf_write, len) < 0)
            ERROR(errno, "tunif %s write error of dst_id %d.%d", vpn_ctx->tunif.name, dst_id/256, dst_id%256);

        continue;
    }

    free(buf_write);
    pthread_cleanup_pop(0);
    return NULL;
}


void* server_recv(void *arg)
{
    pthread_cleanup_push(thread_clean_callback, NULL);
    tunnel_header_t header_recv, header_send;
    vpn_context_t * vpn_ctx = (vpn_context_t *)arg;
    peer_profile_t ** peer_table = vpn_ctx->peer_table;
    uint16_t dst_id = 0, src_id = 0, bigger_id = 0;
    uint ttl;
    struct sockaddr_in peeraddr;
    socklen_t peeraddr_len = sizeof(peeraddr);
    ip_dot_decimal_t ip_daddr, ip_saddr;
    uint16_t len_load, len_recv, nr_aes_block;
    byte * buf_psk;
    byte * buf_recv = (byte *)malloc(ETH_MTU);
    byte * buf_load = (byte *)malloc(TUN_MTU_MAX);
    byte * buf_send = (byte *)malloc(ETH_MTU);

    for(int i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    byte buf_header[HEADER_LEN];
    byte buf_icv[HEAD_ICV_LEN];

    while(vpn_ctx->running)
    {
        len_recv = recvfrom(vpn_ctx->sockfd, buf_recv, ETH_MTU, 0, (struct sockaddr *)&peeraddr, &peeraddr_len);
        if(len_recv < HEADER_LEN+HEAD_ICV_LEN)
        {
            ERROR(errno, "tunif %s recvfrom socket error", vpn_ctx->tunif.name);
            continue;
        }

        decrypt(buf_header, buf_recv, vpn_ctx->buf_group_psk, AES_KEY_LEN);  //decrypt header with group PSK
        memcpy(&header_recv, buf_header, HEADER_LEN);
        memcpy(&header_send, buf_header, HEADER_LEN);

        header_recv.time_magic.u32 = ntohl(header_recv.time_magic.u32);
        if(header_recv.time_magic.bit.magic != HEADER_MAGIC)
        {
            DEBUG("tunif %s received packet: group not match!", vpn_ctx->tunif.name);
            continue;
        }

        header_recv.ttl_pi_sd.u16 = ntohs(header_recv.ttl_pi_sd.u16);
        uint pi = (header_recv.ttl_pi_sd.bit.pi_a << 2) + header_recv.ttl_pi_sd.bit.pi_b;
        
        dst_id = ntohs(header_recv.dst_id);
        src_id = ntohs(header_recv.src_id);
        bigger_id = dst_id > src_id ? dst_id : src_id;

        if(peer_table[src_id] == NULL || peer_table[src_id]->valid == false)
        {
            DEBUG("tunif %s received packet from invalid src_id: %d.%d to %d.%d!", 
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }

        if(peer_table[dst_id] == NULL || peer_table[dst_id]->valid == false)
        {
            DEBUG("tunif %s received packet from invalid dst_id: %d.%d to %d.%d!", 
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }

        if(src_id == 0 || src_id == 1)
        {
            DEBUG("tunif %s received packet from reserved src_id: %d.%d to %d.%d!", 
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }

        if(src_id == vpn_ctx->self_id)
        {
            DEBUG("tunif %s received packet from self: %d.%d to %d.%d!", 
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }

        if(dst_id == 0 || dst_id == 1)
        {
            DEBUG("tunif %s received packet to reserved dst_id: %d.%d to %d.%d!", 
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }

        path_profile_t * first_path = &(peer_table[src_id]->path_array[0]);

        // check if the first path source addr match the IP:Port in secret.txt
        if(pi == 0 && first_path->dynamic == false && dst_id < src_id)
        {
            if(first_path->peeraddr.sin_addr.s_addr != peeraddr.sin_addr.s_addr || first_path->peeraddr.sin_port != peeraddr.sin_port)
            {
                DEBUG("tunif %s received packet from %d.%d to %d.%d: source IP:Port mismatch!",
                    vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
                continue;
            }
        }

        buf_psk = peer_table[bigger_id]->psk;

        encrypt(buf_icv, buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv
        if(strncmp((char*)buf_icv, (char*)(buf_recv+HEADER_LEN), HEAD_ICV_LEN) != 0)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: icv doesn't match!", 
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }

        header_recv.type_len_m.u16 = ntohs(header_recv.type_len_m.u16);

        int type = header_recv.type_len_m.bit.type;
        if(type != HEAD_TYPE_DATA)
        {
            INFO("only HEAD_TYPE_DATA supported!");
            continue;
        }

        header_recv.seq_rand.u32 = ntohl(header_recv.seq_rand.u32);
        uint32_t pkt_time = header_recv.time_magic.bit.time;
        uint32_t pkt_seq = header_recv.seq_rand.bit.seq;

        // got first path from the secret.txt, don't store the addr dynamically
        if(peer_table[src_id]->path_array[pi].dynamic)
            peer_table[src_id]->path_array[pi].peeraddr = peeraddr;
        peer_table[src_id]->path_array[pi].last_time = pkt_time;
        peer_table[src_id]->last_time = pkt_time;
        peer_table[src_id]->last_time_local = time(NULL);

        peer_table[src_id]->recv_pkt_cnt++;  // include duplicated packets


        flow_profile_t * fp_src = peer_table[src_id]->flow_src;
        flow_profile_t * fp_dst = peer_table[dst_id]->flow_src;

        // no need to add lock for dst_id
        if(pthread_mutex_lock(peer_table[src_id]->flow_lock) != 0)
        {
            ERROR(errno, "pthread_mutex_lock");
            continue;
        }

        int fs = flow_filter(pkt_time, pkt_seq, src_id, dst_id, fp_src, fp_dst);

        if(pthread_mutex_unlock(peer_table[src_id]->flow_lock) != 0)
        {
            ERROR(errno, "pthread_mutex_unlock");
            continue;
        }

        if(fs == POLICY_LIMIT_LOGPOINT_REPLAY)
            DEBUG("tunif %s received packet from %d.%d to %d.%d: replay limit exceeded!",
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
        if(fs == POLICY_LIMIT_EXCEEDED_INVOLVE_REPLAY)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: replay limit exceeded!",
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            DEBUG("tunif %s set peer %d.%d to invalid: involve limit exceeded!",
                vpn_ctx->tunif.name, dst_id/256, dst_id%256);
        }
        if(fs == POLICY_LIMIT_LOGPOINT_TIMEJUMP)
            DEBUG("tunif %s received packet from %d.%d to %d.%d: time jump limit exceeded!",
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
        if(fs == POLICY_LIMIT_EXCEEDED_INVOLVE_TIMEJUMP)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: time jump limit exceeded!",
                vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            DEBUG("tunif %s set peer %d.%d to invalid: involve limit exceeded!",
                vpn_ctx->tunif.name, dst_id/256, dst_id%256);
        }
        if(fs < 0)
            continue;


        if(vpn_ctx->self_id == dst_id) // write to local tunif
        {
            len_load = header_recv.type_len_m.bit.len;
            nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
            for(int i=0; i<nr_aes_block; i++)
                decrypt(buf_load+i*AES_TEXT_LEN, buf_recv+HEADER_LEN+HEAD_ICV_LEN+i*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);

            uint32_t daddr, saddr; // network byte order
            if(header_recv.ttl_pi_sd.bit.si == true)
            {
                saddr = (vpn_ctx->tunif.addr & vpn_ctx->tunif.mask) | peer_table[src_id]->vip;
                ip_snat(buf_load, saddr);
            }
            if(header_recv.ttl_pi_sd.bit.di == true)
            {
                daddr = (vpn_ctx->tunif.addr & vpn_ctx->tunif.mask) | peer_table[dst_id]->vip;
                ip_dnat(buf_load, daddr);
            }

            packet_profile_t * pkt = new_pkt();

            pkt->src_id = src_id;
            pkt->dst_id = dst_id;
            pkt->write_fd = vpn_ctx->tunfd;
            pkt->len = len_load;
            memcpy(pkt->buf_packet, buf_load, len_load);

            queue_put(vpn_ctx->write_q, pkt, 0);

            continue;
        }
        else  // forward to dst_id
        {
            ttl = header_recv.ttl_pi_sd.bit.ttl;
            //packet dst is not local and ttl expire, drop packet. only allow 16 hops
            if(HEAD_TTL_MIN == ttl)
            {
                WARNING("TTL expired! from %d.%d.%d.%d to %d.%d.%d.%d.",
                    ip_saddr.a, ip_saddr.b, ip_saddr.c, ip_saddr.d,
                    ip_daddr.a, ip_daddr.b, ip_daddr.c, ip_daddr.d);   
                continue;
            }

            if(vpn_ctx->allow_p2p == false)
            {
                if(header_recv.ttl_pi_sd.bit.si == true && header_recv.ttl_pi_sd.bit.di == true)
                {
                    DEBUG("tunif %s received packet from %d.%d to %d.%d: P2P not allowed!",
                        vpn_ctx->tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
                    continue;
                }
            }

            ttl--;
            header_send.ttl_pi_sd.u16 = ntohs(header_send.ttl_pi_sd.u16);
            header_send.ttl_pi_sd.bit.ttl = ttl;
            header_send.ttl_pi_sd.u16 = htons(header_send.ttl_pi_sd.u16);

            memcpy(buf_recv, &header_send, HEADER_LEN);

            // decrypt the IP header to check if it should be duplicated.
            nr_aes_block = (IP_LEN + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
            for(int i=0; i<nr_aes_block; i++)
                decrypt(buf_load+i*AES_TEXT_LEN, buf_recv+HEADER_LEN+HEAD_ICV_LEN+i*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);
            bool dup = should_pkt_dup(buf_load);

            packet_profile_t * pkt = new_pkt();

            pkt->src_id = src_id;
            pkt->dst_id = dst_id;
            pkt->is_forward = true;
            pkt->outer_src_addr = peeraddr;
            pkt->send_fd = vpn_ctx->sockfd;
            pkt->len = len_recv;
            pkt->dup = dup;
            memcpy(pkt->buf_packet, buf_recv, len_recv);

            queue_put(vpn_ctx->send_q, pkt, 0);

            continue;
        }
    }

    free(buf_recv);
    free(buf_load);
    free(buf_send);
    pthread_cleanup_pop(0);
    return NULL;
}


