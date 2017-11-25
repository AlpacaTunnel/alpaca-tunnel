#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


#include "data-struct/data-struct.h"
#include "policy.h"


/*
 * duplicate TCP-SYN and DNS packets, because they're more import.
*/
bool should_pkt_dup(byte* ip_load)
{
    if(ip_load == NULL)
        return false;

    struct iphdr ip_h;
    struct tcphdr tcp_h;
    struct udphdr udp_h;

    memcpy(&ip_h, ip_load, sizeof(struct iphdr));

    if(6 == ip_h.protocol)
    {
        memcpy(&tcp_h, ip_load+sizeof(struct iphdr), sizeof(struct tcphdr));

        if(htons(tcp_h.source) == 53 || htons(tcp_h.dest) == 53)
            return true;

        if(tcp_h.syn == 1)
            return true;
    }
    else if(17 == ip_h.protocol)
    {
        memcpy(&udp_h, ip_load+sizeof(struct iphdr), sizeof(struct udphdr));

        if(htons(udp_h.source) == 53 || htons(udp_h.dest) == 53)
            return true;
    }

    return false;
}


/*
 * delay TCP-ACK packet write to tunif
*/
bool should_pkt_delay(byte* ip_load)
{
    if(ip_load == NULL)
        return false;

    struct iphdr ip_h;
    struct tcphdr tcp_h;

    memcpy(&ip_h, ip_load, sizeof(struct iphdr));

    if(6 == ip_h.protocol)
    {
        memcpy(&tcp_h, ip_load+sizeof(struct iphdr), sizeof(struct tcphdr));
        if((ntohs(ip_h.tot_len) - ip_h.ihl * 4) == tcp_h.doff * 4 && tcp_h.ack == 1)  // pure ACK, not piggybacking
            return true;
    }

    return false;
}


/*
  need to filter 2 elements: pkt_time and pkt_seq
  1) pkt_time can NOT run too fast. if faster than system, let's call it a jump. if too many jumps, then it may be an attack.
  2) pkt_seq can NOT duplicate.

  return value: return 0, valid packet; return negative number, invalid packet.
  invalid packets should be droped.
*/
int flow_filter(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, flow_profile_t * fp_src, flow_profile_t * fp_dst)
{
    if(src_id == dst_id || 0 == src_id)
        return -1;

    if(fp_src == NULL || fp_dst == NULL)
        return -1;

    if(fp_src->time_min == 0)
        fp_src->time_min = pkt_time;
    else
        fp_src->time_min = pkt_time < fp_src->time_min ? pkt_time : fp_src->time_min;

    if(fp_src->time_max == 0)
        fp_src->time_max = pkt_time;
    else
        fp_src->time_max = pkt_time > fp_src->time_max ? pkt_time : fp_src->time_max;

    if( (fp_src->time_max - fp_src->time_min) > (RESET_STAT_INTERVAL + MAX_DELAY_TIME) )
    {
        fp_src->jump_cnt++;
        fp_src->time_max = 0;
        fp_src->time_min = 0;
        if(fp_src->jump_cnt == JUMP_CNT_LIMIT)
        {
            if(src_id < dst_id)
            {
                fp_dst->involve_cnt++;
                if(fp_dst->involve_cnt > INVOLVE_CNT_LIMIT)
                {
                    // peer_table[dst_id]->valid = false;
                    return POLICY_LIMIT_EXCEEDED_INVOLVE_TIMEJUMP;
                }
            }
            return POLICY_LIMIT_LOGPOINT_TIMEJUMP;  // return when the number first reached limit, to avoid too many logs
        }
    }
    if(fp_src->jump_cnt >= JUMP_CNT_LIMIT)
        return POLICY_LIMIT_EXCEEDED_TIMEJUMP;

    int time_diff = pkt_time - fp_src->time_now;

    if(time_diff >= 2)
    {
        bit_array_clearall(fp_src->ba_pre);
        bit_array_clearall(fp_src->ba_now);
        fp_src->time_now = pkt_time;
        fp_src->time_pre = pkt_time - 1;
        bit_array_set(fp_src->ba_now, pkt_seq);
    }
    else if(time_diff == 1)
    {
        fp_src->time_pre = fp_src->time_now;
        fp_src->time_now = pkt_time;

        bit_array_t * ba_tmp;
        ba_tmp = fp_src->ba_pre;
        fp_src->ba_pre = fp_src->ba_now;
        fp_src->ba_now = ba_tmp;

        bit_array_clearall(fp_src->ba_now);
        bit_array_set(fp_src->ba_now, pkt_seq);
    }
    else if(time_diff == 0)
    {
        if(bit_array_get(fp_src->ba_now, pkt_seq) == 1)  // duplicate packets, don't treat as attack because they'are normal. just drop them.
        {
            // DEBUG("---------- recv dup, %d:%d, time_diff: 0", pkt_time, pkt_seq);
            fp_src->dup_cnt++;
            return -1;
        }
        else
            bit_array_set(fp_src->ba_now, pkt_seq);
    }
    else if(time_diff == -1)
    {
        if(bit_array_get(fp_src->ba_pre, pkt_seq) == 1)
        {
            // DEBUG("---------- recv dup, %d:%d, time_diff: -1", pkt_time, pkt_seq);
            fp_src->dup_cnt++;
            return -1;
        }
        else
            bit_array_set(fp_src->ba_pre, pkt_seq);
    }
    else if(time_diff <= -2 && time_diff > -MAX_DELAY_TIME)  // packets arrived a little late, just drop it. its timestamp is too close to normal packets, can't be attack.
    {
        fp_src->delay_cnt++;
        return -1;
    }
    else // time_diff <= -MAX_DELAY_TIME. packets arrived even latter than MAX_DELAY_TIME, may be replay attack.
    {
        fp_src->replay_cnt++;
        if(fp_src->replay_cnt == REPLAY_CNT_LIMIT)  //if replay_cnt is beyond REPLAY_CNT_LIMIT, drop replay packets.
        {
            if(src_id < dst_id)
            {
                fp_dst->involve_cnt++;
                if(fp_dst->involve_cnt > INVOLVE_CNT_LIMIT)
                {
                    // peer_table[dst_id]->valid = false;
                    return POLICY_LIMIT_EXCEEDED_INVOLVE_REPLAY;
                }
            }
            return POLICY_LIMIT_LOGPOINT_REPLAY;
        }
        if(fp_src->replay_cnt > REPLAY_CNT_LIMIT)
            return POLICY_LIMIT_EXCEEDED_REPLAY;

        bit_array_clearall(fp_src->ba_pre);
        bit_array_clearall(fp_src->ba_now);
        fp_src->time_now = pkt_time;
        fp_src->time_pre = pkt_time - 1;
        bit_array_set(fp_src->ba_now, pkt_seq);
    }

    if(fp_src->replay_cnt >= REPLAY_CNT_LIMIT)
        return POLICY_LIMIT_EXCEEDED_REPLAY;

    if(time_diff == -1)
        return 1;
    if(time_diff == 0)
        return 2;
    if(time_diff == 1)
        return 3;
    if(time_diff > 1 || time_diff < -1)
        return 4;

    return 0;
}

