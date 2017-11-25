#ifndef POLICY_H_
#define POLICY_H_

#include <stdint.h>

#include "peer.h"


#define POLICY_LIMIT_LOGPOINT_REPLAY -2
#define POLICY_LIMIT_EXCEEDED_REPLAY -7
#define POLICY_LIMIT_EXCEEDED_INVOLVE_REPLAY -6
#define POLICY_LIMIT_LOGPOINT_TIMEJUMP -3
#define POLICY_LIMIT_EXCEEDED_TIMEJUMP -4
#define POLICY_LIMIT_EXCEEDED_INVOLVE_TIMEJUMP -5
#define POLICY_LIMIT_EXCEEDED_ERROR -1


// max delay 10 seconds. if an packet delayed more than 10s, it will be treated as new packet.
// if too many delay packets, it may be replay attack
#define MAX_DELAY_TIME 10

// why allow some replay packets? because peer may change devices or adjust system time/date. it's different from DoS.
// so max replay rate is REPLAY_CNT_LIMIT per RESET_STAT_INTERVAL
#define RESET_STAT_INTERVAL 30
#define REPLAY_CNT_LIMIT 10
#define JUMP_CNT_LIMIT 3
#define INVOLVE_CNT_LIMIT 3


bool should_pkt_dup(byte* ip_load);
bool should_pkt_delay(byte* ip_load);

int flow_filter(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, flow_profile_t * fp_src, flow_profile_t * fp_dst);


#endif
