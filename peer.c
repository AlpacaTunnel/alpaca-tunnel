#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>


#include "log.h"
#include "header.h"
#include "peer.h"


#define DEFAULT_SEQ_NR 16000   // enough for 100Mbps TCP
#define TCP_SESSION_CNT 100
#define SECRET_NULL_FLAG "null"

/*
* replace all white-space characters to spaces, remove all characters after '#'
*/
static int shrink_line(char *line)
{
    int n = strlen(line);
    int i;
    for(i=0; i<n; i++)
        if(isspace(line[i]))
            line[i] = ' ';
        else if('#' == line[i])
            for( ; i<n; i++)
                line[i] = '\0';
    return strlen(line);
}


static int delete_peer(peer_profile_t* p)
{
    if(p == NULL)
        return 0;

    if(p->path_array != NULL)
        free(p->path_array);

    if(p->tcp_info != NULL)
        free(p->tcp_info);

    if(p->flow_src != NULL)
    {
        bit_array_destroy(p->flow_src->ba_pre);
        bit_array_destroy(p->flow_src->ba_now);
        free(p->flow_src);
    }

    if(p->flow_lock != NULL)
    {
        pthread_mutex_destroy(p->flow_lock);
        free(p->flow_lock);
    }

    free(p);

    return 0;
}


static peer_profile_t* create_peer()
{
    uint32_t seq_nr = DEFAULT_SEQ_NR;
    peer_profile_t * p = (peer_profile_t *)malloc(sizeof(peer_profile_t));
    if(p == NULL)
    {
        ERROR(errno, "create_peer: malloc failed");
        return NULL;
    }
    bzero(p, sizeof(peer_profile_t));

    p->path_array = (path_profile_t *)malloc(sizeof(path_profile_t) * (HEAD_MAX_PATH+1));
    if(p->path_array == NULL)
    {
        ERROR(errno, "create_peer: malloc failed");
        delete_peer(p);
        return NULL;
    }
    bzero(p->path_array, sizeof(path_profile_t) * (HEAD_MAX_PATH+1));

    p->tcp_info = (tcp_info_t *)malloc(TCP_SESSION_CNT * sizeof(tcp_info_t));
    if(p->tcp_info == NULL)
    {
        ERROR(errno, "create_peer: malloc failed");
        delete_peer(p);
        return NULL;
    }
    bzero(p->tcp_info, TCP_SESSION_CNT * sizeof(tcp_info_t));

    p->flow_src = (flow_profile_t *)malloc(sizeof(flow_profile_t));
    if(p->flow_src == NULL)
    {
        ERROR(errno, "create_peer: malloc failed");
        delete_peer(p);
        return NULL;
    }
    bzero(p->flow_src, sizeof(flow_profile_t));

    p->flow_src->ba_pre = bit_array_init(seq_nr);
    if(p->flow_src->ba_pre == NULL)
    {
        ERROR(errno, "create_peer: malloc failed");
        delete_peer(p);
        return NULL;
    }
    bit_array_clearall(p->flow_src->ba_pre);

    p->flow_lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if(p->flow_lock == NULL)
    {
        ERROR(errno, "policy_init: malloc");
        return NULL;
    }

    if(pthread_mutex_init(p->flow_lock, NULL) != 0)
    {
        ERROR(errno, "pthread_mutex_init");
        return NULL;
    }

    p->flow_src->ba_now = bit_array_init(seq_nr);
    if(p->flow_src->ba_now == NULL)
    {
        ERROR(errno, "create_peer: malloc failed");
        delete_peer(p);
        return NULL;
    }
    bit_array_clearall(p->flow_src->ba_now);

    p->valid = true;
    p->recv_pkt_cnt = 0;
    p->send_pkt_cnt = 0;

    p->aes_ctx = (struct AES_ctx *)malloc(sizeof(struct AES_ctx));
    if(p->aes_ctx == NULL)
    {
        ERROR(errno, "aes_ctx: malloc");
        return NULL;
    }

    return p;
}


int reset_peer_table_flow(peer_profile_t ** peer_table)
{
    if(peer_table == NULL)
        return 0;

    for(int i = 0; i < HEAD_MAX_ID+1; i++)
    {
        peer_profile_t * p = peer_table[i];
        if(p == NULL || p->flow_src == NULL)
            continue;

        if(pthread_mutex_lock(p->flow_lock) != 0)
        {
            ERROR(errno, "pthread_mutex_lock");
            return -1;
        }

        p->flow_src->dup_cnt = 0;
        p->flow_src->delay_cnt = 0;
        p->flow_src->replay_cnt = 0;
        p->flow_src->time_min = 0;
        p->flow_src->time_max = 0;
        p->flow_src->jump_cnt = 0;

        if(pthread_mutex_unlock(p->flow_lock) != 0)
        {
            ERROR(errno, "pthread_mutex_unlock");
            return -1;
        }
    }

    return 0;
}


peer_profile_t** init_peer_table()
{
    int max_id = HEAD_MAX_ID;

    peer_profile_t ** peer_table = (peer_profile_t **)malloc((max_id+1) * sizeof(peer_profile_t*));
    if(peer_table == NULL)
    {
        ERROR(errno, "init_peer_table: malloc failed");
        return NULL;
    }

    bzero(peer_table, (max_id+1) * sizeof(peer_profile_t*));

    return peer_table;
}


/*
 * 1) If new peer, add it.
 * 2) If peer changed, only update these values: peer_key/peer_ip/peer_ip6/peer_port.
 * 3) If peer deleted, don't delete it from peer_table, set it as invalid instead. (avoid segmentation fault)
*/
int update_peer_table(peer_profile_t** peer_table, FILE *secrets_file)
{
    int max_id = HEAD_MAX_ID;

    if(NULL == peer_table || NULL == secrets_file)
    {
        ERROR(0, "update_peer_table: peer_table or secrets_file is NULL");
        return -1;
    }

    // at first, set all peers' discard to true
    for(int i = 0; i < max_id+1; i++)
        if(peer_table[i] != NULL)
            peer_table[i]->discard = true;

    size_t len = 1024;
    char *line = (char *)malloc(len);
    if(line == NULL)
    {
        ERROR(errno, "update_peer_table: malloc failed");
        return -1;
    }
    else
        bzero(line, len);

    while(-1 != getline(&line, &len, secrets_file))  //why line is an array of char*, not a char* ?
    {
        int id = 0;
        char *id_str = NULL;
        char *psk_str = NULL;
        char *ip_name_str = NULL;
        char *ip6_str = NULL;
        char *port_str = NULL;

        if(shrink_line(line) <= 1)
            continue;
        id_str = strtok(line, " ");
        psk_str = strtok(NULL, " ");
        ip_name_str = strtok(NULL, " ");
        ip6_str = strtok(NULL, " ");
        port_str = strtok(NULL, " ");

        if(NULL == id_str)
            continue;
        if(NULL == psk_str)
        {
            WARNING("PSK of ID %s not found, ignore this peer!", id_str);
            continue;
        }
        id = inet_ptons(id_str);
        if(0 == id || id > max_id)
        {
            WARNING("The ID of %s may be wrong, ignore this peer!", id_str);
            continue;
        }

        peer_profile_t * tmp_peer = create_peer();
        if(tmp_peer == NULL)
        {
            ERROR(errno, "update_peer_table: create_peer failed.");
            return -1;
        }

        tmp_peer->id = id;

        if(strlen(psk_str) > 2*AES_BLOCKLEN)
            WARNING("PSK of ID %s is longer than %d, ignore some bytes.", id_str, 2*AES_BLOCKLEN);
        strncpy((char*)tmp_peer->psk, psk_str, 2*AES_BLOCKLEN);

        int port = 0;
        if(port_str != NULL) // port_str must be parsed before ip, because servaddr.sin_port uses it.
        {
            port = atoi(port_str);
            if(port < 1)
                WARNING("Invalid PORT of peer: %s, ingore it's port value!", id_str);
        }

        for(int i = 0; i <= HEAD_MAX_PATH; i++)
            tmp_peer->path_array[i].dynamic = true; // set all path to dynamic by default

        path_profile_t * first_path = &(tmp_peer->path_array[0]);     // only read the fist path form secret.txt
        if(ip_name_str != NULL && strcmp(ip_name_str, SECRET_NULL_FLAG) != 0)
        {
            char ip_str[IP_LEN] = "\0";
            if(hostname_to_ip(ip_name_str, ip_str) < 0)
                WARNING("Invalid host of peer: %s, %s nslookup failed, ingore it's IP/Port value!", id_str, ip_name_str);
            else
            {
                inet_pton(AF_INET, ip_str, &(first_path->peeraddr.sin_addr));
                first_path->peeraddr.sin_family = AF_INET;
                first_path->peeraddr.sin_port = htons(port);
                first_path->dynamic = false;
            }
        }

        if(ip6_str != NULL && strcmp(ip6_str, SECRET_NULL_FLAG) != 0)
            WARNING("IPv6 not supported now, ignore it!");

        tmp_peer->vip = htonl(id); // 0.0.x.x in network byte order, used inside tunnel.

        if(peer_table[id] == NULL)
        {
            INFO("Add the ID of %s.", id_str);
            peer_table[id] = tmp_peer;
        }
        else
        {
            INFO("update the ID of %s.", id_str);

            memcpy(peer_table[id]->psk, tmp_peer->psk, 2*AES_BLOCKLEN);

            for(int i = 0; i <= HEAD_MAX_PATH; i++)
            {
                peer_table[id]->path_array[i].peeraddr = tmp_peer->path_array[i].peeraddr;
                peer_table[id]->path_array[i].dynamic  = tmp_peer->path_array[i].dynamic;
            }

            delete_peer(tmp_peer);
            tmp_peer = NULL;
        }

        AES_init_ctx(peer_table[id]->aes_ctx, peer_table[id]->psk);

        peer_table[id]->discard = false;  // found the ID in secret.txt, set it to not discard
    }

    free(line);

    // at the end, check discard peer and set it to invalid
    for(int i = 0; i < max_id+1; i++)
        if(peer_table[i] != NULL)
        {
            if(peer_table[i]->discard)
            {
                WARNING("Delete the ID (set to invalid): %d.%d", i/256, i%256);
                peer_table[i]->valid = false;
            }
            else
                peer_table[i]->valid = true;
        }

    return 0;
}


int destroy_peer_table(peer_profile_t **peer_table)
{
    if(NULL == peer_table)
        return 0;

    int peer_num = HEAD_MAX_ID + 1;

    int i;
    for(i = 0; i < peer_num; i++)
    {
        delete_peer(peer_table[i]);
        peer_table[i] = NULL;
    }

    free(peer_table);
    return 0;
}

