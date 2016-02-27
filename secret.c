#include "secret.h"
#include "log.h"
#include "ip.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct peer_profile_t* add_peer()
{
    struct peer_profile_t * p = (struct peer_profile_t *)malloc(sizeof(struct peer_profile_t));
    if(p == NULL)
    {
        printlog(errno, "add_peer: malloc failed");
        return NULL;
    }
    else
        bzero(p, sizeof(struct peer_profile_t));

    struct sockaddr_in * peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    if(peeraddr == NULL)
    {
        printlog(errno, "add_peer: malloc failed");
        delete_peer(p);
        return NULL;
    }
    else
    {
        bzero(peeraddr, sizeof(struct sockaddr_in));
        p->peeraddr = peeraddr;
    }

    p->flow_src = (struct flow_profile_t *)malloc(sizeof(struct flow_profile_t));
    if(p->flow_src == NULL)
    {
        printlog(errno, "add_peer: malloc failed");
        delete_peer(p);
        return NULL;
    }
    else
        bzero(p->flow_src, sizeof(struct flow_profile_t));

    p->flow_src->ba_pre = bit_array_create(SEQ_LEVEL_1);
    if(p->flow_src->ba_pre == NULL)
    {
        printlog(errno, "add_peer: malloc failed");
        delete_peer(p);
        return NULL;
    }
    else
        bit_array_clearall(p->flow_src->ba_pre);

    p->flow_src->ba_now = bit_array_create(SEQ_LEVEL_1);
    if(p->flow_src->ba_now == NULL)
    {
        printlog(errno, "add_peer: malloc failed");
        delete_peer(p);
        return NULL;
    }
    else
        bit_array_clearall(p->flow_src->ba_now);

    p->valid = true;

    return p;
}

int delete_peer(struct peer_profile_t* p)
{
    if(p == NULL)
        return 0;

    if(p->peeraddr != NULL)
        free(p->peeraddr);

    if(p->flow_src != NULL)
    {
        bit_array_destroy(p->flow_src->ba_pre);
        bit_array_destroy(p->flow_src->ba_now);
        free(p->flow_src);
    }

    free(p);

    return 0;
}

int copy_peer(struct peer_profile_t* dst, struct peer_profile_t* src)
{
    if(dst == NULL || src == NULL)
    {
        printlog(ERROR_LEVEL, "error copy_peer: dst or src is NULL\n");
        return -1;
    }

    if(dst->peeraddr == NULL || src->peeraddr == NULL)
    {
        printlog(ERROR_LEVEL, "error copy_peer: dst->peeraddr or src->peeraddr is NULL\n");
        return -1;
    }

    if(dst->flow_src == NULL || src->flow_src == NULL)
    {
        printlog(ERROR_LEVEL, "error copy_peer: dst->flow_src or src->flow_src is NULL\n");
        return -1;
    }

    dst->id           = src->id;
    dst->valid        = src->valid;
    dst->discard      = src->discard;
    dst->restricted   = src->restricted;
    dst->dup          = src->dup;
    dst->srtt         = src->srtt;
    dst->involve_cnt  = src->involve_cnt;
    dst->port         = src->port;
    dst->vip          = src->vip;
    dst->rip          = src->rip;

    memcpy(dst->psk, src->psk, 2*AES_TEXT_LEN);
    memcpy(dst->peeraddr, src->peeraddr, sizeof(struct sockaddr_in));

    dst->flow_src->time_pre    = src->flow_src->time_pre;
    dst->flow_src->time_now    = src->flow_src->time_now;
    dst->flow_src->dup_cnt     = src->flow_src->dup_cnt;
    dst->flow_src->delay_cnt   = src->flow_src->delay_cnt;
    dst->flow_src->replay_cnt  = src->flow_src->replay_cnt;
    dst->flow_src->jump_cnt    = src->flow_src->jump_cnt;
    dst->flow_src->time_min    = src->flow_src->time_min;
    dst->flow_src->time_max    = src->flow_src->time_max;

    bit_array_copy(dst->flow_src->ba_pre, src->flow_src->ba_pre);
    bit_array_copy(dst->flow_src->ba_now, src->flow_src->ba_now);

    return 0;
}

struct peer_profile_t** init_peer_table(FILE *secrets_file, int max_id)
{
    if(NULL == secrets_file)
        return NULL;

    struct peer_profile_t ** peer_table = (struct peer_profile_t **)malloc((max_id+1) * sizeof(struct peer_profile_t*));
    if(peer_table == NULL)
    {
        printlog(errno, "init_peer_table: malloc failed");
        return NULL;
    }
    else
        bzero(peer_table, (max_id+1) * sizeof(struct peer_profile_t*));

    if(update_peer_table(peer_table, secrets_file, max_id) < 0)
    {
        printlog(ERROR_LEVEL, "init_peer_table: update_peer_table failed");
        destroy_peer_table(peer_table, max_id); 
        return NULL;
    }

    return peer_table;
}

int update_peer_table(struct peer_profile_t** peer_table, FILE *secrets_file, int max_id)
{
    if(NULL == peer_table || NULL == secrets_file)
    {
        printlog(ERROR_LEVEL, "error update_peer_table: peer_table or secrets_file is NULL");
        return -1;
    }
    
    int i;
    for(i = 0; i < max_id+1; i++)
        if(peer_table[i] != NULL)
            peer_table[i]->discard = true;

    size_t len = 1024;
    char *line = (char *)malloc(len);
    if(line == NULL)
    {
        printlog(errno, "update_peer_table: malloc failed");
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
            printlog(INFO_LEVEL, "Warning: PSK of ID %s not found, ignore this peer!\n", id_str);
            continue;
        }
        id = inet_ptons(id_str);
        if(0 == id || id > max_id)
        {
            printlog(INFO_LEVEL, "Warning: the ID of %s may be wrong, ignore this peer!\n", id_str);
            continue;
        }
        
        struct peer_profile_t * tmp_peer = add_peer();
        if(tmp_peer == NULL)
        {
            printlog(errno, "update_peer_table: add_peer failed");
            return -1;
        }
        if(peer_table[id] != NULL)
            if(copy_peer(tmp_peer, peer_table[id]) < 0)
                printlog(ERROR_LEVEL, "Error: copy the ID of %s failed\n", id_str);

        tmp_peer->id = id;
        tmp_peer->discard = false;
        strncpy((char*)tmp_peer->psk, psk_str, 2*AES_TEXT_LEN);

        if(port_str != NULL) //port_str must be parsed before ip, because servaddr.sin_port uses it.
        {
            int port = atoi(port_str);
            if(port < 1)
                printlog(ERROR_LEVEL, "Warning: invalid PORT of peer: %s, ingore it's port value!\n", id_str);
            tmp_peer->port = port;
        }

        if(ip_name_str != NULL && strcmp(ip_name_str, "none") != 0)
        {
            char ip_str[IPV4_LEN] = "\0";
            if(hostname_to_ip(ip_name_str, ip_str) < 0)
                printlog(ERROR_LEVEL, "Warning: invalid host of peer: %s, %s nslookup failed, ingore it's IP/Port value!\n", id_str, ip_name_str);
            else
            {
                inet_pton(AF_INET, ip_str, &(tmp_peer->peeraddr->sin_addr));
                tmp_peer->peeraddr->sin_family = AF_INET;
                tmp_peer->peeraddr->sin_port = htons(tmp_peer->port);
                tmp_peer->restricted = true;
            }
        }

        if(ip6_str != NULL && strcmp(ip6_str, "none") != 0)
            printlog(INFO_LEVEL, "IPv6 not supported now, ignore it!\n");

        tmp_peer->vip = htonl(id); //0.0.x.x in network byte order, used inside tunnel.
        //tmp_peer->rip = (global_tunif.addr & global_tunif.mask) | htonl(id); //in network byte order.

        if(peer_table[id] != NULL)
        {
            printlog(INFO_LEVEL, "Warning: update the ID of %s\n", id_str);
            if(copy_peer(peer_table[id], tmp_peer) < 0)
                printlog(ERROR_LEVEL, "Error: update the ID of %s failed\n", id_str);
            delete_peer(tmp_peer);
            tmp_peer = NULL;
        }
        else
            peer_table[id] = tmp_peer;
    }

    free(line);

    for(i = 0; i < max_id+1; i++)
        if(peer_table[i] != NULL)
            if(peer_table[i]->discard)
            {
                printlog(INFO_LEVEL, "Warning: delete the ID of %d.%d\n", i/256, i%256);
                delete_peer(peer_table[i]);
                peer_table[i] = NULL;
            }

    return 0;
}

int shrink_line(char *line)
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


int destroy_peer_table(struct peer_profile_t **peer_table, int max_id)
{
    if(NULL == peer_table)
        return 0;

    int peer_num = max_id+1;
    
    int i;
    for(i = 0; i < peer_num; i++)
    {
        delete_peer(peer_table[i]);
        peer_table[i] = NULL;
    }

    free(peer_table);
    return 0;
}