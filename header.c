#include "header.h"

/*
void print_header(tunnel_header_t *header)
{
    printf("type_len_m: %d\n", header->type_len_m);
    printf("ttl_pi_sd: %d\n", header->ttl_pi_sd);
    printf("src_id: %d\n", header->src_id);
    printf("dst_id: %d\n", header->dst_id);
    printf("time_magic: %d\n", header->time_magic);
    printf("seq_rand: %d\n", header->seq_rand);
}
*/


// convert byte order from host to network
void header_hton(tunnel_header_t * header)
{
    header->type_len_m.u16  = htons(header->type_len_m.u16);
    header->ttl_pi_sd.u16   = htons(header->ttl_pi_sd.u16);
    header->src_id          = htons(header->src_id);
    header->dst_id          = htons(header->dst_id);
    header->time_magic.u32  = htonl(header->time_magic.u32);
    header->seq_rand.u32    = htonl(header->seq_rand.u32);
    return;
}


// convert byte order from network to host
void header_ntoh(tunnel_header_t * header)
{
    header->type_len_m.u16  = ntohs(header->type_len_m.u16);
    header->ttl_pi_sd.u16   = ntohs(header->ttl_pi_sd.u16);
    header->src_id          = ntohs(header->src_id);
    header->dst_id          = ntohs(header->dst_id);
    header->time_magic.u32  = ntohl(header->time_magic.u32);
    header->seq_rand.u32    = ntohl(header->seq_rand.u32);
    return;
}
