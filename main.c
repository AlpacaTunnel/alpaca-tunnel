#include "aes.h"
#include "route.h"
#include "data_struct.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
typedef enum { false, true } bool;

//custom specified path: first. (not available now.)
//second, if exe located at /usr/bin/
#define ABSOLUTE_PATH_TO_SECRETS "/etc/alpaca_tunnel.d/alpaca_secrets"
//second, if exe located at /usr/local/bin/
#define ABSOLUTE_PATH_TO_SECRETS_LOCAL "/usr/local/etc/alpaca_tunnel.d/alpaca_secrets"
//third, the same path with exe_file
#define RELATIVE_PATH_TO_SECRETS "alpaca_tunnel.d/alpaca_secrets"
#define PATH_LEN 1024
#define PROCESS_NAME "AlpacaTunnel"
#define VERSION "2.1.4"

#define TUN_NETMASK 0xFFFF0000
//tunnel MTU must not be greater than 1440
#define TUN_MTU 1440
#define ETH_MTU 1500
//strlen of ipv4 address, including two quotation marks, must be larger than 16
#define IPV4_LEN 32
//length of aes key must be 128, 192 or 256
#define AES_KEY_LEN 128
#define DEFAULT_PORT 1984


struct m_type_len_t
{
    uint m:1;
    uint type:4;
    uint len:11;
} __attribute__((packed));

typedef union
{
    struct m_type_len_t bit;
    uint16_t u16;
} m_type_len_u;

struct ttl_flag_random_t
{
    uint ttl:4;
    bool src_inside:1;
    bool dst_inside:1;
    uint random:10;
} __attribute__((packed));

typedef union
{
    struct ttl_flag_random_t bit;
    uint16_t u16;
} ttl_flag_random_u;

struct seq_frag_off_t
{
    uint32_t seq:24;
    uint frag:1;
    uint off:7;
} __attribute__((packed));

typedef union
{
    struct seq_frag_off_t bit;
    uint32_t u32;
} seq_frag_off_u;

/*
  all data in header are stored in network bit/byte order.
*/

struct tunnel_header_t
{
    m_type_len_u m_type_len;
    ttl_flag_random_u ttl_flag_random;
    uint16_t src_id;
    uint16_t dst_id;
    uint32_t time;
    seq_frag_off_u seq_frag_off;
} __attribute__((packed));


/*
    struct tunnel_header_t send_head;
    send_head.m_type_len.bit.m = 1;
    send_head.m_type_len.bit.type = 10;
    send_head.m_type_len.bit.len = 0;
    printf("%d\n", send_head.m_type_len.u16);
*/

/*
#define HEAD_MASK_MORE 0x8000
#define HEAD_MASK_TYPE 0x7800
#define HEAD_MASK_LEN  0x07FF
#define HEAD_MASK_TTL  0xF000
#define HEAD_MASK_RANDOM  0x0FFF
#define HEAD_MASK_SEQ  0xFFFFFF00
#define HEAD_MASK_FRAG 0x00000080
#define HEAD_MASK_OFF  0x0000007F
*/

#define HEADER_LEN 16
#define ICV_LEN 16
#define HEAD_MORE_FALSE 0
#define HEAD_MORE_TRUE  1
#define HEAD_TYPE_DATA  0
#define HEAD_TYPE_MSG   1
#define HEAD_FRAG_FALSE 0
#define HEAD_FRAG_TRUE  1
#define IPV4_HEAD_LEN 20
#define TCP_HEAD_LEN 40
#define IPV4_OFFSET_CSUM 10
#define IPV4_OFFSET_SADDR 12
#define IPV4_OFFSET_DADDR 16
#define IPV4_MASK_FRAGOFF 0x1FFF  //in host byte order
#define TTL_MAX 0xF
#define TTL_MIN 0

#define WRITE_BUF_SIZE 50000000
#define SEND_BUF_SIZE 50000000
#define SEQ_LEVEL_1 1000000

#define NAT_BOUND 4095  //15.255
#define MAX_SERVER_ID 4095  //15.255
#define MAX_ID 65535
//reserved ID: 0.0, 0.1, 255.255, any server/client cann't use.

#define MAX_DELAY_TIME 10  //max delay 10 seconds.

//why allow some replay packets? because peer may change devices or adjust system time/date. it's different from DoS.
//so max replay rate is REPLAY_CNT_LIMIT per RESET_STAT_INTERVAL
#define RESET_STAT_INTERVAL 30
#define REPLAY_CNT_LIMIT 10
#define JUMP_CNT_LIMIT 3
#define INVOLVE_CNT_LIMIT 3

#define ALLOW_P2P true
#define CHECK_RESTRICTED_IP true

enum {error, debug, info} global_log_level = debug;

struct ip_dot_decimal_t   //in network byte order
{
    byte a;
    byte b;
    byte c;
    byte d;
} __attribute__((packed));

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

//client_read and client_recv are obsoleted
void* client_read(void *arg);
void* client_recv(void *arg);

void* server_read(void *arg);
void* server_recv(void *arg);
void* server_write(void *arg);
void* server_send(void *arg);
void* server_reset_stat(void *arg);
void* watch_link_route(void *arg);
void* reset_link_route(void *arg);
int tun_alloc(char *dev, int flags); 
int printlog(int en, char* format, ...);
int usage(char *pname);
struct peer_profile_t** init_peer(FILE *secrets_file);
int free_peer(struct peer_profile_t **p2);
void sig_handler(int signum);
uint16_t do_csum(uint16_t old_sum, uint32_t old_ip, uint32_t new_ip);
int ip_dnat(byte* ip_load, uint32_t new_ip);
int ip_snat(byte* ip_load, uint32_t new_ip);
int16_t inet_ptons(char *a);   //convert 15.255 to 4095
int shrink_line(char *line);
int flow_filter(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, struct peer_profile_t ** peer_table);

/* get next hop id form route_table or system route table
 * return value:
 * 0 : actually, will never return 0. instead, return 1.
 * 1 : local or link dst, should write to tunnel interface
 * >1: the ID of other tunnel server
 * if next_hop_id == global_self_id, return 1
*/
uint16_t get_next_hop_id(uint32_t ip_dst, uint32_t ip_src);


static int global_running = 0;
static int global_sysroute_change = 0;
static uint16_t global_self_id = 0;
static int global_pkt_cnt = 0;
static pthread_spinlock_t global_stat_spin;

//in network byte order.
static struct if_info_t global_tunif;
static struct if_info_t *global_if_list;
static uint16_t global_ipv4_mask_fragoff;

//static int global_packet_cnt_write = 0;
//static int global_packet_cnt_send = 0;

//enum {none, server, client, middle} global_mode = none;
static byte global_buf_group_psk[2*AES_TEXT_LEN] = "FUCKnimadeGFW!";
static int global_tunfd, global_sockfd;
static uint32_t global_local_time;
static uint32_t global_local_seq;
static uint32_t* global_trusted_ip = NULL;
static int global_trusted_ip_cnt = 0;

int usage(char *pname)
{
    printf("Usage: %s [-v|V] [-p port] [-g group] [-n id] [-i tun]\n", pname);
    return 0;
}

int main(int argc, char *argv[])
{
    srandom(time(NULL));
    if(init_route_spin() < 0)
        return -1;
    if(pthread_spin_init(&global_stat_spin, PTHREAD_PROCESS_PRIVATE) != 0)
    {
        perror("pthread_spin_init");
        return -1;
    }
    global_if_list = NULL;
    collect_if_info(&global_if_list);
    global_ipv4_mask_fragoff = htons(IPV4_MASK_FRAGOFF);
    global_running = 1;

    int rc1=0, rc2=0, rc3=0, rc5=0, rc6=0;
    //uint16_t clid = 0;
    struct peer_profile_t ** peer_table = NULL;
    pthread_t tid1=0, tid2=0, tid3=0, tid5=0, tid6=0;
    int port = DEFAULT_PORT;
    char tun_name[IFNAMSIZ] = "\0";
    //byte buf_psk[2*AES_TEXT_LEN] = "\0";
    char exe_path[PATH_LEN] = "\0";
    char secrets_path[PATH_LEN] = "\0";

    int opt;
    while((opt = getopt(argc, argv, "vVp:g:n:i:")) != -1)
    {
        switch(opt)
        {
        case 'v':
        case 'V':
            printf("%s %s\n", PROCESS_NAME, VERSION);
            exit(1);
        case 'p':
            port = atoi(optarg);
            if(port < 0 || port > 65534)
            {
                printlog(0, "error: Invalid port: %s!\n", port);
                printlog(0, "%s has exited.\n", PROCESS_NAME);
                exit(1);
            }
            break;
        case 'g':
            strncpy((char*)global_buf_group_psk, optarg, 2*AES_TEXT_LEN);
            break;
        case 'n':
            global_self_id = inet_ptons(optarg);
            break;
        case 'i':
            strncpy(tun_name, optarg, IFNAMSIZ);
            break;
        default:
            printlog(0, "%s has exited.\n", PROCESS_NAME);
            usage(argv[0]);
            exit(1);
        }
    }
    
    if(0 == global_self_id)
    {
        printlog(0, "error: ID not set or wrong format!\n");
        usage(argv[0]);
        printlog(0, "%s has exited.\n", PROCESS_NAME);
        exit(1);
    }
    if(1 == global_self_id || MAX_ID == global_self_id)
    {
        printlog(0, "error: ID cannot be 0.1 or 255.255!\n");
        printlog(0, "%s has exited.\n", PROCESS_NAME);
        exit(1);
    }
    
    if('\0' == tun_name[0])
    {
        printlog(0, "%s has exited.\n", PROCESS_NAME);
        usage(argv[0]);
        exit(1);
    }
    if( (global_tunfd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI)) < 0 )
    {
        printlog(0, "%s has exited.\n", PROCESS_NAME);
        exit(1);
    }
    strncpy(global_tunif.name, tun_name, IFNAMSIZ);

    global_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct ifreq tmp_ifr;
    tmp_ifr.ifr_addr.sa_family = AF_INET;
    strncpy(tmp_ifr.ifr_name, tun_name, IFNAMSIZ-1);
    if(ioctl(global_sockfd, SIOCGIFADDR, &tmp_ifr) < 0)
    {
        printlog(errno, "ioctl(SIOCGIFADDR) error: %s",global_tunif.name);
        goto _END;
    }
    struct sockaddr_in *tmp_in = (struct sockaddr_in *)&tmp_ifr.ifr_addr;
    global_tunif.addr = tmp_in->sin_addr.s_addr;
    global_tunif.mask = get_ipmask(global_tunif.addr, global_if_list);
    //tunif IP must be a /16 network, and must match self ID! otherwise, from/to peer will be confusing.
    if(TUN_NETMASK != ntohl(global_tunif.mask))
    {
        printlog(0, "error: tunnel mask is not /16\n");
        goto _END;
    }
    if((uint16_t)(ntohl(global_tunif.addr)) != global_self_id)
    {
        printlog(0, "error: tunnel ip does not match ID!\n");
        goto _END;
    }

    if('\0' == secrets_path[0])
    {
        int path_len = readlink("/proc/self/exe", exe_path, PATH_LEN);
        if(path_len < 0)
        {
            printlog(errno, "readlink error: /proc/self/exe");
            goto _END;
        }
        else if(path_len > (PATH_LEN-40))   //40 is reserved for strcat.
        {
            printlog(0, "readlink error: file path too long!\n");
            goto _END;
        }
        while(exe_path[path_len] != '/')
        {
            exe_path[path_len] = '\0';
            path_len--;
        }
        strcpy(secrets_path, exe_path);
        if(strcmp(exe_path, "/usr/bin/") == 0)
            strcpy(secrets_path, ABSOLUTE_PATH_TO_SECRETS);
        else if(strcmp(exe_path, "/usr/local/bin/") == 0)
            strcpy(secrets_path, ABSOLUTE_PATH_TO_SECRETS_LOCAL);
        else
            strcat(secrets_path, RELATIVE_PATH_TO_SECRETS);
    }

    FILE *secrets_file = NULL;
    if((secrets_file = fopen(secrets_path, "r")) == NULL)
    {
        printlog(errno, "open file error: %s", secrets_path);
        goto _END;
    }
    if((peer_table = init_peer(secrets_file)) == NULL)
    {
        printlog(0, "init peer failed!\n");
        fclose(secrets_file);
        goto _END;
    }
    fclose(secrets_file);
    //peer_table[0]->id = global_self_id;
    //memcpy(peer_table[0]->psk, buf_psk, 2*AES_TEXT_LEN);

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(global_sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printlog(errno, "bind error: port %d", port);
        goto _END;
    }

    if( (rc1 = pthread_create(&tid1, NULL, server_recv, peer_table)) != 0 )
    {
        printlog(errno, "pthread_error: create rc1"); 
        goto _END;
    }
    if( (rc2 = pthread_create(&tid2, NULL, server_read, peer_table)) != 0 )
    {
        printlog(errno, "pthread_error: create rc2"); 
        goto _END;
    }

    if( (rc3 = pthread_create(&tid3, NULL, server_reset_stat, peer_table)) != 0 )
    {
        printlog(errno, "pthread_error: create rc2"); 
        goto _END;
    }
    
    if( (rc5 = pthread_create(&tid5, NULL, watch_link_route, NULL)) != 0 )
    {
        printlog(errno, "pthread_error: create rc5"); 
        goto _END;
    }
    if( (rc6 = pthread_create(&tid6, NULL, reset_link_route, NULL)) != 0 )
    {
        printlog(errno, "pthread_error: create rc6"); 
        goto _END;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    //nohup won't work when SIGHUP installed.
    signal(SIGHUP, sig_handler);
    printlog(0, "%s has started.\n", PROCESS_NAME);
    while(global_running)
        sleep(1);  //pause();

    pthread_cancel(tid1);
    pthread_cancel(tid2);
    pthread_cancel(tid3);
    pthread_cancel(tid5);
    pthread_cancel(tid6);
    //pthread_join(tid1, NULL);
    //pthread_join(tid2, NULL);
    //pthread_join(tid3, NULL);

_END:
    global_running = 0;
    close(global_sockfd);
    close(global_tunfd);
    clear_if_info(global_if_list);
    global_if_list = NULL;
    destroy_route_spin();
    pthread_spin_destroy(&global_stat_spin);
    free_peer(peer_table);
    peer_table = NULL;
    //free(peer_table);
    printlog(0, "%s has exited.\n", PROCESS_NAME);
    return 0;
}


int16_t inet_ptons(char *a)
{
    if(a == NULL)
        return 0;
    uint8_t n1, n2;
    char *c = strdup(a);
    char delim[] = ".";
    char *a1 = strtok(c, delim);
    char *a2 = strtok(NULL, delim);
    if(a2 == NULL)
        return 0;

    int i;
    for(i=0; i<strlen(a1); i++)
        if(isdigit(a1[i]))
            continue;
        else
            return 0;
    for(i=0; i<strlen(a2); i++)
        if(isdigit(a2[i]))
            continue;
        else
            return 0;

    n1 = atoi(a1);
    n2 = atoi(a2);

    return ( n1 * 256 + n2 );
}

void sig_handler(int signum)
{
    if(SIGINT == signum)
        printlog(0, "received SIGINT!\n");
    else if(SIGTERM == signum)
        printlog(0, "received SIGTERM!\n");
    else if(SIGHUP == signum)
    {
        printlog(0, "received SIGHUP!\n");
        return; //do nothing
    }

    global_running = 0;
}

int printlog(int en, char* format, ...)
{
    va_list arglist;
    time_t timer;
    char tm_buf[64];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(tm_buf, 64, "%Y-%m-%d %H:%M:%S", tm_info);
    if(0 == en)
    {
        if(global_log_level == error)
            return 0;

        printf("%s ", tm_buf);
        va_start(arglist, format);
        vprintf(format, arglist);
        va_end(arglist);
    }
    else
    {
        fprintf(stderr, "%s ", tm_buf);
        va_start(arglist, format);
        vfprintf(stderr, format, arglist);
        va_end(arglist);

        errno = en;
        perror(" ");
    }
    //fflush(NULL);

    return 0;
}

int tun_alloc(char *dev, int flags) 
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if( (fd = open(clonedev, O_RDWR)) < 0 ) 
    {
        printlog(errno, "Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if (*dev) 
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) 
    {
        printlog(errno, "ioctl(TUNSETIFF) error: %s", dev);
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}

struct peer_profile_t** init_peer(FILE *secrets_file)
{
    if(NULL == secrets_file)
        return NULL;

    if(CHECK_RESTRICTED_IP)
    {
        global_trusted_ip = (uint32_t *)malloc((MAX_ID+1) * sizeof(uint32_t));;
        if(global_trusted_ip == NULL)
        {
            printlog(errno, "init_peer: malloc failed");
            return NULL;
        }
        else
            bzero(global_trusted_ip, (MAX_ID+1) * sizeof(uint32_t));
    }

    int i;
    int peer_num = MAX_ID+1;
    struct peer_profile_t ** p2 = (struct peer_profile_t **)malloc((MAX_ID+1) * sizeof(struct peer_profile_t*));
    if(p2 == NULL)
    {
        printlog(errno, "init_peer: malloc failed");
        free_peer(p2);
        p2 = NULL;
        return NULL;
    }
    else
        bzero(p2, (MAX_ID+1) * sizeof(struct peer_profile_t*));

    for(i = 0; i < peer_num; i++)
        p2[i] = NULL;

    int id = 0;
    char *id_str = NULL;
    char *psk_str = NULL;
    char *ip_str = NULL;
    char *ip6_str = NULL;
    char *port_str = NULL;

    size_t len = 1024;
    char *line = (char *)malloc(len);
    if(line == NULL)
    {
        printlog(errno, "init_peer: malloc failed");
        free_peer(p2);
        p2 = NULL;
        return NULL;
    }
    else
        bzero(line, len);

    while(-1 != getline(&line, &len, secrets_file))  //why line is an array of char*, not a char* ?
    {
        if(shrink_line(line) <= 1)
            continue;
        id_str = strtok(line, " ");
        psk_str = strtok(NULL, " ");
        ip_str = strtok(NULL, " ");
        ip6_str = strtok(NULL, " ");
        port_str = strtok(NULL, " ");

        if(NULL == id_str)
            continue;
        if(NULL == psk_str)
        {
            printlog(0, "Warning: PSK of ID %s not found, ignore this peer!\n", id_str);
            continue;
        }
        id = inet_ptons(id_str);
        if(0 == id)
        {
            printlog(0, "Warning: the ID of %s may be wrong, ignore this peer!\n", id_str);
            continue;
        }
        if(p2[id] != NULL)
            printlog(0, "Warning: the ID of %s may be duplicate, use the last one!\n", id_str);
        
        struct peer_profile_t * p1 = (struct peer_profile_t *)malloc(sizeof(struct peer_profile_t));
        if(p1 == NULL)
        {
            printlog(errno, "init_peer: malloc failed");
            free_peer(p2); 
            p2 = NULL;
            return NULL;
        }
        else
            bzero(p1, sizeof(struct peer_profile_t));

        p1->valid = true;

        p1->id = id;
        bzero(p1->psk, 2*AES_TEXT_LEN);
        strncpy((char*)p1->psk, psk_str, 2*AES_TEXT_LEN);

        if(port_str != NULL) //port_str must be parsed before ip, because servaddr.sin_port uses it.
        {
            int port = atoi(port_str);
            if(port < 1)
                printlog(0, "Warning: invalid PORT of peer: %s, ingore it's port value!\n", id_str);
            p1->port = port;
        }

        struct sockaddr_in * peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        if(peeraddr == NULL)
        {
            printlog(errno, "init_peer: malloc failed");
            free_peer(p2);
            p2 = NULL;
            return NULL;
        }
        else
            bzero(peeraddr, sizeof(struct sockaddr_in));

        if(ip_str != NULL && strcmp(ip_str, "none") != 0)
        {
            if(0 == inet_pton(AF_INET, ip_str, &peeraddr->sin_addr))
                printlog(0, "Warning: invalid IP of peer: %s, ingore it's IP/Port value!\n", id_str);
            else
            {
                peeraddr->sin_family = AF_INET;
                peeraddr->sin_port = htons(p1->port);
                p1->restricted = true;
                if(CHECK_RESTRICTED_IP)
                {
                    global_trusted_ip[global_trusted_ip_cnt] = peeraddr->sin_addr.s_addr;
                    global_trusted_ip_cnt++;
                }
            }
        }
        p1->peeraddr = peeraddr;

        if(ip6_str != NULL && strcmp(ip6_str, "none") != 0)
            printlog(0, "IPv6 not supported now, ignore it!\n");

        //p1->vip = (global_tunif.addr & global_tunif.mask) | htonl(id); //in network byte order.
        //p1->rip = 0;
        p1->vip = htonl(id); //0.0.x.x in network byte order, used inside tunnel.
        p1->rip = (global_tunif.addr & global_tunif.mask) | htonl(id); //in network byte order.

        p1->flow_src = (struct flow_profile_t *)malloc(sizeof(struct flow_profile_t));
        //p1->flow_dst = (struct flow_profile_t *)malloc(sizeof(struct flow_profile_t));
        //if(p1->flow_src == NULL || p1->flow_dst == NULL)
        if(p1->flow_src == NULL)
        {
            printlog(errno, "init_peer: malloc failed");
            free_peer(p2);
            p2 = NULL;
            return NULL;
        }
        else
        {
            bzero(p1->flow_src, sizeof(struct flow_profile_t));
            //bzero(p1->flow_dst, sizeof(struct flow_profile_t));
        }

        p1->flow_src->ba_pre = bit_array_create(SEQ_LEVEL_1);
        p1->flow_src->ba_now = bit_array_create(SEQ_LEVEL_1);
        //p1->flow_dst->ba_pre = bit_array_create(SEQ_LEVEL_1);
        //p1->flow_dst->ba_now = bit_array_create(SEQ_LEVEL_1);
        if(p1->flow_src->ba_pre == NULL || p1->flow_src->ba_now == NULL)
        //    || p1->flow_dst->ba_pre == NULL || p1->flow_dst->ba_now == NULL)
        {
            printlog(errno, "init_peer: malloc failed");
            free_peer(p2);
            p2 = NULL;
            return NULL;
        }
        bit_array_clearall(p1->flow_src->ba_pre);
        bit_array_clearall(p1->flow_src->ba_now);
        //bit_array_clearall(p1->flow_dst->ba_pre);
        //bit_array_clearall(p1->flow_dst->ba_now);

        p2[id] = p1;
    }
    free(line);

    if(NULL == p2[global_self_id])
    {
        printlog(0, "init peer error: didn't find self profile in secert file!\n");
        free_peer(p2);
        p2 = NULL;
        return NULL;
    }

    //p1->peeraddr = peeraddr;
    //p2[0] = p1;
    if(CHECK_RESTRICTED_IP)
        bubble_sort(global_trusted_ip, global_trusted_ip_cnt);

    return p2;
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

int free_peer(struct peer_profile_t **p2)
{
    if(CHECK_RESTRICTED_IP && global_trusted_ip != NULL)
        free(global_trusted_ip);

    if(NULL == p2)
        return 0;

    int peer_num = MAX_ID+1;
    
    int i;
    for(i = 0; i < peer_num; i++)
    {
        struct peer_profile_t *p1 = p2[i];
        if(p1 != NULL)
        {
            if(p1->flow_src != NULL)
            {
                bit_array_destroy(p1->flow_src->ba_pre);
                bit_array_destroy(p1->flow_src->ba_now);
                free(p1->flow_src);
            }
            //if(p1->flow_dst != NULL)
            //{
            //    bit_array_destroy(p1->flow_dst->ba_pre);
            //    bit_array_destroy(p1->flow_dst->ba_now);
            //    free(p1->flow_dst);
            //}
            if(p1->peeraddr != NULL)
                free(p1->peeraddr);
            free(p1);
        }
    }

    free(p2);
    return 0;
}

uint16_t do_csum(uint16_t old_sum, uint32_t old_ip, uint32_t new_ip)
{
    if(0 == old_sum)    //only in one case: UDP checksum not calculated; otherwise, checksum cann't be 0.
        return 0;

    old_ip = ~old_ip;
    old_ip = (old_ip >> 16) + (old_ip & 0x0000FFFF);
    old_ip = (old_ip >> 16) + (old_ip & 0x0000FFFF);

    new_ip = ~new_ip;
    new_ip = (new_ip >> 16) + (new_ip & 0x0000FFFF);
    new_ip = (new_ip >> 16) + (new_ip & 0x0000FFFF);

    uint32_t new_sum = 0x00010000 | (old_sum - 0x00000001);   //move one bit to left. old_sum must be bigger than 0.
    new_sum = new_sum - old_ip + new_ip;
    new_sum = (new_sum >> 16) + (new_sum & 0x0000FFFF);
    new_sum = (new_sum >> 16) + (new_sum & 0x0000FFFF);
    return new_sum;
}

int ip_dnat(byte* ip_load, uint32_t new_ip)
{
    uint16_t csum = 0;
    struct iphdr ip_h;
    memcpy(&ip_h, ip_load, IPV4_HEAD_LEN);
    if(ip_h.daddr == new_ip)
        return 0;
    memcpy(&ip_load[IPV4_OFFSET_DADDR], &new_ip, 4);
    csum = do_csum(ip_h.check, ip_h.daddr, new_ip);
    memcpy(&ip_load[IPV4_OFFSET_CSUM], &csum, 2);     //recalculated ip checksum
    //if packet is fragmented, can only recaculate the first fragment.
    //Because the following packets don't have a layer 4 header!
    if(6 == ip_h.protocol && (global_ipv4_mask_fragoff & ip_h.frag_off) == 0 )    //tcp
    {
        int csum_off = 4*ip_h.ihl + 16;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.daddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated tcp checksum
    }
    else if(17 == ip_h.protocol && (global_ipv4_mask_fragoff & ip_h.frag_off) == 0 )  //udp
    {
        int csum_off = 4*ip_h.ihl + 6;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.daddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated udp checksum
    }
    return 0;
}

int ip_snat(byte* ip_load, uint32_t new_ip)
{
    uint16_t csum = 0;
    struct iphdr ip_h;
    memcpy(&ip_h, ip_load, IPV4_HEAD_LEN);
    if(ip_h.saddr == new_ip)
        return 0;
    memcpy(&ip_load[IPV4_OFFSET_SADDR], &new_ip, 4);
    csum = do_csum(ip_h.check, ip_h.saddr, new_ip);
    memcpy(&ip_load[IPV4_OFFSET_CSUM], &csum, 2);     //recalculated ip checksum
    //if packet is fragmented, can only recaculate the first fragment.
    //Because the following packets don't have a layer 4 header!
    if(6 == ip_h.protocol && (global_ipv4_mask_fragoff & ip_h.frag_off) == 0 )    //tcp
    {
        int csum_off = 4*ip_h.ihl + 16;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.saddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated tcp checksum
    }
    else if(17 == ip_h.protocol && (global_ipv4_mask_fragoff & ip_h.frag_off) == 0 )  //udp
    {
        int csum_off = 4*ip_h.ihl + 6;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.saddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated udp checksum
    }
    return 0;
}

uint16_t get_next_hop_id(uint32_t ip_dst, uint32_t ip_src)
{
    uint16_t next_hop_id;
    next_hop_id = get_route(ip_dst, ip_src);
    if(0 == next_hop_id)
    {
        uint32_t next_hop_ip = get_sys_iproute(ip_dst, ip_src, global_if_list);
        //next_hop_ip is in tunif's subnet
        if((next_hop_ip & global_tunif.mask) == (global_tunif.addr & global_tunif.mask))
            next_hop_id = (uint16_t)ntohl(next_hop_ip);
        else  //this limits the use of ID 0.1, 0.1 cann't be used by any peer, it always indicates local.
            next_hop_id = 1;

        if(global_self_id == next_hop_id)
            next_hop_id = 1;
        add_route(next_hop_id, ip_dst, ip_src);
    }
    return next_hop_id;
}

void* watch_link_route(void *arg)
{
    char buf[8192];
    struct rtnl_handle_t rth;
    rth.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    bzero(&rth.local, sizeof(rth.local));
    rth.local.nl_family = AF_NETLINK;
    rth.local.nl_pid = getpid()+1;
    rth.local.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE | RTMGRP_IPV4_IFADDR | 
        RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR | 
        RTMGRP_NOTIFY;
    if(bind(rth.fd, (struct sockaddr*) &rth.local, sizeof(rth.local)) < 0)
    {
        printlog(errno, "rtnl_handle_t bind error");
        global_running = 0;
    }

    while(global_running)
        if(recv(rth.fd, buf, sizeof(buf), 0) )
            global_sysroute_change++;

    close(rth.fd);
    return NULL;
}

void* reset_link_route(void *arg)
{
    int pre = global_sysroute_change;
    while(global_running)
    {
        sleep(1);
        if(pre != global_sysroute_change)
        {
            printlog(0, "RTNETLINK: route changed!\n");

            if(clear_if_info(global_if_list) != 0)
                continue;
            else
                global_if_list = NULL;

            if(collect_if_info(&global_if_list) != 0)
                continue;

            //must clear if_info_t first, then clear_route
            if(clear_route() != 0)
                continue;

            printlog(0, "RTNETLINK: route table reset!\n");
            pre = global_sysroute_change;
        }
    }
    return NULL;
}

void* server_reset_stat(void *arg)
{
    struct peer_profile_t ** peer_table = (struct peer_profile_t **)arg;
    int peer_num = MAX_ID+1;
    //int pre = global_pkt_cnt;

    int i, j = 0;
    while(global_running)
    {
        sleep(RESET_STAT_INTERVAL);
        j++;
        for(i = 0; i < peer_num; i++)
        {
            struct peer_profile_t *p = peer_table[i];
            if(p != NULL)
            {
                if(pthread_spin_lock(&global_stat_spin) != 0)
                {
                    perror("pthread_spin_lock");
                    continue;
                }
                //if(pre != global_pkt_cnt)
                if(true)
                {
                    p->flow_src->dup_cnt = 0;
                    p->flow_src->delay_cnt = 0;
                    p->flow_src->replay_cnt = 0;
                    //p->flow_src->sys_time = time(NULL);
                    p->flow_src->time_min = 0;
                    p->flow_src->time_max = 0;
                    //p->flow_dst->dup_cnt = 0;
                    //p->flow_dst->delay_cnt = 0;
                    //p->flow_dst->replay_cnt = 0;
                    //printlog(0, "status count reset!\n");
                    //pre = global_pkt_cnt;
                }
                if(j%4 == 0 && p->flow_src->jump_cnt > 0)  //why 4? no why, it can be 5,6,7...100, any
                {
                    j++;
                    p->flow_src->jump_cnt = 0;
                    printlog(0, "jump status count reset!\n");
                }
                if(pthread_spin_unlock(&global_stat_spin) != 0)
                {
                    perror("pthread_spin_unlock");
                    continue;
                }
            }
        }
    }
    return NULL;
}

void* server_read(void *arg)
{
    struct tunnel_header_t header_send;
    struct peer_profile_t ** peer_table = (struct peer_profile_t **)arg;
    //uint16_t peerid = 0;
    uint16_t next_id = 0;
    uint16_t src_id;
    uint16_t dst_id;
    uint16_t bigger_id;
    struct sockaddr_in *peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    struct iphdr ip_h;
    uint16_t len_load, len_pad, nr_aes_block;
    byte buf_load[TUN_MTU];
    byte buf_send[ETH_MTU];
    byte buf_header[HEADER_LEN];
    byte * buf_psk;
    int i;
    for(i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    bzero(buf_load, TUN_MTU);

    while(global_running)
    {
        if( (len_load = read(global_tunfd, buf_load, TUN_MTU)) < 0 )
        {
            printlog(errno, "tunif %s read error", global_tunif.name);
            continue;
        }

        //printlog(0, "read:1 \n" );
        memcpy(&ip_h, buf_load, IPV4_HEAD_LEN);
        next_id = get_next_hop_id(ip_h.daddr, ip_h.saddr);
        //printlog(0, "in read: dest: %d\n", next_id);

        //peerid = (uint16_t)ntohl(ip_h.daddr);
        //peerid = next_id;
        if(NULL == peer_table[next_id] || 1 == next_id || global_self_id == next_id)
        {
            printlog(0, "tunif %s read packet to peer %d.%d: invalid peer!\n", global_tunif.name, next_id/256, next_id%256);
            continue;
        }
        if(NULL == peer_table[next_id]->peeraddr)
        {
            printlog(0, "tunif %s read packet to peer %d.%d: invalid addr!\n", global_tunif.name, next_id/256, next_id%256);
            continue;
        }
        memcpy(peeraddr, peer_table[next_id]->peeraddr, sizeof(struct sockaddr_in));

        //dst addr is in the same network with global_tunif
        bool dst_inside = ((ip_h.daddr & global_tunif.mask) == (global_tunif.addr & global_tunif.mask));
        //src addr is in the same network with global_tunif
        bool src_inside = ((ip_h.saddr & global_tunif.mask) == (global_tunif.addr & global_tunif.mask));
        //src addr is local tunif
        bool src_local = (ip_h.saddr == global_tunif.addr);
        
        //not supported now: read packet in tunif's subnet but ID mismatch
        if(src_inside != src_local)
        {
            printlog(0, "tunif %s read packet from other peer, ignore it!\n", global_tunif.name);
            continue;
        }
        else if(!dst_inside && !src_inside) //not supported now: outside IP to outside IP
        {
            printlog(0, "tunif %s read packet from outside net to outside net, ignore it!\n", global_tunif.name);
            continue;
        }  

        if(src_inside)
        {
            header_send.ttl_flag_random.bit.src_inside = true;
            //now src_id == global_self_id; but in the future, src_id may be other peer's id.
            src_id = ntohl(ip_h.saddr);
            ip_snat(buf_load, peer_table[src_id]->vip);
        }
        else
        {
            header_send.ttl_flag_random.bit.src_inside = false;
            src_id = global_self_id;
        }

        if(dst_inside)
        {
            header_send.ttl_flag_random.bit.dst_inside = true;
            dst_id = ntohl(ip_h.daddr);
            ip_dnat(buf_load, peer_table[dst_id]->vip);
        }
        else
        {
            header_send.ttl_flag_random.bit.dst_inside = false;
            dst_id = next_id;
        }
        bigger_id = dst_id > src_id ? dst_id : src_id;
        if(NULL == peer_table[bigger_id])
        {
            printlog(0, "tunif %s read packet of invalid peer: %d.%d!\n", global_tunif.name, bigger_id/256, bigger_id%256);
            continue;
        }

        buf_psk = peer_table[bigger_id]->psk;
        header_send.dst_id = htons(dst_id);
        header_send.src_id = htons(global_self_id);
        header_send.m_type_len.bit.m = HEAD_MORE_FALSE;
        header_send.m_type_len.bit.type = HEAD_TYPE_DATA;
        header_send.m_type_len.bit.len = len_load;
        header_send.m_type_len.u16 = htons(header_send.m_type_len.u16);
        header_send.ttl_flag_random.bit.ttl = TTL_MAX;
        header_send.ttl_flag_random.bit.random = random();
        header_send.ttl_flag_random.u16 = htons(header_send.ttl_flag_random.u16);
        uint32_t now = time(NULL);
        if(global_local_time == now)
        {
            global_local_seq++;
            //printf("-----------------local time is: %d\n", peer_table[next_id]->local_time);
            //printf("-----------------local seq is: %d\n", peer_table[next_id]->local_seq);
        }
        else
        {
            global_local_seq = 0;
            global_local_time = now;
        }

        header_send.time = htonl(now);
        header_send.seq_frag_off.bit.seq = global_local_seq;
        header_send.seq_frag_off.bit.frag = 0;
        header_send.seq_frag_off.bit.off = 0;
        header_send.seq_frag_off.u32 = htonl(header_send.seq_frag_off.u32);

        memcpy(buf_header, &header_send, HEADER_LEN);
        encrypt(buf_send, buf_header, global_buf_group_psk, AES_KEY_LEN);  //encrypt header with group PSK
        encrypt(&buf_send[HEADER_LEN], buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv

        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
        for(i=0; i<nr_aes_block; i++)
            encrypt(&buf_send[HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN], &buf_load[i*AES_TEXT_LEN], buf_psk, AES_KEY_LEN);

        len_pad = (len_load > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
        if(sendto(global_sockfd, buf_send, HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN + len_pad,
            0, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0 )
            printlog(errno, "tunif %s sendto next_id %d.%d socket error", global_tunif.name, next_id/256, next_id%256);
    }

    free(peeraddr);
    return NULL;
}

void* server_recv(void *arg)
{
    struct tunnel_header_t header_recv, header_send;
    struct peer_profile_t ** peer_table = (struct peer_profile_t **)arg;
    uint16_t next_id = 0;
    uint16_t dst_id = 0;
    uint16_t src_id = 0;
    uint16_t bigger_id = 0;
    uint ttl;
    struct sockaddr_in *peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    socklen_t peeraddr_len = sizeof(*peeraddr);
    struct iphdr ip_h;
    struct ip_dot_decimal_t ip_daddr;
    struct ip_dot_decimal_t ip_saddr;
    uint16_t len_load, nr_aes_block;
    uint nr_aes_block_ipv4_header = (IPV4_HEAD_LEN + TCP_HEAD_LEN + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
    int i;
    byte * buf_psk;
    byte buf_recv[ETH_MTU];
    byte buf_load[TUN_MTU];
    //byte buf_send[TUN_MTU];
    byte buf_header[HEADER_LEN];
    byte buf_icv[ICV_LEN];
    //printlog(0, "global_self_id: %d\n", global_self_id);

    while(global_running)
    {
        if(recvfrom(global_sockfd, buf_recv, ETH_MTU, 0, (struct sockaddr *)peeraddr, &peeraddr_len) < HEADER_LEN+ICV_LEN)
        {
            printlog(errno, "tunif %s recvfrom socket error", global_tunif.name);
            continue;
        }

        decrypt(buf_header, buf_recv, global_buf_group_psk, AES_KEY_LEN);  //decrypt header with group PSK
        memcpy(&header_recv, buf_header, HEADER_LEN);
        memcpy(&header_send, &header_recv, sizeof(struct tunnel_header_t));
        //header_recv.time = ntohl(header_recv.time);
        
        dst_id = ntohs(header_recv.dst_id);
        src_id = ntohs(header_recv.src_id);
        bigger_id = dst_id > src_id ? dst_id : src_id;

        if(NULL == peer_table[bigger_id] || peer_table[bigger_id]->valid == false)
        {
            printlog(0, "tunif %s received packet from %d.%d to %d.%d: invalid peer: %d.%d!\n", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, bigger_id/256, bigger_id%256);
            continue;
        }
        //if(bigger_id != global_self_id && NULL == peer_table[bigger_id])
        if(src_id == 0 || src_id == 1 || src_id == global_self_id)
        {
            printlog(0, "tunif %s received packet from %d.%d to %d.%d: invalid src_id!\n", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }
        if(CHECK_RESTRICTED_IP && peer_table[src_id] != NULL && peer_table[src_id]->restricted == true)
        {
            //if dst_id == global_self_id, don't ckeck but write to tunif
            if(dst_id != global_self_id && binary_search(global_trusted_ip, 0, global_trusted_ip_cnt, peeraddr->sin_addr.s_addr) == -1)
            {
                printlog(0, "tunif %s received packet from %d.%d to %d.%d: src_id addr not trusted!\n", 
                    global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
                continue;
            }
        }

        buf_psk = peer_table[bigger_id]->psk;

        encrypt(buf_icv, buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv
        if(strncmp((char*)buf_icv, (char*)&buf_recv[HEADER_LEN], ICV_LEN) != 0)
        {
            printlog(0, "tunif %s received packet from %d.%d to %d.%d: icv doesn't match!\n", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }
        //store the src's UDP socket only when src_id is bigger.
        //otherwise, the bigger id may forge any smaller id's source address.
        if(src_id > dst_id)
            memcpy(peer_table[src_id]->peeraddr, peeraddr, sizeof(struct sockaddr_in));

        header_recv.m_type_len.u16 = ntohs(header_recv.m_type_len.u16);
        len_load = header_recv.m_type_len.bit.len;
        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
        header_recv.ttl_flag_random.u16 = ntohs(header_recv.ttl_flag_random.u16);
        ttl = header_recv.ttl_flag_random.bit.ttl;
        uint32_t pkt_time = ntohl(header_recv.time);
        header_recv.seq_frag_off.u32 = ntohl(header_recv.seq_frag_off.u32);
        uint32_t pkt_seq = header_recv.seq_frag_off.bit.seq;
        //printf("pkt_time: %d\n", pkt_time);
        //printf("pkt_seq : %d\n", pkt_seq);
        if(pthread_spin_lock(&global_stat_spin) != 0)
        {
            perror("pthread_spin_lock");
            continue;
        }
        int fs = flow_filter(pkt_time, pkt_seq, src_id, dst_id, peer_table);
        if(pthread_spin_unlock(&global_stat_spin) != 0)
        {
            perror("pthread_spin_unlock");
            continue;
        }
        if(fs == -2)
            printlog(0, "tunif %s received packet from %d.%d to %d.%d: replay limit exceeded!\n", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
        if(fs == -6)
        {
            printlog(0, "tunif %s received packet from %d.%d to %d.%d: replay limit exceeded!\n", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            printlog(0, "tunif %s set peer %d.%d to invalid: involve limit exceeded!\n", 
                global_tunif.name, dst_id/256, dst_id%256);
        }
        if(fs == -3)
            printlog(0, "tunif %s received packet from %d.%d to %d.%d: time jump limit exceeded!\n", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
        if(fs == -5)
        {
            printlog(0, "tunif %s received packet from %d.%d to %d.%d: time jump limit exceeded!\n", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            printlog(0, "tunif %s set peer %d.%d to invalid: involve limit exceeded!\n", 
                global_tunif.name, dst_id/256, dst_id%256);
        }
        if(fs < 0)
            continue;

        for(i=0; i<nr_aes_block_ipv4_header; i++)
            decrypt(&buf_load[i*AES_TEXT_LEN], &buf_recv[HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN], buf_psk, AES_KEY_LEN);
        
        memcpy(&ip_h, buf_load, IPV4_HEAD_LEN);
        memcpy(&ip_saddr, &ip_h.saddr, sizeof(uint32_t));
        memcpy(&ip_daddr, &ip_h.daddr, sizeof(uint32_t));

        uint32_t daddr, saddr; //network byte order

        //if(0 != src_id)
        //src_inside
        if(header_recv.ttl_flag_random.bit.src_inside == true)
        {
            saddr = (global_tunif.addr & global_tunif.mask) | ip_h.saddr;
            ip_snat(buf_load, saddr);
        }
        else
            saddr = ip_h.saddr;

        //if(0 != dst_id)
        //dst_inside
        if(header_recv.ttl_flag_random.bit.dst_inside == true)
        {
            daddr = (global_tunif.addr & global_tunif.mask) | ip_h.daddr;
            ip_dnat(buf_load, daddr);
            next_id = dst_id;
        }
        else
        {
            daddr = ip_h.daddr;
            next_id = get_next_hop_id(daddr, saddr);
        }

        bool dst_inside = ((daddr & global_tunif.mask) == (global_tunif.addr & global_tunif.mask));
        if(header_recv.ttl_flag_random.bit.dst_inside == false && dst_inside == true)
        {
            printlog(0, "tunif %s received packet from %d.%d to %d.%d: probe packet, drop it!\n", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }

        if(0 == next_id)
        {
            printlog(0, "tunif %s received packet from %d.%d to %d.%d: no route!\n", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }
        else if(1 == next_id || global_self_id == next_id) //write to local tunif
        {
            for(i=nr_aes_block_ipv4_header; i<nr_aes_block; i++)
                decrypt(&buf_load[i*AES_TEXT_LEN], &buf_recv[HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN], buf_psk, AES_KEY_LEN);

            if(write(global_tunfd, &buf_load, len_load) < 0)
                printlog(errno, "tunif %s write error", global_tunif.name);
            continue;
        }
        else  //switch to next_id or dst_id
        //if( (0 == dst_id && 1 != next_id) || (0 != dst_id && global_self_id != dst_id) )
        {
            //packet dst is not local and ttl expire, drop packet. only allow 16 hops
            if(TTL_MIN == ttl)
            {
                printlog(0, "TTL expired! from %d.%d.%d.%d to %d.%d.%d.%d\n",
                    ip_saddr.a, ip_saddr.b, ip_saddr.c, ip_saddr.d,
                    ip_daddr.a, ip_daddr.b, ip_daddr.c, ip_daddr.d);   
                continue;
            }

            if(ALLOW_P2P != true)
                if(header_recv.ttl_flag_random.bit.src_inside == true && header_recv.ttl_flag_random.bit.dst_inside == true)
                {
                    printlog(0, "tunif %s received packet from %d.%d to %d.%d: p2p not allowed!\n", 
                        global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
                    continue;
                }

            //if(dst_id != 0)
            //    next_id = dst_id;

            if(NULL == peer_table[next_id])
            {
                printlog(0, "tunif %s recv packet from %d.%d to %d.%d: route to invalid next peer: %d.%d!\n", 
                    global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, next_id/256, next_id%256);
                continue;
            }
            if(NULL == peer_table[next_id]->peeraddr)
            {
                printlog(0, "tunif %s recv packet from %d.%d to %d.%d: route to next peer %d.%d: invalid addr!\n", 
                    global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, next_id/256, next_id%256);
                continue;
            }

            //split horizon
            //i don't want to compare port here, thus prevent two peers in the same NAT gw from seeing each other.
            if(peeraddr->sin_addr.s_addr == peer_table[next_id]->peeraddr->sin_addr.s_addr &&
                peeraddr->sin_port == peer_table[next_id]->peeraddr->sin_port)
            {
                printlog(0, "tunif %s recv packet from %d.%d to %d.%d: next peer is %d.%d, dst addr equals src addr!\n", 
                    global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, next_id/256, next_id%256);
                continue;
            }
            else
                memcpy(peeraddr, peer_table[next_id]->peeraddr, sizeof(struct sockaddr_in));

            ttl--;
            header_send.ttl_flag_random.bit.ttl = ttl;
            header_send.ttl_flag_random.bit.src_inside = header_recv.ttl_flag_random.bit.src_inside;
            header_send.ttl_flag_random.bit.dst_inside = header_recv.ttl_flag_random.bit.dst_inside;
            header_send.ttl_flag_random.bit.random = random();
            header_send.ttl_flag_random.u16 = htons(header_send.ttl_flag_random.u16);

            memcpy(buf_header, &header_send, HEADER_LEN);
            encrypt(buf_recv, buf_header, global_buf_group_psk, AES_KEY_LEN);  //encrypt header with group PSK
            encrypt(&buf_recv[HEADER_LEN], buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv

            int len_pad = (len_load > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
            if(sendto(global_sockfd, buf_recv, HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN + len_pad,
                0, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0 )
                printlog(errno, "tunif %s sendto next_id %d.%d socket error", global_tunif.name, next_id/256, next_id%256);
            continue;
        }
    }

    free(peeraddr);
    return NULL;
}

//need to filter 2 elements:pkt_time and pkt_seq;
//pkt_time can NOT run too fast, if faster than system, let's call it a jump. if too many jumps, then it may be an attack.
//pkt_seq can NOT duplicate.
int flow_filter(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, struct peer_profile_t ** peer_table)
{
    //there should be an spin lock
    global_pkt_cnt++;
    struct flow_profile_t * fp = NULL;

    if(src_id == dst_id || 0 == src_id)
        return -1;
    else if(NULL == peer_table[src_id])
        return -1;
    else
        fp = peer_table[src_id]->flow_src;

    if(peer_table[src_id] == NULL || peer_table[dst_id] == NULL)
        return -1;

    if(fp->time_min == 0)
        fp->time_min = pkt_time;
    else
        fp->time_min = pkt_time < fp->time_min ? pkt_time : fp->time_min;
    if(fp->time_max == 0)
        fp->time_max = pkt_time;
    else
        fp->time_max = pkt_time > fp->time_max ? pkt_time : fp->time_max;
    if( (fp->time_max - fp->time_min) > (RESET_STAT_INTERVAL + MAX_DELAY_TIME) )
    {
        fp->jump_cnt++;
        fp->time_max = 0;
        fp->time_min = 0;
        if(fp->jump_cnt == JUMP_CNT_LIMIT)
        {
            if(src_id < dst_id)
            {
                peer_table[dst_id]->involve_cnt++;
                if(peer_table[dst_id]->involve_cnt > INVOLVE_CNT_LIMIT)
                {
                    peer_table[dst_id]->valid = false;
                    return -5;
                }
            }
            return -3;
        }
    }
    if(fp->jump_cnt >= JUMP_CNT_LIMIT)
        return -4;

    int time_diff = pkt_time - fp->time_now;
    if(time_diff >= 2)
    {
        bit_array_clearall(fp->ba_pre);
        bit_array_clearall(fp->ba_now);
        fp->time_now = pkt_time;
        fp->time_pre = pkt_time - 1;
        bit_array_set(fp->ba_now, pkt_seq);
    }
    else if(time_diff == 1)
    {
        fp->time_pre = fp->time_now;
        fp->time_now = pkt_time;

        struct bit_array_t * ba_tmp;
        ba_tmp = fp->ba_pre;
        fp->ba_pre = fp->ba_now;
        fp->ba_now = ba_tmp;

        bit_array_clearall(fp->ba_now);
        bit_array_set(fp->ba_now, pkt_seq);
    }
    else if(time_diff == 0)
    {
        if(bit_array_get(fp->ba_now, pkt_seq) == 1)
        {
            //printf("packet duplicate!\n");
            fp->dup_cnt++;
            return -1;
        }
        else
            bit_array_set(fp->ba_now, pkt_seq);
    }
    else if(time_diff == -1)
    {
        if(bit_array_get(fp->ba_pre, pkt_seq) == 1)
        {
            //printf("packet duplicate!\n");
            fp->dup_cnt++;
            return -1;
        }
        else
            bit_array_set(fp->ba_pre, pkt_seq);
    }
    else if(time_diff <= -MAX_DELAY_TIME) //why? let's assume max packet delay is MAX_DELAY_TIME seconds.
    {
        fp->replay_cnt++;
        //global_pkt_cnt++;
        if(fp->replay_cnt == REPLAY_CNT_LIMIT)  //if replay_cnt is beyond REPLAY_CNT_LIMIT, drop replay packets.
        {
            if(src_id < dst_id)
            {
                peer_table[dst_id]->involve_cnt++;
                if(peer_table[dst_id]->involve_cnt > INVOLVE_CNT_LIMIT)
                {
                    peer_table[dst_id]->valid = false;
                    return -6;
                }
            }
            return -2;
        }
        if(fp->replay_cnt > REPLAY_CNT_LIMIT)
            return -1;
        bit_array_clearall(fp->ba_pre);
        bit_array_clearall(fp->ba_now);
        fp->time_now = pkt_time;
        fp->time_pre = pkt_time - 1;
        bit_array_set(fp->ba_now, pkt_seq);
    }
    else    // -9 <= time_diff <= -2, just drop it
    {
        fp->delay_cnt++;
        return -1;
    }

    if(fp->replay_cnt >= REPLAY_CNT_LIMIT)
        return -1;
    return 0;
}
