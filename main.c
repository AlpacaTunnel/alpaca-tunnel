#include "aes.h"
#include "route.h"

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

#define TUN_NETMASK 0xFFFF0000
//tunnel MTU must not be greater than 1440
#define TUN_MTU 1440
#define ETH_MTU 1500
//strlen of ipv4 address, including two quotation marks, must be larger than 16
#define IPV4_LEN 32
//length of aes key must be 128, 192 or 256
#define AES_KEY_LEN 128
#define DEFAULT_PORT 1984

#define HEADER_LEN 16
#define ICV_LEN 16
/*
  all data in header are stored in network bit/byte order.
  the id in packet header is always the sender's id.
*/
struct tunnel_header
{
    uint16_t id;  //sender's ID
    uint16_t m_type_len;
    uint32_t time;
    uint32_t seq_frag_off;
    uint32_t padding;
};

#define HEAD_MASK_MORE 0x8000
#define HEAD_MASK_TYPE 0x7800
#define HEAD_MASK_LEN  0x07FF
#define HEAD_MASK_SEQ  0xFFFFFF00
#define HEAD_MASK_FRAG 0x00000080
#define HEAD_MASK_OFF  0x0000007F

#define HEAD_MORE_FALSE 0x0000
#define HEAD_MORE_TRUE  0x8000
#define HEAD_TYPE_DATA  0x0000
#define HEAD_TYPE_MSG   0x0800
#define HEAD_FRAG_FALSE 0x00000000
#define HEAD_FRAG_TRUE  0x00000080
#define IPV4_HEAD_LEN 20
#define OFFSET_IPV4_CSUM 10
#define OFFSET_IPV4_SADDR 12
#define OFFSET_IPV4_DADDR 16
#define OFFSET_IPV4_FRAGOFF 0x1FFF  //in host byte order
#define INTER_SWITCH_NET 0x7FFF0000  //127.255.0.0 in host byte order
#define BETWEEN_TUN_NET 0x7F000000  //127.0.0.0 in host byte order

#define WRITE_BUF_SIZE 50000000
#define SEND_BUF_SIZE 50000000

#define NAT_BOUND 4095  //15.255
#define MAX_SERVER_ID 4095  //15.255
#define MAX_ID 65535
//reserved ID: 0.0, 0.1, 255.255, any server/client cann't use.

struct ip_dot_decimal   //in network byte order
{
    byte a;
    byte b;
    byte c;
    byte d;
} __attribute__((packed));

struct packet_profile
{
    uint16_t from_peer;
    uint16_t to_peer;
    uint16_t psk_peer;
    byte packet[ETH_MTU];
    int len;
};

//data struct of peers in memory.
struct peer_profile
{
    uint16_t id;
    bool valid;
    bool dup;   //when set, packet will be double sent.
    uint16_t srtt;
    uint32_t time;
    uint32_t seq;
    uint32_t * pre;
    uint32_t * now;
    byte psk[2*AES_TEXT_LEN];
    struct sockaddr_in *peeraddr;   //peer IP
    int port;   //peer port
    uint32_t vip;   //virtual client ip
    uint32_t inter_vip;   //virtual client ip, used for internal switch
    uint32_t rip;   //real client ip, will be NATed to vip
};

//client_read and client_recv are only for demostrating
void* client_read(void *arg);
void* client_recv(void *arg);

void* server_read(void *arg);
void* server_recv(void *arg);
void* server_write(void *arg);
void* server_send(void *arg);
void* watch_link_route(void *arg);
void* reset_link_route(void *arg);
int tun_alloc(char *dev, int flags); 
int printlog(int en, char* format, ...);
int usage(char *pname);
struct peer_profile** init_peer(FILE *secrets_file);
int free_peer(struct peer_profile **p2);
void sig_handler(int signum);
uint16_t do_csum(uint16_t old_sum, uint32_t old_ip, uint32_t new_ip);
int ip_dnat(byte* ip_load, uint32_t new_ip);
int ip_snat(byte* ip_load, uint32_t new_ip);
int16_t inet_ptons(char *a);   //convert 15.255 to 4095
int shrink_line(char *line);

static int global_running = 0;
static int global_sysroute_change = 0;
static uint16_t global_self_id = 0;

//in network byte order.
struct if_info global_tunif;
uint16_t global_offset_ipv4_fragoff;
uint32_t global_inter_switch_net;
uint32_t global_between_tun_net;
int global_packet_cnt_write = 0;
int global_packet_cnt_send = 0;

enum {none, server, client, middle} global_mode = none;
byte global_buf_group_psk[2*AES_TEXT_LEN] = "FUCKnimadeGFW!";
int global_tunfd, global_sockfd;
extern struct if_info *global_if_list;

pthread_spinlock_t route_spin;

int usage(char *pname)
{
    printf("Usage: %s [-p port] [-g group] [-n id] [-i tun]\n", pname);
    return 0;
}

int main(int argc, char *argv[])
{
    /*    
    for(int ii=1; ii<RT_TB_SIZE+1; ii++)
        add_route(ii,ii,ii);
    
    int nid = get_route(123, 123);
    printf("%d\n", nid);
    struct sockaddr_in t1, t2;
    inet_pton(AF_INET, argv[1], &t1.sin_addr);
    inet_pton(AF_INET, argv[2], &t2.sin_addr);

    //reset_link();
    extern struct if_info *global_if_list;
    
    collect_if_info(&global_if_list);
    clear_if_info(global_if_list);
    global_if_list = NULL;

    collect_if_info(&global_if_list);

    int if2 = get_ipiif(t2.sin_addr.s_addr);
    int i1 = get_sys_iproute(t1.sin_addr.s_addr, t2.sin_addr.s_addr, if2);
    struct timeval stop, start;

    gettimeofday(&start, NULL);
    int n3 = get_next_hop_id(t1.sin_addr.s_addr, t2.sin_addr.s_addr);
    gettimeofday(&stop, NULL);

    printf("i1: %d\n", i1);
    printf("if2: %d\n", if2);
    printf("n3: %d\n", n3);

    printf("took %lu\n", stop.tv_sec - start.tv_sec);
    printf("took %lu\n", stop.tv_usec - start.tv_usec);
    */

    //printf("sizeof packet_profile: %d\n", sizeof(struct packet_profile));
    //printlog(0, "%d %d\n", 1, 2);
    //printlog(2, "%s %s", "a", "b");
    pthread_spin_init(&route_spin, PTHREAD_PROCESS_PRIVATE);
    global_if_list = NULL;
    collect_if_info(&global_if_list);
    global_offset_ipv4_fragoff = htons(OFFSET_IPV4_FRAGOFF);
    global_inter_switch_net = htonl(INTER_SWITCH_NET);
    global_between_tun_net = htonl(BETWEEN_TUN_NET);
    global_running = 1;

    int rc1=0, rc2=0, rc5=0, rc6=0;
    //uint16_t clid = 0;
    struct peer_profile ** peer_table = NULL;
    pthread_t tid1=0, tid2=0, tid5=0, tid6=0;
    struct sockaddr_in servaddr;
    int port = DEFAULT_PORT;
    char tun_name[IFNAMSIZ] = "\0";
    byte buf_psk[2*AES_TEXT_LEN] = "\0";
    char exe_path[PATH_LEN] = "\0";
    char secrets_path[PATH_LEN] = "\0";

    int opt;
    while((opt = getopt(argc, argv, "p:g:n:i:")) != -1)
    {
        switch(opt)
        {
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
    global_tunif.mask = get_ipmask(global_tunif.addr);
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
    peer_table[0]->id = global_self_id;
    memcpy(peer_table[0]->psk, buf_psk, 2*AES_TEXT_LEN);

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
        pause();

    pthread_cancel(tid1);
    pthread_cancel(tid2);
    pthread_cancel(tid5);
    pthread_cancel(tid6);
    //pthread_join(tid1, NULL);
    //pthread_join(tid2, NULL);
    //pthread_join(tid3, NULL);
_END:
    global_running = 0;
    pthread_spin_destroy(&route_spin);
    close(global_sockfd);
    close(global_tunfd);
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

struct peer_profile** init_peer(FILE *secrets_file)
{
    if(NULL == secrets_file)
        return NULL;

    int i;
    int peer_num = MAX_ID+1;
    struct peer_profile ** p2 = (struct peer_profile **)malloc((MAX_ID+1) * sizeof(struct peer_profile*));
    if(p2 == NULL)
    {
        printlog(errno, "init_peer: malloc failed");
        return NULL;
    }
    for(i = 0; i < peer_num; i++)
        p2[i] = NULL;

    struct peer_profile * p1 = (struct peer_profile *)malloc(sizeof(struct peer_profile));
    if(p1 == NULL)
    {
        printlog(errno, "init_peer: malloc failed");
        free_peer(p2); 
        p2 = NULL;
        return NULL;
    }
    p1->valid = true;

    struct sockaddr_in * peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    if(peeraddr == NULL)
    {
        printlog(errno, "init_peer: malloc failed");
        free_peer(p2);
        p2 = NULL;
        return NULL;
    }

    int id = 0;
    char *id_str = NULL;
    char *psk = NULL;
    char *ip = NULL;
    char *ip6 = NULL;
    char *port_str = NULL;

    size_t len = 1024;
    char *line = (char *)malloc(len);
    while(-1 != getline(&line, &len, secrets_file))  //why line is an array of char*, not a char* ?
    {
        if(shrink_line(line) <= 1)
            continue;
        id_str = strtok(line, " ");
        psk = strtok(NULL, " ");
        ip = strtok(NULL, " ");
        ip6 = strtok(NULL, " ");
        port_str = strtok(NULL, " ");

        if(NULL == id_str)
            continue;
        if(NULL == psk)
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
        p1->id = id;
        bzero(p1->psk, 2*AES_TEXT_LEN);
        strncpy((char*)p1->psk, psk, 2*AES_TEXT_LEN);
        
        struct sockaddr_in * tmpaddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        if(tmpaddr == NULL)
        {
            printlog(errno, "init_peer: malloc failed");
            free_peer(p2);
            p2 = NULL;
            return NULL;
        }

        if(port_str != NULL) //port_str must be parsed before ip, because servaddr.sin_port uses it.
        {
            int port = atoi(port_str);
            if(port < 1)
                printlog(0, "Warning: invalid PORT of peer: %s, ingore it's port value!\n", id_str);
            p1->port = port;
        }

        if(ip != NULL && strcmp(ip, "none") != 0)
        {
            struct sockaddr_in servaddr = *peeraddr;
            if(0 == inet_pton(AF_INET, ip, &servaddr.sin_addr))
                printlog(0, "Warning: invalid IP of peer: %s, ingore it's IP value!\n", id_str);
            servaddr.sin_family = AF_INET;
            servaddr.sin_port = htons(p1->port);
            memcpy(tmpaddr, &servaddr, sizeof(struct sockaddr_in));
        }
        p1->peeraddr = tmpaddr;

        if(ip6 != NULL && strcmp(ip6, "none") != 0)
            printlog(0, "IPv6 not supported now, ignore it!\n");

        p1->vip = (global_tunif.addr & global_tunif.mask) | htonl(id); //in network byte order.
        p1->inter_vip = (global_inter_switch_net & global_tunif.mask) | htonl(id); //in network byte order.
        p1->rip = 0;

        struct peer_profile * tmp1 = (struct peer_profile *)malloc(sizeof(struct peer_profile));
        if(tmp1 == NULL)
        {
            printlog(errno, "init_peer: malloc failed");
            free_peer(p2);
            p2 = NULL;
            return NULL;
        }
        memcpy(tmp1, p1, sizeof(struct peer_profile));
        p2[id] = tmp1;
    }
    free(line);

    if(NULL == p2[global_self_id])
    {
        printlog(0, "init peer error: didn't find self profile in secert file!\n");
        free_peer(p2);
        p2 = NULL;
        return NULL;
    }

    p1->peeraddr = peeraddr;
    p2[0] = p1;

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

int free_peer(struct peer_profile **p2)
{
    if(NULL == p2)
        return 0;

    int peer_num = MAX_ID+1;
    
    int i;
    for(i = 0; i < peer_num; i++)
        if(p2[i] != NULL)
        {
            free(p2[i]->peeraddr);
            free(p2[i]);
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
    memcpy(&ip_load[OFFSET_IPV4_DADDR], &new_ip, 4);
    csum = do_csum(ip_h.check, ip_h.daddr, new_ip);
    memcpy(&ip_load[OFFSET_IPV4_CSUM], &csum, 2);     //recalculated ip checksum
    //if packet is fragmented, can only recaculate the first fragment.
    //Because the following packets don't have a layer 4 header!
    if(6 == ip_h.protocol && (global_offset_ipv4_fragoff & ip_h.frag_off) == 0 )    //tcp
    {
        int csum_off = 4*ip_h.ihl + 16;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.daddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated tcp checksum
    }
    else if(17 == ip_h.protocol && (global_offset_ipv4_fragoff & ip_h.frag_off) == 0 )  //udp
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
    memcpy(&ip_load[OFFSET_IPV4_SADDR], &new_ip, 4);
    csum = do_csum(ip_h.check, ip_h.saddr, new_ip);
    memcpy(&ip_load[OFFSET_IPV4_CSUM], &csum, 2);     //recalculated ip checksum
    //if packet is fragmented, can only recaculate the first fragment.
    //Because the following packets don't have a layer 4 header!
    if(6 == ip_h.protocol && (global_offset_ipv4_fragoff & ip_h.frag_off) == 0 )    //tcp
    {
        int csum_off = 4*ip_h.ihl + 16;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.saddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated tcp checksum
    }
    else if(17 == ip_h.protocol && (global_offset_ipv4_fragoff & ip_h.frag_off) == 0 )  //udp
    {
        int csum_off = 4*ip_h.ihl + 6;
        memcpy(&csum, ip_load+csum_off, 2);
        csum = do_csum(csum, ip_h.saddr, new_ip);
        memcpy(ip_load+csum_off, &csum, 2);    //recalculated udp checksum
    }
    return 0;
}

void* client_read(void *arg)
{
    struct tunnel_header header_send;
    struct peer_profile * peer_table = (struct peer_profile *)arg;
    uint16_t peerid = 0;
    struct iphdr ip_h;
    struct sockaddr_in *peeraddr = peer_table[peerid].peeraddr;
    uint16_t len_load, len_pad, nr_aes_block;
    byte buf_load[TUN_MTU];
    byte buf_send[ETH_MTU];
    byte buf_header[HEADER_LEN];
    int i;
    srandom(time(NULL));
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

        memcpy(&ip_h, buf_load, IPV4_HEAD_LEN);
        peerid = get_next_hop_id(ip_h.daddr, ip_h.saddr);
        
        if(false == peer_table[peerid].valid || 1 == peerid || global_self_id == peerid)
        {
            printlog(0, "tunif %s read packet to peer %d.%d: invalid peer!\n", global_tunif.name, peerid/256, peerid%256);
            continue;
        }

        header_send.id = htons(peer_table[peerid].id);
        header_send.m_type_len = 0;
        header_send.m_type_len |= ( HEAD_MASK_MORE & HEAD_MORE_FALSE );
        header_send.m_type_len |= ( HEAD_MASK_TYPE & HEAD_TYPE_DATA  );
        header_send.m_type_len |= ( HEAD_MASK_LEN & len_load );
        header_send.m_type_len = htons(header_send.m_type_len);
        header_send.time = htonl(time(NULL));
        header_send.padding = random();

        memcpy(buf_header, &header_send, HEADER_LEN);
        //encrypt header with group PSK
        encrypt(buf_send, buf_header, global_buf_group_psk, AES_KEY_LEN);
        //encrypt header to generate icv
        encrypt(&buf_send[HEADER_LEN], buf_header, peer_table[peerid].psk, AES_KEY_LEN);

        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
        for(i=0; i<nr_aes_block; i++)
            encrypt(&buf_send[HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN], 
                &buf_load[i*AES_TEXT_LEN], peer_table[peerid].psk, AES_KEY_LEN);

        len_pad = (len_load > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
        if(sendto(global_sockfd, buf_send, HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN + len_pad, \
            0, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0 )
            printlog(errno, "tunif %s sendto socket error", global_tunif.name);
    }

    return NULL;
}

void* client_recv(void *arg)
{
    struct tunnel_header header_recv;
    struct peer_profile * peer_table = (struct peer_profile *)arg;
    uint16_t peerid = 0;
    struct sockaddr_in *peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    socklen_t peeraddr_len = sizeof(*peeraddr);
    uint16_t len_load, nr_aes_block;
    int i;
    byte buf_recv[ETH_MTU];
    byte buf_load[TUN_MTU];
    byte buf_header[HEADER_LEN];
    byte buf_icv[ICV_LEN];

    while(global_running)
    {
        if(recvfrom(global_sockfd, buf_recv, ETH_MTU, 0, (struct sockaddr *)peeraddr, &peeraddr_len) < HEADER_LEN+ICV_LEN)
        {
            printlog(errno, "tunif %s recvfrom socket error", global_tunif.name);
            continue;
        }

        decrypt(buf_header, buf_recv, global_buf_group_psk, AES_KEY_LEN);  //decrypt header with group PSK
        memcpy(&header_recv, buf_header, HEADER_LEN);
        //header_recv.time = ntohl(header_recv.time);

        encrypt(buf_icv, buf_header, peer_table[peerid].psk, AES_KEY_LEN);  //encrypt header to generate icv
        if(strncmp((char*)buf_icv, (char*)&buf_recv[HEADER_LEN], ICV_LEN) != 0)
        {
            printlog(0, "tunif %s icv doesn't match!\n", global_tunif.name);
            continue;
        }

        header_recv.m_type_len = ntohs(header_recv.m_type_len);
        len_load = HEAD_MASK_LEN & header_recv.m_type_len;
        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;

        for(i=0; i<nr_aes_block; i++)
            decrypt(&buf_load[i*AES_TEXT_LEN], 
                &buf_recv[HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN], peer_table[peerid].psk, AES_KEY_LEN);

        if(write(global_tunfd, &buf_load, len_load) < 0 )
            printlog(errno, "tunif %s write error", global_tunif.name);
    }

    free(peeraddr);
    return NULL;
}

void* watch_link_route(void *arg)
{
    char buf[8192];
    struct rtnl_handle rth;
    rth.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    bzero(&rth.local, sizeof(rth.local));
    rth.local.nl_family = AF_NETLINK;
    rth.local.nl_pid = getpid()+1;
    rth.local.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY;
    bind(rth.fd, (struct sockaddr*) &rth.local, sizeof(rth.local));
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
            clear_if_info(global_if_list);
            global_if_list = NULL;
            collect_if_info(&global_if_list);
            //must clear if_info first
            clear_route();
            printlog(0, "RTNETLINK: route changed!\n");
            pre = global_sysroute_change;
        }
    }
    return NULL;
}

void* server_read(void *arg)
{
    struct tunnel_header header_send;
    struct peer_profile ** peer_table = (struct peer_profile **)arg;
    uint16_t peerid = 0;
    uint16_t next_id = 0;
    struct sockaddr_in *peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    struct iphdr ip_h;
    uint16_t len_load, len_pad, nr_aes_block;
    byte buf_load[TUN_MTU];
    byte buf_send[ETH_MTU];
    byte buf_header[HEADER_LEN];
    byte * buf_psk;
    int i;
    srandom(time(NULL));
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
        peerid = next_id;
        if(NULL == peer_table[peerid] || 1 == peerid || global_self_id == peerid)
        {
            printlog(0, "tunif %s read packet to peer %d.%d: invalid peer!\n", global_tunif.name, peerid/256, peerid%256);
            continue;
        }
        if(NULL == peer_table[peerid]->peeraddr)
        {
            printlog(0, "tunif %s read packet to peer %d.%d: invalid addr!\n", global_tunif.name, peerid/256, peerid%256);
            continue;
        }
        memcpy(peeraddr, peer_table[peerid]->peeraddr, sizeof(struct sockaddr_in));

        //daddr is in the same network with global_tunif
        if((ip_h.daddr & global_tunif.mask) == (global_tunif.addr & global_tunif.mask))
        {
            if(ip_h.saddr == global_tunif.addr)  //saddr is local tunif
            {
                //printlog(0, "sent from local tunif\n");
                uint32_t rip = htonl(peerid) | global_between_tun_net;     //apply dnat, daddr is 127.0.x.x
                ip_dnat(buf_load, rip);
            }
            else //saddr is NOT local tunif, traffic passing by
            {
                uint32_t rip = peer_table[peerid]->rip;  //real ip is stored in network byte order.
                ip_dnat(buf_load, rip);
            }
        }
        
        if(peerid > global_self_id)
            buf_psk = peer_table[peerid]->psk;
        else
            buf_psk = peer_table[global_self_id]->psk;
        header_send.id = htons(global_self_id);
        header_send.m_type_len = 0;
        header_send.m_type_len |= ( HEAD_MASK_MORE & HEAD_MORE_FALSE );
        header_send.m_type_len |= ( HEAD_MASK_TYPE & HEAD_TYPE_DATA  );
        header_send.m_type_len |= ( HEAD_MASK_LEN & len_load );
        header_send.m_type_len = htons(header_send.m_type_len);
        header_send.time = htonl(time(NULL));
        header_send.padding = random();

        memcpy(buf_header, &header_send, HEADER_LEN);
        encrypt(buf_send, buf_header, global_buf_group_psk, AES_KEY_LEN);  //encrypt header with group PSK
        encrypt(&buf_send[HEADER_LEN], buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv

        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
        for(i=0; i<nr_aes_block; i++)
            encrypt(&buf_send[HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN], &buf_load[i*AES_TEXT_LEN], buf_psk, AES_KEY_LEN);

        len_pad = (len_load > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
        if(sendto(global_sockfd, buf_send, HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN + len_pad, \
            0, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0 )
            printlog(errno, "tunif %s sendto socket error", global_tunif.name);
    }

    free(peeraddr);
    return NULL;
}

void* server_recv(void *arg)
{
    struct tunnel_header header_recv, header_send;
    struct peer_profile ** peer_table = (struct peer_profile **)arg;
    uint16_t peerid = 0;
    uint16_t next_id = 0;
    struct sockaddr_in *peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    socklen_t peeraddr_len = sizeof(*peeraddr);
    struct iphdr ip_h;
    struct ip_dot_decimal ip_daddr;
    struct ip_dot_decimal ip_saddr;
    uint16_t len_load, nr_aes_block;
    int i;
    byte * buf_psk;
    byte buf_recv[ETH_MTU];
    byte buf_load[TUN_MTU];
    byte buf_send[TUN_MTU];
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

        //printlog(0, "recved :1 \n" );
        decrypt(buf_header, buf_recv, global_buf_group_psk, AES_KEY_LEN);  //decrypt header with group PSK
        memcpy(&header_recv, buf_header, HEADER_LEN);
        //header_recv.time = ntohl(header_recv.time);
        
        peerid = ntohs(header_recv.id);
        //printlog(0, "recv peerid: %d\n", peerid);
        if(peerid != global_self_id && NULL == peer_table[peerid])
        {
            printlog(0, "tunif %s received packet from peer %d.%d: invalid peer!\n", 
                global_tunif.name, peerid/256, peerid%256);
            continue;
        }

        if(peerid > global_self_id)
            buf_psk = peer_table[peerid]->psk;
        else
            buf_psk = peer_table[global_self_id]->psk;

        encrypt(buf_icv, buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv
        if(strncmp((char*)buf_icv, (char*)&buf_recv[HEADER_LEN], ICV_LEN) != 0)
        {
            printlog(0, "tunif %s received packet from peer %d.%d: icv doesn't match!\n", 
                global_tunif.name, peerid/256, peerid%256);
            continue;
        }
        memcpy(peer_table[peerid]->peeraddr, peeraddr, sizeof(struct sockaddr_in));

        header_recv.m_type_len = ntohs(header_recv.m_type_len);
        len_load = HEAD_MASK_LEN & header_recv.m_type_len;
        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;

        for(i=0; i<nr_aes_block; i++)
            decrypt(&buf_load[i*AES_TEXT_LEN], &buf_recv[HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN], buf_psk, AES_KEY_LEN);
        
        memcpy(&ip_h, buf_load, IPV4_HEAD_LEN);
        memcpy(&ip_saddr, &ip_h.saddr, sizeof(uint32_t));
        memcpy(&ip_daddr, &ip_h.daddr, sizeof(uint32_t));

        //ttl expire, drop packet. only allow 16 hops
        if(127 == ip_saddr.a && ip_saddr.b < 240)
        {
            //printlog(0, "saddr:%d.%d.%d.%d\n",ip_saddr.a,ip_saddr.b,ip_saddr.c,ip_saddr.d);
            printlog(0, "TTL expired! daddr: %d.%d.%d.%d\n", ip_daddr.a, ip_daddr.b, ip_daddr.c, ip_daddr.d);   
            continue;
        }

        //daddr is 127.0.x.x, send to local tunif, should apply both dnat and snat
        //if((ip_h.daddr & global_tunif.mask) == (global_between_tun_net & global_tunif.mask))
        else if(127 == ip_daddr.a && 0 == ip_daddr.b)
        {
            //printlog(0, "dnat to local\n");
            //dnat first
            uint32_t rip = global_tunif.addr;
            ip_dnat(buf_load, rip);     //apply dnat, daddr is local tunif

            //snat second
            uint32_t vip = peer_table[peerid]->vip;     //apply snat, saddr is peer's vip
            ip_snat(buf_load, vip);
        
            if(write(global_tunfd, &buf_load, len_load) < 0)
                printlog(errno, "tunif %s write error", global_tunif.name);
            continue;
        }

        //daddr is 127.x.x.x, should switch packet to client
        //else if((ip_h.daddr & global_tunif.mask) == (global_inter_switch_net & global_tunif.mask))
        else if(127 == ip_daddr.a)
        {
            //printlog(0, "send to client\n");
            //apply dnat
            peerid = ntohl(ip_h.daddr);
            uint32_t rip = peer_table[peerid]->rip;  //real ip is stored in network byte order.
            ip_dnat(buf_load, rip);

            //encrypt and send to client
            memcpy(peeraddr, peer_table[peerid]->peeraddr, sizeof(struct sockaddr_in));
        
            header_send.id = htons(global_self_id);
            header_send.m_type_len = 0;
            header_send.m_type_len |= ( HEAD_MASK_MORE & HEAD_MORE_FALSE );
            header_send.m_type_len |= ( HEAD_MASK_TYPE & HEAD_TYPE_DATA  );
            header_send.m_type_len |= ( HEAD_MASK_LEN & len_load );
            header_send.m_type_len = htons(header_send.m_type_len);
            header_send.time = htonl(time(NULL));
            header_send.padding = random();
    
            if(peerid > global_self_id)
                buf_psk = peer_table[peerid]->psk;
            else
                buf_psk = peer_table[global_self_id]->psk;
            memcpy(buf_header, &header_send, HEADER_LEN);
            encrypt(buf_send, buf_header, global_buf_group_psk, AES_KEY_LEN);  //encrypt header with group PSK
            encrypt(&buf_send[HEADER_LEN], buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv
    
            nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
            for(i=0; i<nr_aes_block; i++)
                encrypt(&buf_send[HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN], &buf_load[i*AES_TEXT_LEN], buf_psk, AES_KEY_LEN);
    
            int len_pad = (len_load > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
            if(sendto(global_sockfd, buf_send, HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN + len_pad, \
                0, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0 )
                printlog(errno, "tunif %s sendto socket error", global_tunif.name);
            continue;
        }

        //daddr is NOT 127.x.x.x
        else
        {
            peer_table[peerid]->rip = ip_h.saddr;  //save client's inner real saddr in network byte order.
    
            next_id = get_next_hop_id(ip_h.daddr, peer_table[peerid]->vip);
            //printlog(0, "in recv: dest: %d\n", next_id);
            //printlog(0, "global_self_id: %d\n", global_self_id);
    
            if(1 == next_id || global_self_id == next_id)   //write to local tunnel
            {
                if(ip_h.daddr == global_tunif.addr)   //send to local tunif
                {
                    ;   //do nothing
                }
                else   //not send to local tunif
                {
                    uint32_t vip = peer_table[peerid]->vip;     //apply snat, saddr is peer's vip
                    ip_snat(buf_load, vip);
                }
                
                if(write(global_tunfd, &buf_load, len_load) < 0)
                    printlog(errno, "tunif %s write error", global_tunif.name);
            }
            else if(0 != next_id)     //switch to another server
            {
                uint32_t vip = peer_table[peerid]->inter_vip;     //apply snat, saddr is 127.255.x.x
                if(127 == ip_saddr.a)
                {
                    ip_saddr.b--;   //decrease TTL
                    memcpy(&vip, &ip_saddr, sizeof(uint32_t));
                    vip = (vip & global_tunif.mask) | htonl(peerid); //in network byte order.
                }
                ip_snat(buf_load, vip);
    
                struct tunnel_header header_send;
                if(next_id > global_self_id)
                    buf_psk = peer_table[next_id]->psk;
                else
                    buf_psk = peer_table[global_self_id]->psk;
                header_send.id = htons(global_self_id);
                byte buf_send[ETH_MTU];
                header_send.m_type_len = 0;
                header_send.m_type_len |= ( HEAD_MASK_MORE & HEAD_MORE_FALSE );
                header_send.m_type_len |= ( HEAD_MASK_TYPE & HEAD_TYPE_DATA  );
                header_send.m_type_len |= ( HEAD_MASK_LEN & len_load );
                header_send.m_type_len = htons(header_send.m_type_len);
                header_send.time = htonl(time(NULL));
                header_send.padding = random();
        
                memcpy(buf_header, &header_send, HEADER_LEN);
                encrypt(buf_send, buf_header, global_buf_group_psk, AES_KEY_LEN);  //encrypt header with group PSK
                encrypt(&buf_send[HEADER_LEN], buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv
        
                nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
                for(i=0; i<nr_aes_block; i++)
                    encrypt(&buf_send[HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN], &buf_load[i*AES_TEXT_LEN], buf_psk, AES_KEY_LEN);
        
                //printlog(0, "sendto: %d\n", next_id);
                int len_pad = (len_load > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
                if(sendto(global_sockfd, buf_send, HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN + len_pad, \
                    0, (struct sockaddr *)peer_table[next_id]->peeraddr, sizeof(*peeraddr)) < 0 )
                    printlog(errno, "tunif %s sendto socket error", global_tunif.name);
            }
        }
    }

    free(peeraddr);
    return NULL;
}
