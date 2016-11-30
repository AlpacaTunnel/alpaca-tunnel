#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>

#include "aes.h"
#include "route.h"
#include "log.h"
#include "data_struct.h"
#include "secret.h"
#include "ip.h"
#include "tunnel.h"
#include "header.h"
#include "config.h"
#include "bool.h"
#include "cmd_helper.h"
#include "timer.h"


#define PROCESS_NAME    "alpaca-tunnel"
#define VERSION         "2.8"

/*
 * Config file path choose order:
 * 1) if user specify the path with -C, this path will be used.
 * 2) if exe is located at `/usr/bin/`, config will be `/etc/alpaca-tunnel.json`.
 * 3) if exe is located at `/usr/local/bin/`, config will be `/usr/local/etc/alpaca-tunnel.json`.
 * 4) config will be at the same path with exe file.
 *
 * Secret file path choose order:
 * 1) if user specify the path in json, this path will be used. if this path is a relative path, it's relative to the config json.
 * 2) Otherwise, the secret file MUST be located at the relative path `alpaca-tunnel.d/alpaca-secrets` to the config json, NOT with exe!
*/

#define ABSOLUTE_PATH_TO_JSON        "/etc/alpaca-tunnel.json"
#define ABSOLUTE_PATH_TO_JSON_LOCAL  "/usr/local/etc/alpaca-tunnel.json"
#define RELATIVE_PATH_TO_JSON        "alpaca-tunnel.json"
#define RELATIVE_PATH_TO_SECRETS     "alpaca-tunnel.d/alpaca-secrets"
#define CONFIG_JSON_NAME             "alpaca-tunnel.json"
#define SECRET_NAME                  "alpaca-secrets"

#define PATH_LEN 1024


//length of aes key must be 128, 192 or 256
#define AES_KEY_LEN 128
#define DEFAULT_PORT 1984

#define MAX_DELAY_TIME 10  //max delay 10 seconds. if an packet delayed more than 10s, it will be treated as new packet.

//why allow some replay packets? because peer may change devices or adjust system time/date. it's different from DoS.
//so max replay rate is REPLAY_CNT_LIMIT per RESET_STAT_INTERVAL
#define RESET_STAT_INTERVAL 30
#define REPLAY_CNT_LIMIT 10
#define JUMP_CNT_LIMIT 3
#define INVOLVE_CNT_LIMIT 3

#define ALLOW_P2P true
#define CHECK_RESTRICTED_IP true

//numbers of packets, let's set it 20000 = 00.2*SEQ_LEVEL_1, store 20-milliseconds packets at full speed.
//ocupy about 2*20000*1500 = 60M memory, allow max speed of about 1Mpps TCP-ACK packets.
//but if don't store sent/wrote packets, 200 is enough for inter-threads buffer with 100Mbps speed.
#define WRITE_BUF_SIZE 5000
#define SEND_BUF_SIZE  5000
#define EPOLL_MAXEVENTS 1024
#define TICK_QUEUE_SIZE (SEQ_LEVEL_1 * 2)
#define TICK_INTERVAL 1 // 1 ms
#define ACK_NUM 2
#define ACK_FIRST_TIME  10000000
#define ACK_INTERVAL    50000000
#define ACK_WRITE_DELAY 100  // ms
#define UDP_DUP_DELAY   100  // ms


enum {pkt_none, pkt_write, pkt_send} packet_type = pkt_none;
struct packet_profile_t
{
    int type;
    uint16_t src_id;
    uint16_t dst_id;
    uint32_t timestamp;
    uint32_t seq;
    int send_fd;
    int write_fd;
    int timer_fd;
    int send_cnt;
    int len;
    bool dup;
    timer_ms_t ms_timer;
    struct sockaddr_in * dst_addr;
    byte * buf_packet;
};


static struct packet_profile_t * global_write_buf = NULL;
static struct packet_profile_t * global_tick_queue_buf = NULL;
static ll_node_t * global_tick_list_head = NULL;
static struct packet_profile_t * global_send_buf  = NULL;
static int global_write_first = 0;
static int global_write_last  = 0;
static int global_send_first  = 0;
static int global_send_last   = 0;
static pthread_mutex_t global_write_mutex;
static pthread_mutex_t global_send_mutex;
static pthread_cond_t  global_write_cond;
static pthread_cond_t  global_send_cond;

static int global_running = 0;
static int global_sysroute_change = 0;
static int global_secret_change = 0;
static uint16_t global_self_id = 0;
static uint global_pkt_cnt = 0;
static pthread_spinlock_t global_stat_spin;
static pthread_spinlock_t global_time_seq_spin;
static pthread_spinlock_t global_tick_queue_spin;

//in network byte order.
static struct if_info_t global_tunif;
static struct if_info_t *global_if_list;

static char global_exe_path[PATH_LEN] = "\0";
static char global_json_path[PATH_LEN] = "\0";
static char global_secrets_path[PATH_LEN] = "\0";
static char global_secrets_dir[PATH_LEN] = "\0";

enum {mode_none, mode_server, mode_client} global_mode = mode_none;
static byte global_buf_group_psk[2*AES_TEXT_LEN] = "FUCKnimadeGFW!";
static int global_tunfd, global_sockfd;
static uint32_t global_local_time;
//static uint32_t global_local_seq;
static int64_t* global_trusted_ip = NULL;  // int64_t can hold uint32_t(IPv4 address)
static int global_trusted_ip_cnt = 0;
static int global_epoll_fd_recv = 0;
static int global_epoll_fd_write = 0;
static prior_q_t global_tick_queue;

void* tick_queue(void *arg);

//client_read and client_recv are obsoleted
void* client_read(void *arg);
void* client_recv(void *arg);

void* server_read(void *arg);
void* server_recv(void *arg);
void* server_write(void *arg);
void* server_send(void *arg);
void* watch_timer_recv(void *arg);

void* server_reset_stat(void *arg);
void* watch_link_route(void *arg);
void* watch_secret(void *arg);
void* update_secret(void *arg);
void* reset_link_route(void *arg);
void clean_lock_all(void *arg);
int init_global_values();

int usage(char *pname);
void sig_handler(int signum);
int flow_filter(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, struct peer_profile_t ** peer_table);
int check_timerfd(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, struct peer_profile_t ** peer_table);
int add_timerfd_epoll(int epfd, uint8_t type, struct ack_info_t * info);

/* get next hop id form route_table or system route table
 * return value:
 * 0 : actually, will never return 0. instead, return 1.
 * 1 : local or link dst, should write to tunnel interface
 * >1: the ID of other tunnel server
 * if next_hop_id == global_self_id, return 1
*/
uint16_t get_next_hop_id(uint32_t ip_dst, uint32_t ip_src);


int usage(char *pname)
{
    printf("Usage: %s [-t|T] [-v|V] [-c|C config]\n", pname);
    return 0;
}


void clean_lock_all(void *arg)
{
    if(global_running)
    {
        ERROR(0, "Entering clean_lock_all, which should only happen when process exits.");
        ERROR(0, "This message means there is a thread exited during process runing.");
    }

    // unlock a unlocked lock, the result is undefined, may cause segmentation fault.
    // since this function is called more than once, so I have to return here.
    return;

    //no thread should exit during process runing, so I put all unlock here, just for future debug.
    pthread_spin_unlock(&global_stat_spin);
    pthread_mutex_unlock(&global_write_mutex);
    pthread_mutex_unlock(&global_send_mutex);
    unlock_route_spin();

    return;
}

int init_global_values()
{
    if(init_route_spin() < 0)
    {
        ERROR(0, "init_route_spin");
        return -1;
    }
    if(pthread_spin_init(&global_stat_spin, PTHREAD_PROCESS_PRIVATE) != 0)
    {
        ERROR(errno, "pthread_spin_init");
        return -1;
    }
    if(pthread_spin_init(&global_time_seq_spin, PTHREAD_PROCESS_PRIVATE) != 0)
    {
        ERROR(errno, "pthread_spin_init");
        return -1;
    }
    if(pthread_spin_init(&global_tick_queue_spin, PTHREAD_PROCESS_PRIVATE) != 0)
    {
        ERROR(errno, "pthread_spin_init");
        return -1;
    }
    if(pthread_mutex_init(&global_write_mutex, NULL) != 0)
    {
        ERROR(errno, "pthread_mutex_init");
        return -1;
    }
    if(pthread_mutex_init(&global_send_mutex, NULL) != 0)
    {
        ERROR(errno, "pthread_mutex_init");
        return -1;
    }
    if(pthread_cond_init(&global_write_cond, NULL) != 0)
    {
        ERROR(errno, "pthread_cond_init");
        return -1;
    }
    if(pthread_cond_init(&global_send_cond, NULL) != 0)
    {
        ERROR(errno, "pthread_cond_init");
        return -1;
    }

    global_epoll_fd_recv = epoll_create(1);
    if(global_epoll_fd_recv == -1)
    {
        ERROR(errno, "epoll_create");
        return -1;
    }

    global_epoll_fd_write = epoll_create(1);
    if(global_epoll_fd_write == -1)
    {
        ERROR(errno, "epoll_create");
        return -1;
    }

    if(pq_init(&global_tick_queue, TICK_QUEUE_SIZE) == -1)
    {
        ERROR(0, "init_prior_q");
        return -1;
    }

    global_write_buf = (struct packet_profile_t *)malloc(WRITE_BUF_SIZE * sizeof(struct packet_profile_t));
    if(global_write_buf == NULL)
    {
        ERROR(errno, "malloc failed: global_write_buf");
        return -1;
    }
    else
    {
        bzero(global_write_buf, WRITE_BUF_SIZE * sizeof(struct packet_profile_t));
        int i;
        for(i=0; i<WRITE_BUF_SIZE; i++)
        {
            global_write_buf[i].dst_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
            if(global_write_buf[i].dst_addr == NULL)
            {
                ERROR(errno, "malloc failed: global_write_buf");
                return -1;
            }
            global_write_buf[i].buf_packet = (byte *)malloc(ETH_MTU);
            if(global_write_buf[i].buf_packet == NULL)
            {
                ERROR(errno, "malloc failed: global_write_buf");
                return -1;
            }
        }
    }

    global_send_buf = (struct packet_profile_t *)malloc(SEND_BUF_SIZE * sizeof(struct packet_profile_t));
    if(global_send_buf == NULL)
    {
        ERROR(errno, "malloc failed: global_send_buf");
        return -1;
    }
    else
    {
        bzero(global_send_buf, SEND_BUF_SIZE * sizeof(struct packet_profile_t));
        int i;
        for(i=0; i<SEND_BUF_SIZE; i++)
        {
            global_send_buf[i].dst_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
            if(global_send_buf[i].dst_addr == NULL)
            {
                ERROR(errno, "malloc failed: global_send_buf");
                return -1;
            }
            global_send_buf[i].buf_packet = (byte *)malloc(ETH_MTU);
            if(global_send_buf[i].buf_packet == NULL)
            {
                ERROR(errno, "malloc failed: global_send_buf");
                return -1;
            }
        }
    }

    global_tick_queue_buf = (struct packet_profile_t *)malloc(TICK_QUEUE_SIZE * sizeof(struct packet_profile_t));
    if(global_tick_queue_buf == NULL)
    {
        ERROR(errno, "malloc failed: global_tick_queue_buf");
        return -1;
    }
    else
    {
        bzero(global_tick_queue_buf, TICK_QUEUE_SIZE * sizeof(struct packet_profile_t));
        int i;
        for(i=0; i<TICK_QUEUE_SIZE; i++)
        {
            global_tick_queue_buf[i].dst_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
            if(global_tick_queue_buf[i].dst_addr == NULL)
            {
                ERROR(errno, "malloc failed: global_tick_queue_buf");
                return -1;
            }
            global_tick_queue_buf[i].buf_packet = (byte *)malloc(ETH_MTU);
            if(global_tick_queue_buf[i].buf_packet == NULL)
            {
                ERROR(errno, "malloc failed: global_tick_queue_buf");
                return -1;
            }
        }
    }

    ll_array_init(&global_tick_list_head, TICK_QUEUE_SIZE);

    ll_array_load_data(global_tick_list_head, TICK_QUEUE_SIZE, (uintptr_t)global_tick_queue_buf, (uint)sizeof(struct packet_profile_t));
    
    return 0;
}

int destory_global_values()
{
    destroy_route_spin();
    pthread_spin_destroy(&global_stat_spin);
    pthread_spin_destroy(&global_time_seq_spin);
    pthread_spin_destroy(&global_tick_queue_spin);
    pthread_mutex_destroy(&global_write_mutex);
    pthread_mutex_destroy(&global_send_mutex);
    pthread_cond_destroy(&global_write_cond);
    pthread_cond_destroy(&global_send_cond);
    close(global_epoll_fd_recv);
    close(global_epoll_fd_write);
    pq_destory(&global_tick_queue);

    if(global_write_buf != NULL)
    {
        int i;
        for(i=0; i<WRITE_BUF_SIZE; i++)
        {
            if(global_write_buf[i].dst_addr != NULL)
                free(global_write_buf[i].dst_addr);
            if(global_write_buf[i].buf_packet != NULL)
                free(global_write_buf[i].buf_packet);
        }
        free(global_write_buf);
    }

    if(global_send_buf != NULL)
    {
        int i;
        for(i=0; i<SEND_BUF_SIZE; i++)
        {
            if(global_send_buf[i].dst_addr != NULL)
                free(global_send_buf[i].dst_addr);
            if(global_send_buf[i].buf_packet != NULL)
                free(global_send_buf[i].buf_packet);
        }
        free(global_send_buf);
    }

    if(global_tick_queue_buf != NULL)
    {
        int i;
        for(i=0; i<TICK_QUEUE_SIZE; i++)
        {
            if(global_tick_queue_buf[i].dst_addr != NULL)
                free(global_tick_queue_buf[i].dst_addr);
            if(global_tick_queue_buf[i].buf_packet != NULL)
                free(global_tick_queue_buf[i].buf_packet);
        }
        free(global_tick_queue_buf);
    }

    ll_array_destory(global_tick_list_head);

    return 0;
}

int main(int argc, char *argv[])
{
    int opt;
    while((opt = getopt(argc, argv, "tTvVc:C:")) != -1)
    {
        switch(opt)
        {
        case 'v':
        case 'V':
            printf("%s %s\n", PROCESS_NAME, VERSION);
            exit(0);
        case 'c':
        case 'C':
            strncpy((char*)global_json_path, optarg, PATH_LEN);
            break;
        case 't':
        case 'T':
            set_log_time();
            break;
        default:
            usage(argv[0]);
            exit(1);
        }
    }


/******************* init global/main variables *******************/

    srandom(time(NULL));

    struct peer_profile_t ** peer_table = NULL;
    struct config_t config;
    memset(&config, 0, sizeof(config));

    bool start_success = false;
    bool default_route_changed = false;
    bool server_ip_route_added = false;
    ll_node_t * local_route_list = NULL;

    char default_gw_ip[IP_LEN] = "\0";
    //char default_gw_dev[IFNAMSIZ] = "\0";

    if(init_global_values() != 0)
        goto _END;


/******************* load json config *******************/

    int path_len;
    if('\0' == global_json_path[0])
    {
        path_len = readlink("/proc/self/exe", global_exe_path, PATH_LEN);
        if(path_len < 0)
        {
            ERROR(errno, "readlink: /proc/self/exe");
            goto _END;
        }
        else if(path_len > (PATH_LEN-40))   //40 is reserved for strcat.
        {
            ERROR(0, "readlink: file path too long: %s", global_exe_path);
            goto _END;
        }
        while(global_exe_path[path_len] != '/')
        {
            global_exe_path[path_len] = '\0';
            path_len--;
        }
        
        if(strcmp(global_exe_path, "/usr/bin/") == 0)
            strcpy(global_json_path, ABSOLUTE_PATH_TO_JSON);
        else if(strcmp(global_exe_path, "/usr/local/bin/") == 0)
            strcpy(global_json_path, ABSOLUTE_PATH_TO_JSON_LOCAL);
        else
        {
            strcpy(global_json_path, global_exe_path);
            strcat(global_json_path, RELATIVE_PATH_TO_JSON);
        }
    }

    if(load_config(global_json_path, &config) != 0)
    {
        ERROR(0, "Load config failed.");
        goto _END;
    }
    if(check_config(&config) != 0)
    {
        ERROR(0, "Check config failed.");
        goto _END;
    }


/******************* set log level, model, group *******************/

    set_log_level(get_log_level(config.log_level));

    if(strcmp(config.mode, "client") == 0)
        global_mode = mode_client;
    else if(strcmp(config.mode, "server") == 0)
        global_mode = mode_server;

    strncpy((char*)global_buf_group_psk, config.group, 2*AES_TEXT_LEN);
    global_self_id = inet_ptons(config.id);
    
    // wait default route to come up
    if(global_mode == mode_client)
    {
        INFO("searching default route in main table...");
        bool default_route_up = false;
        for(int i = 0; i < 10; ++i)
        {
            get_default_route(default_gw_ip, NULL);
            if(default_gw_ip[0] != '\0')
            {
                default_route_up = true;
                break;
            }
            else
                sleep(3);
        }
        if(default_route_up == false)
        {
            ERROR(0, "default route was not found!");
            goto _END;
        }
    }


/******************* bind UDP socket *******************/

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(config.port);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    global_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(bind(global_sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        ERROR(errno, "bind port %d", config.port);
        goto _END;
    }


/******************* get secret file *******************/

    if(config.secret_file != NULL && config.secret_file[0] == '/')
        strcpy(global_secrets_path, config.secret_file);
    else
    {
        strcpy(global_secrets_path, global_json_path);
        path_len = strlen(global_secrets_path);
        while(global_secrets_path[path_len] != '/' && path_len >= 0)
        {
            global_secrets_path[path_len] = '\0';
            path_len--;
        }
        if(config.secret_file == NULL)
            strcat(global_secrets_path, RELATIVE_PATH_TO_SECRETS);
        else
            strcat(global_secrets_path, config.secret_file);
    }

    if(access(global_secrets_path, R_OK) == -1)
    {
        ERROR(errno, "cann't read secret file: %s", global_secrets_path);
        goto _END;
    }

    strcpy(global_secrets_dir, global_secrets_path);
    path_len = strlen(global_secrets_dir);
    while(global_secrets_dir[path_len] != '/' && path_len >= 0)
    {
        global_secrets_dir[path_len] = '\0';
        path_len--;
    }

    INFO("%s", global_json_path);
    INFO("%s", global_secrets_path);
    

/******************* load secret file *******************/

    FILE *secrets_file = NULL;
    if((secrets_file = fopen(global_secrets_path, "r")) == NULL)
    {
        ERROR(errno, "open file: %s", global_secrets_path);
        goto _END;
    }
    if((peer_table = init_peer_table(secrets_file, MAX_ID)) == NULL)
    {
        ERROR(0, "Init peer failed!");
        fclose(secrets_file);
        goto _END;
    }
    fclose(secrets_file);

    if(NULL == peer_table[global_self_id])
    {
        ERROR(0, "Init peer: didn't find self profile in secert file!");
        goto _END;
    }

    if(CHECK_RESTRICTED_IP)
    {
        global_trusted_ip = (int64_t *)malloc((MAX_ID+1) * sizeof(int64_t));;
        if(global_trusted_ip == NULL)
        {
            ERROR(errno, "Init global_trusted_ip: malloc failed");
            goto _END;
        }
        else
            bzero(global_trusted_ip, (MAX_ID+1) * sizeof(int64_t));

        int i;
        for(i = 0; i < MAX_ID+1; i++)
            if(peer_table[i] != NULL && peer_table[i]->peeraddr != NULL && peer_table[i]->peeraddr->sin_addr.s_addr != 0)
            {
                global_trusted_ip[global_trusted_ip_cnt] = peer_table[i]->peeraddr->sin_addr.s_addr;
                global_trusted_ip_cnt++;
            }
        merge_sort(global_trusted_ip, global_trusted_ip_cnt);
    }


/******************* setup tunnel interface *******************/

    // before bring tunnel interface up
    run_cmd_list(&config.pre_up_cmds);

    char tun_name[IFNAMSIZ] = "\0";
    if( (global_tunfd = tun_alloc(tun_name)) < 0 )
    {
        ERROR(0, "tun_alloc failed.");
        goto _END;
    }
    if(tun_up(tun_name) != 0)
    {
        ERROR(0, "tun_up %s failed.", tun_name);
        goto _END;
    }
    if(tun_mtu(tun_name, config.mtu) != 0)
    {
        ERROR(0, "tun_mtu %s failed.", tun_name);
        goto _END;
    }

    char tun_ip[IP_LEN];
    sprintf(tun_ip, "%s.%s", config.net, config.id);
    if(tun_addip(tun_name, tun_ip, TUN_MASK_LEN) != 0)
    {
        ERROR(0, "tun_addip %s failed.", tun_name);
        goto _END;
    }

    global_if_list = NULL;
    collect_if_info(&global_if_list);
    strncpy(global_tunif.name, tun_name, IFNAMSIZ);

    // get ip address of the tunnel interface    
    int tmp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq tmp_ifr;
    tmp_ifr.ifr_addr.sa_family = AF_INET;
    strncpy(tmp_ifr.ifr_name, tun_name, IFNAMSIZ-1);
    if(ioctl(tmp_sockfd, SIOCGIFADDR, &tmp_ifr) < 0)
    {
        ERROR(errno, "ioctl(SIOCGIFADDR): %s",global_tunif.name);
        close(tmp_sockfd);
        goto _END;
    }
    close(tmp_sockfd);

    struct sockaddr_in *tmp_in = (struct sockaddr_in *)&tmp_ifr.ifr_addr;
    global_tunif.addr = tmp_in->sin_addr.s_addr;
    global_tunif.mask = get_ipmask(global_tunif.addr, global_if_list);
    //tunif IP must be a /16 network, and must match self ID! otherwise, from/to peer will be confusing.
    if(TUN_NETMASK != ntohl(global_tunif.mask))
    {
        ERROR(0, "Tunnel mask is not /16.");
        goto _END;
    }
    if((uint16_t)(ntohl(global_tunif.addr)) != global_self_id)
    {
        ERROR(0, "Tunnel ip does not match ID!");
        goto _END;
    }
    
    // after bring tunnel interface up
    run_cmd_list(&config.post_up_cmds);

    enable_ip_forward();

    // setup route
    if(global_mode == mode_client)
    {
        char gw_ip[IP_LEN];
        sprintf(gw_ip, "%s.%s", config.net, config.gateway);
    
        if(default_gw_ip[0] != '\0')
        {
            change_default_route(gw_ip);
            default_route_changed = true;
        }

        for(int i = 0; i < MAX_ID+1; i++)
        {
            server_ip_route_added = true;
            if(peer_table[i] != NULL && peer_table[i]->peeraddr != NULL && peer_table[i]->peeraddr->sin_addr.s_addr != 0)
            {
                struct in_addr in;
                in.s_addr = peer_table[i]->peeraddr->sin_addr.s_addr;
                char * server_ip_str = inet_ntoa(in);
                add_iproute(server_ip_str, default_gw_ip, "default");
            }
        }

        char * local_route;
        while( (local_route = shift_ll(&config.local_routes) ) != NULL)
        {
            add_iproute(local_route, default_gw_ip, "default");
            append_ll(&local_route_list, local_route);
        }
    }

    if(global_mode == mode_server)
    {
        char tun_net[IP_LEN+4];
        sprintf(tun_net, "%s.0.0/%d", config.net, TUN_MASK_LEN);
        add_iptables_nat(tun_net);
    }

    add_iptables_tcpmss(TCPMSS);

    
/******************* start all working threads *******************/

    global_running = 1;

    int rc1=0, rc2=0, rc3=0, rc4=0, rc5=0, rc6=0, rc7=0, rc8=0, rc9=0, rc10=0, rc11=0;
    pthread_t tid1=0, tid2=0, tid3=0, tid4=0, tid5=0, tid6=0, tid7=0, tid8=0, tid9=0, tid10=0, tid11=0;

    if( (rc1 = pthread_create(&tid1, NULL, server_recv, peer_table)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc1"); 
        goto _END;
    }
    if( (rc2 = pthread_create(&tid2, NULL, server_read, peer_table)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc2"); 
        goto _END;
    }
    if( (rc3 = pthread_create(&tid3, NULL, server_write, peer_table)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc3"); 
        goto _END;
    }
    if( (rc4 = pthread_create(&tid4, NULL, server_send, peer_table)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc4"); 
        goto _END;
    }

    if( (rc5 = pthread_create(&tid5, NULL, watch_link_route, NULL)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc5"); 
        goto _END;
    }
    if( (rc6 = pthread_create(&tid6, NULL, reset_link_route, NULL)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc6"); 
        goto _END;
    }
    if( (rc7 = pthread_create(&tid7, NULL, watch_secret, NULL)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc7"); 
        goto _END;
    }
    if( (rc8 = pthread_create(&tid8, NULL, update_secret, peer_table)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc8"); 
        goto _END;
    }
    if( (rc9 = pthread_create(&tid9, NULL, server_reset_stat, peer_table)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc9"); 
        goto _END;
    }
    if( (rc10 = pthread_create(&tid10, NULL, watch_timer_recv, peer_table)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc10"); 
        goto _END;
    }

    if( (rc11 = pthread_create(&tid11, NULL, tick_queue, NULL)) != 0 )
    {
        ERROR(errno, "pthread_error: create rc11"); 
        goto _END;
    }


/******************* main thread sleeps during running *******************/

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    //nohup won't work when SIGHUP installed.
    signal(SIGHUP, sig_handler);
    INFO("%s has started.", PROCESS_NAME);
    start_success = true;

    while(global_running)
        sleep(1);  //pause();


    //wait 50ms for the threads to clear env.
    struct timespec time_wait_threads;
    time_wait_threads.tv_sec = 0;
    time_wait_threads.tv_nsec = 50000000;
    nanosleep(&time_wait_threads, NULL);

    pthread_cancel(tid1);
    pthread_cancel(tid2);
    pthread_cancel(tid3);
    pthread_cancel(tid4);
    pthread_cancel(tid5);
    pthread_cancel(tid6);
    pthread_cancel(tid7);
    pthread_cancel(tid8);
    pthread_cancel(tid9);
    pthread_cancel(tid10);
    pthread_cancel(tid11);

    // what happens to a locked lock when cancel the thread?
    // what happens when destory a locked lock?


/******************* clear env *******************/

_END:

    global_running = 0;

    if(global_mode == mode_client)
    {
        if(default_route_changed)
            restore_default_route(default_gw_ip);

        for(int i = 0; i < MAX_ID+1; i++)
            if(server_ip_route_added && peer_table != NULL && peer_table[i] != NULL && peer_table[i]->peeraddr != NULL && peer_table[i]->peeraddr->sin_addr.s_addr != 0)
            {
                struct in_addr in;
                in.s_addr = peer_table[i]->peeraddr->sin_addr.s_addr;
                char * server_ip_str = inet_ntoa(in);
                del_iproute(server_ip_str, "default");
            }

        char * local_route;
        while( (local_route = shift_ll(&local_route_list) ) != NULL)
            del_iproute(local_route, "default");
    }

    if(global_mode == mode_server)
    {
        char tun_net[IP_LEN+4];
        sprintf(tun_net, "%s.0.0/%d", config.net, TUN_MASK_LEN);
        del_iptables_nat(tun_net);
    }

    del_iptables_tcpmss(TCPMSS);

    // before turn tunnel interface down 
    run_cmd_list(&config.pre_down_cmds);

    // close the fd will delete the tunnel interface.
    close(global_tunfd);

    // after turn tunnel interface down 
    run_cmd_list(&config.post_down_cmds);

    free_config(&config);

    close(global_sockfd);
    clear_if_info(global_if_list);
    global_if_list = NULL;

    if(CHECK_RESTRICTED_IP && global_trusted_ip != NULL)
        free(global_trusted_ip);

    destory_global_values();

    destroy_peer_table(peer_table, MAX_ID);
    peer_table = NULL;

    ERROR(0, "%s has exited.", PROCESS_NAME);
    if(start_success)
        exit(0);
    else
        exit(1);
}


void sig_handler(int signum)
{
    if(SIGINT == signum)
        ERROR(0, "Received SIGINT!");
    else if(SIGTERM == signum)
        ERROR(0, "Received SIGTERM!");
    else if(SIGHUP == signum)
    {
        ERROR(0, "Received SIGHUP!");
        return; //do nothing
    }

    global_running = 0;
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

void* tick_queue(void *arg)
{
    /*
     * Only this thread will dequeue!
    */
    pq_node_t node2;
    uint64_t fd_buf = 0;
    struct packet_profile_t * delay_pkt;
    struct sockaddr_in *peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    byte * buf_write = (byte *)malloc(TUN_MTU);
    byte * buf_send = (byte *)malloc(ETH_MTU);
    int i;
    for(i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    int sockfd = 0;
    int len = 0;
    uint16_t dst_id = 0;
    int tunfd = 0;

    struct itimerspec tick_it;
    tick_it.it_value.tv_sec = 0;
    tick_it.it_value.tv_nsec = TICK_INTERVAL * 1000000;
    tick_it.it_interval.tv_sec = 0;
    tick_it.it_interval.tv_nsec = TICK_INTERVAL * 1000000;

    int tick_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if(tick_fd == -1)
    {
        ERROR(errno, "timerfd_create");
        return NULL;
    }
    if(timerfd_settime(tick_fd, 0, &tick_it, NULL) == -1)
    {
        ERROR(errno, "timerfd_settime");
        close(tick_fd);
        return NULL;
    }

    // int pre_sort_tick = 0;
    // int tick_nr = 0;
    // int max_tick_round = 3600000; // 1 hour, let's assume no timer will be lager than 1 hour.
    while(global_running)
    {
        // wait timerfd interval
        if(read(tick_fd, &fd_buf, sizeof(uint64_t)) < 0)
        {
            ERROR(errno, "tunif %s read tick_fd", global_tunif.name);
            continue;
        }

        // the priority is the timer's interval, so for every tick, should reduce all node's priority
        pq_reduce(&global_tick_queue, TICK_INTERVAL);

        if(global_tick_queue.sorted == 0)
        {
            pq_sort(&global_tick_queue, 0);

            if(pthread_spin_lock(&global_tick_queue_spin) != 0)
            {
                ERROR(errno, "pthread_spin_lock");
                continue;
            }

            global_tick_queue.sorted = 1;
            
            if(pthread_spin_unlock(&global_tick_queue_spin) != 0)
            {
                ERROR(errno, "pthread_spin_unlock");
                continue;
            }
        }

        bool dequeue_flag = true;
        while(dequeue_flag)
        {
            if(pq_look_first(&global_tick_queue, &node2) != 0)
            {
                dequeue_flag = false;  // no data in queue
                continue;
            }
        
            ll_node_t * node1 = node2.data;
            delay_pkt = node1->data;
            if(!timer_elapsed(&(delay_pkt->ms_timer)))
            {
                dequeue_flag = false;  // the first timer in queue has not elapsed
                // DEBUG("not elapsed");
                continue;
            }

            if(pq_deq(&global_tick_queue, &node2) == 0)
            {
                if(pthread_spin_lock(&global_tick_queue_spin) != 0)
                {
                    ERROR(errno, "pthread_spin_lock");
                    continue;
                }

                if(delay_pkt->type == pkt_write)
                {
                    // DEBUG("write delayed ack");
                    tunfd = delay_pkt->write_fd;
                    len = delay_pkt->len;
                    dst_id = delay_pkt->dst_id;
                    memcpy(buf_write, delay_pkt->buf_packet, len);
                    
                    if(write(tunfd, buf_write, len) < 0)
                        ERROR(errno, "tunif %s write error of dst_id %d.%d", global_tunif.name, dst_id/256, dst_id%256);
                }

                if(delay_pkt->type == pkt_send)
                {
                    // DEBUG("send delayed pkt");
                    sockfd = delay_pkt->send_fd;
                    len = delay_pkt->len;
        
                    dst_id = delay_pkt->dst_id;
                    memcpy(peeraddr, delay_pkt->dst_addr, sizeof(struct sockaddr_in));
                    memcpy(buf_send, delay_pkt->buf_packet, len);

                    int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
                    if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0 )
                        ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", global_tunif.name, dst_id/256, dst_id%256);
                }

                ll_array_return(global_tick_list_head, node1);

                if(pthread_spin_unlock(&global_tick_queue_spin) != 0)
                {
                    ERROR(errno, "pthread_spin_unlock");
                    continue;
                }
            }
        }

    }

    free(buf_write);
    return NULL;
}

void* watch_secret(void *arg)
{
    int event_size = sizeof(struct inotify_event);
    int buf_len = 1024 * (event_size + 16);

    int msg_len=0, fd=0, wd=0;
    char buffer[buf_len];

    fd = inotify_init();

    if(fd < 0) 
    {
        ERROR(errno, "inotify_init");
        return NULL;
    }

    wd = inotify_add_watch(fd, global_secrets_dir, IN_MODIFY | IN_CREATE | IN_DELETE);
    while(global_running)
    {
        int i = 0;
        msg_len = read(fd, buffer, buf_len);
        if(msg_len < 0) 
            ERROR(errno, "read inotify");

        while(i < msg_len)
        {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if(event->len)
            {
                if(strcmp(event->name, SECRET_NAME) == 0)
                {
                    if(event->mask & IN_ISDIR)
                    {
                        if(event->mask & IN_CREATE)
                            WARNING("Rir has the same name with %s has been created\n", event->name);
                        else if(event->mask & IN_MODIFY)
                            WARNING("Dir has the same name with %s has been modified\n", event->name);
                        else if(event->mask & IN_DELETE)
                            WARNING("Dir has the same name with %s has been deleted\n", event->name);
                    }
                    else
                    {
                        if(event->mask & IN_CREATE)
                        {
                            global_secret_change++;
                            WARNING("Secret file %s has been created\n", event->name);
                        }
                        else if(event->mask & IN_MODIFY)
                        {
                            global_secret_change++;
                            WARNING("Secret file %s has been modified\n", event->name);
                        }
                        else if(event->mask & IN_DELETE)
                            WARNING("Secret file %s has been deleted\n", event->name);
                    }
                }
            }
            i += event_size + event->len;
        }
    }

    (void)inotify_rm_watch(fd, wd);
    (void)close(fd);
    return NULL;
}

//todo: add lock when update, otherwise timerfd may lost.
//for other data or status, there is no big issue.
void* update_secret(void *arg)
{
    struct peer_profile_t ** peer_table = (struct peer_profile_t **)arg;
    int pre = global_secret_change;
    while(global_running)
    {
        sleep(1);
        if(pre != global_secret_change)
        {
            FILE *secrets_file = NULL;
            if((secrets_file = fopen(global_secrets_path, "r")) == NULL)
                ERROR(errno, "open file failed when update_secret: %s", global_secrets_path);
            
            if(update_peer_table(peer_table, secrets_file, MAX_ID) < 0)
                ERROR(0, "update secret file failed!");
            else
                INFO("FILE: secret file reloaded!");
            fclose(secrets_file);

            if(NULL == peer_table[global_self_id])
                ERROR(0, "update_secret: didn't find self profile in secert file!");
    
            if(CHECK_RESTRICTED_IP)
            {
                global_trusted_ip_cnt = 0;
                bzero(global_trusted_ip, (MAX_ID+1) * sizeof(int64_t));
                int i;
                for(i = 0; i < MAX_ID+1; i++)
                    if(peer_table[i] != NULL && peer_table[i]->peeraddr != NULL && peer_table[i]->peeraddr->sin_addr.s_addr != 0)
                    {
                        if(global_trusted_ip_cnt > MAX_ID)
                            continue;
                        global_trusted_ip[global_trusted_ip_cnt] = peer_table[i]->peeraddr->sin_addr.s_addr;
                        global_trusted_ip_cnt++;
                    }
                merge_sort(global_trusted_ip, global_trusted_ip_cnt);
            }

            pre = global_secret_change;
        }
    }
    return NULL;
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
        ERROR(errno, "rtnl_handle_t bind");
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
    pthread_cleanup_push(clean_lock_all, NULL);
    int pre = global_sysroute_change;
    while(global_running)
    {
        sleep(1);
        if(pre != global_sysroute_change)
        {
            // DEBUG("RTNETLINK: route changed.");

            if(clear_if_info(global_if_list) != 0)
                continue;
            else
                global_if_list = NULL;

            if(collect_if_info(&global_if_list) != 0)
                continue;

            //must clear if_info_t first, then clear_route
            if(clear_route() != 0)
                continue;

            // DEBUG("RTNETLINK: route table reset.");
            pre = global_sysroute_change;
        }
    }
    pthread_cleanup_pop(0);
    return NULL;
}

void* server_reset_stat(void *arg)
{
    pthread_cleanup_push(clean_lock_all, NULL);
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
                    ERROR(errno, "pthread_spin_lock");
                    continue;
                }
                //if(pre != global_pkt_cnt)
                if(p->flow_src != NULL)
                {
                    p->flow_src->dup_cnt = 0;
                    p->flow_src->delay_cnt = 0;
                    p->flow_src->replay_cnt = 0;
                    //p->flow_src->sys_time = time(NULL);
                    p->flow_src->time_min = 0;
                    p->flow_src->time_max = 0;
                }
                if(j%4 == 0 && p->flow_src != NULL && p->flow_src->jump_cnt > 0)  //why 4? No why, it can be 5,6,7...100, any
                {
                    j++;
                    p->flow_src->jump_cnt = 0;
                    INFO("jump status count reset.");
                }
                if(pthread_spin_unlock(&global_stat_spin) != 0)
                {
                    ERROR(errno, "pthread_spin_unlock");
                    continue;
                }
            }
        }
    }
    pthread_cleanup_pop(0);
    return NULL;
}

bool should_pkt_dup(struct peer_profile_t * p, byte* ip_load)
{
    return true;

    if(p == NULL || p->tcp_info == NULL)
        return false;
    //struct tcp_info_t * tcp_info = p->tcp_info;
    struct iphdr ip_h;
    struct tcphdr tcp_h;
    struct udphdr udp_h;


    memcpy(&ip_h, ip_load, sizeof(struct iphdr));

    // DEBUG("iph tot_len: %d", ntohs(ip_h.tot_len));
    // DEBUG("iph ihl: %d", ip_h.ihl * 4);

    if(6 == ip_h.protocol)
    {
        //printf("tcp\n");
        memcpy(&tcp_h, ip_load+sizeof(struct iphdr), sizeof(struct tcphdr));
        // DEBUG("tcphdr doff: %d", tcp_h.doff * 4);

        

        //printf("src: %d, dst: %d, seq: %u, ack: %u\n", htons(tcp_h.source), htons(tcp_h.dest), htonl(tcp_h.seq), htonl(tcp_h.ack_seq));
        if(htons(tcp_h.source) == 53 || htons(tcp_h.dest) == 53)
        {
            //printf("tcp dns\n");
            return true;
        }
        if(tcp_h.syn == 1)
        {
            //todo: for the first about 10 or 20 tcp packets, should return true.
            //uint32_t init_seq = htonl(tcp_h.seq);
            //printf("syn init_seq: %u\n", init_seq);
            return true;
        }
        
        
    }
    else if(17 == ip_h.protocol)
    {
        return true; // dup all UDP

        //printf("udp\n");
        memcpy(&udp_h, ip_load+sizeof(struct iphdr), sizeof(struct udphdr));
        //printf("src: %d, dst: %d\n", htons(udp_h.source), htons(udp_h.dest));
        if(htons(udp_h.source) == 53 || htons(udp_h.dest) == 53)
            return true;
    }

    return false;
}

bool should_pkt_delay(struct peer_profile_t * p, byte* ip_load)
{
    return false;
    /*
    * delay TCP ACK write
    */

    // if(p == NULL || p->tcp_info == NULL)
        // return false;
    
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

void* server_read(void *arg)
{
    pthread_cleanup_push(clean_lock_all, NULL);
    struct tunnel_header_t header_send;
    struct peer_profile_t ** peer_table = (struct peer_profile_t **)arg;
    uint16_t next_id = 0;
    uint16_t src_id;
    uint16_t dst_id;
    uint16_t bigger_id;
    struct sockaddr_in *peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    struct iphdr ip_h;
    uint16_t len_load, nr_aes_block;
    byte * buf_load = (byte *)malloc(TUN_MTU);
    byte * buf_send = (byte *)malloc(ETH_MTU);
    byte buf_header[HEADER_LEN];
    byte * buf_psk;
    int i;
    bzero(buf_load, TUN_MTU);

    while(global_running)
    {
        if( (len_load = read(global_tunfd, buf_load, TUN_MTU)) < 0 )
        {
            ERROR(errno, "read tunif %s", global_tunif.name);
            continue;
        }
        
        memcpy(&ip_h, buf_load, sizeof(struct iphdr));
        next_id = get_next_hop_id(ip_h.daddr, ip_h.saddr);

        if(NULL == peer_table[next_id] || 1 == next_id || global_self_id == next_id)
        {
            DEBUG("tunif %s read packet to peer %d.%d: invalid peer!", global_tunif.name, next_id/256, next_id%256);
            continue;
        }
        if(NULL == peer_table[next_id]->peeraddr)
        {
            DEBUG("tunif %s read packet to peer %d.%d: invalid addr!", global_tunif.name, next_id/256, next_id%256);
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
            DEBUG("tunif %s read packet from other peer, ignore it!", global_tunif.name);
            continue;
        }
        else if(!dst_inside && !src_inside) //not supported now: outside IP to outside IP
        {
            DEBUG("tunif %s read packet from outside net to outside net, ignore it!", global_tunif.name);
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
            DEBUG("tunif %s read packet of invalid peer: %d.%d!", global_tunif.name, bigger_id/256, bigger_id%256);
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
        header_send.ttl_flag_random.bit.random = 0;
        header_send.ttl_flag_random.u16 = htons(header_send.ttl_flag_random.u16);

        uint32_t now = time(NULL);
        header_send.time = htonl(now);
        if(pthread_spin_lock(&global_time_seq_spin) != 0)
        {
            ERROR(errno, "pthread_spin_lock");
            continue;
        }
        if(global_local_time == now)
            peer_table[dst_id]->local_seq++;
        else
        {
            peer_table[dst_id]->local_seq = 0;
            global_local_time = now;
            uint32_t * tmp_index = peer_table[dst_id]->pkt_index_array_pre;
            peer_table[dst_id]->pkt_index_array_pre = peer_table[dst_id]->pkt_index_array_now;
            peer_table[dst_id]->pkt_index_array_now = tmp_index;
        }
        header_send.seq_frag_off.bit.seq = peer_table[dst_id]->local_seq;
        if(pthread_spin_unlock(&global_time_seq_spin) != 0)
        {
            ERROR(errno, "pthread_spin_unlock");
            continue;
        }

        if(peer_table[dst_id]->local_seq > SEQ_LEVEL_1)
        {
            DEBUG("local_seq beyond limit, drop this packet to dst_id: %d.%d.", dst_id/256, dst_id%256);
            continue;
        }

        header_send.seq_frag_off.bit.frag = 0;
        header_send.seq_frag_off.bit.off = 0;
        header_send.seq_frag_off.u32 = htonl(header_send.seq_frag_off.u32);

        memcpy(buf_header, &header_send, HEADER_LEN);
        encrypt(buf_send, buf_header, global_buf_group_psk, AES_KEY_LEN);  //encrypt header with group PSK
        encrypt(buf_send+HEADER_LEN, buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv

        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
        for(i=0; i<nr_aes_block; i++)
            encrypt(buf_send+HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN, buf_load+i*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);

        bool dup = should_pkt_dup(peer_table[bigger_id], buf_load);
        //if(dup)
        //    printf("should dup\n");

        //copy send packet to send thread
        if(pthread_mutex_lock(&global_send_mutex) != 0)
        {
            ERROR(errno, "pthread_mutex_lock");
            ERROR(0, "Drop this packet to next id: %d.%d", next_id/256, next_id%256);
            continue;
        }

        if((global_send_last + 1) % SEND_BUF_SIZE == global_send_first)
            ERROR(0, "send_buf is full, drop this packet to next id: %d.%d", next_id/256, next_id%256);
        else
        {
            int len = HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN;
            global_send_last = (global_send_last + 1) % SEND_BUF_SIZE;
            global_send_buf[global_send_last].src_id = global_self_id;
            global_send_buf[global_send_last].dst_id = dst_id;
            global_send_buf[global_send_last].send_fd = global_sockfd;
            global_send_buf[global_send_last].dup = dup;
            global_send_buf[global_send_last].len = len;
            global_send_buf[global_send_last].timestamp = now;
            global_send_buf[global_send_last].seq = peer_table[dst_id]->local_seq;
            memcpy(global_send_buf[global_send_last].dst_addr, peeraddr, sizeof(struct sockaddr_in));
            memcpy(global_send_buf[global_send_last].buf_packet, buf_send, len);
            peer_table[dst_id]->pkt_index_array_now[peer_table[dst_id]->local_seq] = global_send_last;
        }

        pthread_cond_signal(&global_send_cond);

        if(pthread_mutex_unlock(&global_send_mutex) != 0)
            ERROR(errno, "pthread_mutex_unlock");

        continue;
    }

    free(peeraddr);
    free(buf_load);
    free(buf_send);
    pthread_cleanup_pop(0);
    return NULL;
}

void* server_send(void *arg)
{
    pthread_cleanup_push(clean_lock_all, NULL);

    struct sockaddr_in *peeraddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    byte * buf_send = (byte *)malloc(ETH_MTU);
    int i;
    for(i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    int sockfd = 0;
    int len = 0;
    uint16_t dst_id = 0;

    while(global_running)
    {
        if(pthread_mutex_lock(&global_send_mutex) != 0)
        {
            ERROR(errno, "pthread_mutex_lock");
            continue;
        }
        
        while(global_send_last == global_send_first)
            pthread_cond_wait(&global_send_cond, &global_send_mutex);

        global_send_first = (global_send_first + 1) % SEND_BUF_SIZE;
        sockfd = global_send_buf[global_send_first].send_fd;
        len = global_send_buf[global_send_first].len;
        bool dup = global_send_buf[global_send_first].dup;
        dst_id = global_send_buf[global_send_first].dst_id;
        memcpy(peeraddr, global_send_buf[global_send_first].dst_addr, sizeof(struct sockaddr_in));
        memcpy(buf_send, global_send_buf[global_send_first].buf_packet, len);
        
        if(pthread_mutex_unlock(&global_send_mutex) != 0)
            ERROR(errno, "pthread_mutex_unlock");
    
        int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
        if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0 )
            ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", global_tunif.name, dst_id/256, dst_id%256);

        if(dup)  // add to tick_queue for delay
        {
            if(pthread_spin_lock(&global_tick_queue_spin) != 0)
            {
                ERROR(errno, "pthread_spin_lock");
                continue;
            }

            ll_node_t * node1 = ll_array_borrow(global_tick_list_head);  // malloc from the list and it's data pointer.
            if(node1 == NULL)
                ERROR(0, "tick_queue write_buf is full, drop this packet to next id: %d.%d", dst_id/256, dst_id%256);
            else
            {
                struct packet_profile_t * pkt = (struct packet_profile_t *)(node1->data);
                start_timer(&(pkt->ms_timer), UDP_DUP_DELAY);
                pkt->type = pkt_send;
                pkt->send_fd = sockfd;
                pkt->len = len;
                pkt->dst_id = dst_id;
                memcpy(pkt->dst_addr, peeraddr, sizeof(struct sockaddr_in));
                memcpy(pkt->buf_packet, buf_send, len);
                pq_node_t node2;
                node2.priority = UDP_DUP_DELAY;
                node2.data = node1;
                if(pq_enq(&global_tick_queue, &node2) == 0)
                    global_tick_queue.sorted = 0;
                else
                    DEBUG("append delay_pkt into tick_queue failed");
            }
            
            if(pthread_spin_unlock(&global_tick_queue_spin) != 0)
            {
                ERROR(errno, "pthread_spin_unlock");
                continue;
            }

            // DEBUG("dup send packet");
            // len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
            // if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0 )
            //     ERROR(errno, "tunif %s sendto dst_id %d.%d socket error when dup", global_tunif.name, dst_id/256, dst_id%256);
        }

        continue;
    }

    free(peeraddr);
    free(buf_send);
    pthread_cleanup_pop(0);
    return NULL;
}

void* server_write(void *arg)
{
    pthread_cleanup_push(clean_lock_all, NULL);

    byte * buf_write = (byte *)malloc(TUN_MTU);
    int tunfd = 0;
    int len = 0;
    uint16_t dst_id = 0;

    while(global_running)
    {
        if(pthread_mutex_lock(&global_write_mutex) != 0)
        {
            ERROR(errno, "pthread_mutex_lock");
            continue;
        }
        
        while(global_write_last == global_write_first)
            pthread_cond_wait(&global_write_cond, &global_write_mutex);

        global_write_first = (global_write_first + 1) % WRITE_BUF_SIZE;
        tunfd = global_write_buf[global_write_first].write_fd;
        len = global_write_buf[global_write_first].len;
        dst_id = global_write_buf[global_write_first].dst_id;
        memcpy(buf_write, global_write_buf[global_write_first].buf_packet, len);
        
        if(pthread_mutex_unlock(&global_write_mutex) != 0)
            ERROR(errno, "pthread_mutex_unlock");
    
        if(write(tunfd, buf_write, len) < 0)
            ERROR(errno, "tunif %s write error of dst_id %d.%d", global_tunif.name, dst_id/256, dst_id%256);

        continue;
    }

    free(buf_write);
    pthread_cleanup_pop(0);
    return NULL;
}

void* watch_timer_recv(void *arg)
{
    pthread_cleanup_push(clean_lock_all, NULL);
    struct peer_profile_t ** peer_table = (struct peer_profile_t **)arg;
    struct epoll_event * evs = NULL;
    evs = calloc(EPOLL_MAXEVENTS, sizeof(struct epoll_event));
    uint64_t read_buf;
    uint16_t len_load, nr_aes_block, bigger_id;
    struct tunnel_header_t header_send;
    struct ack_msg_t ack_msg;
    byte * buf_load = (byte *)malloc(TUN_MTU);
    byte * buf_send = (byte *)malloc(ETH_MTU);
    byte buf_header[HEADER_LEN];
    byte * buf_psk;
    int i;
    for(i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    bzero(buf_load, TUN_MTU);

    while(global_running)
    {
        int n = epoll_wait(global_epoll_fd_recv, evs, EPOLL_MAXEVENTS, -1);
        if(n == -1)
        {
            ERROR(errno, "epoll_wait");
            continue;
        }
        
        int i;
        for(i = 0; i < n; i++)
        {
            struct ack_info_t * ai = (struct ack_info_t *)(evs[i].data.ptr);
            uint16_t ack_id = ai->src_id;
            if(read(ai->fd, &read_buf, sizeof(uint64_t)) < 0)
                continue;

            //to do:
            //for HEAD_TYPE_MSG packets, haven't assigned a seq number. this may be a weakness.
            //or use msg_seq/data_seq instead of local_seq.

            uint32_t now = time(NULL);
            header_send.time = htonl(now);
            header_send.seq_frag_off.bit.seq = 0;
            header_send.seq_frag_off.bit.frag = 0;
            header_send.seq_frag_off.bit.off = 0;
            header_send.seq_frag_off.u32 = htonl(header_send.seq_frag_off.u32);

            len_load = sizeof(struct ack_msg_t);
            header_send.m_type_len.bit.m = HEAD_MORE_FALSE;
            header_send.m_type_len.bit.type = HEAD_TYPE_MSG;
            header_send.m_type_len.bit.len = len_load;
            header_send.m_type_len.u16 = htons(header_send.m_type_len.u16);
            header_send.ttl_flag_random.bit.ttl = TTL_MIN;
            header_send.ttl_flag_random.bit.random = 0;
            header_send.ttl_flag_random.u16 = htons(header_send.ttl_flag_random.u16);
            header_send.dst_id = htons(ack_id);
            header_send.src_id = htons(global_self_id);
            
            ack_msg.src_id = htons(ai->src_id);
            ack_msg.dst_id = htons(ai->dst_id);
            ack_msg.ack_type = htonl(ai->type);
            ack_msg.timestamp = htonl(ai->timestamp);
            ack_msg.seq = ai->seq;

            // DEBUG("send ack %d:%d, type %d", ai->timestamp, ai->seq, ai->type);

            ack_msg.seq = htonl(ack_msg.seq);
            memcpy(buf_load, &ack_msg, len_load);

            bigger_id = ack_id > global_self_id ? ack_id : global_self_id;
            if(NULL == peer_table[bigger_id])
            {
                DEBUG("tunif %s read ack message to invalid peer: %d.%d!", global_tunif.name, bigger_id/256, bigger_id%256);
                continue;
            }
            buf_psk = peer_table[bigger_id]->psk;
            memcpy(buf_header, &header_send, HEADER_LEN);
            encrypt(buf_send, buf_header, global_buf_group_psk, AES_KEY_LEN);  //encrypt header with group PSK
            encrypt(buf_send+HEADER_LEN, buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv

            nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;
            int j;
            for(j=0; j<nr_aes_block; j++)
                encrypt(buf_send+HEADER_LEN+ICV_LEN+j*AES_TEXT_LEN, buf_load+j*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);

            int len = HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN;
            //int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
            int len_pad = 17;  //for debug only
            if(sendto(global_sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)peer_table[ack_id]->peeraddr, sizeof(struct sockaddr)) < 0 )
                ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", global_tunif.name, ack_id/256, ack_id%256);

            if(ai->cnt >= (ACK_NUM-1))
            {
                close(ai->fd);
                ai->fd = 0;
            }
            else
                ai->cnt++;
        }
        bzero(evs, n*sizeof(struct epoll_event));
    }

    free(buf_send);
    free(buf_load);
    pthread_cleanup_pop(0);
    return NULL;
}

void* server_recv(void *arg)
{
    pthread_cleanup_push(clean_lock_all, NULL);
    struct tunnel_header_t header_recv, header_send;
    struct peer_profile_t ** peer_table = (struct peer_profile_t **)arg;
    struct ack_msg_t ack_msg;
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
    byte * buf_psk;
    byte * buf_recv = (byte *)malloc(ETH_MTU);
    byte * buf_load = (byte *)malloc(TUN_MTU);
    byte * buf_send = (byte *)malloc(ETH_MTU);
    int i, type;
    for(i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    byte buf_header[HEADER_LEN];
    byte buf_icv[ICV_LEN];

    while(global_running)
    {
        if(recvfrom(global_sockfd, buf_recv, ETH_MTU, 0, (struct sockaddr *)peeraddr, &peeraddr_len) < HEADER_LEN+ICV_LEN)
        {
            ERROR(errno, "tunif %s recvfrom socket error", global_tunif.name);
            continue;
        }

        decrypt(buf_header, buf_recv, global_buf_group_psk, AES_KEY_LEN);  //decrypt header with group PSK
        memcpy(&header_recv, buf_header, HEADER_LEN);
        memcpy(&header_send, &header_recv, sizeof(struct tunnel_header_t));
        //header_recv.time = ntohl(header_recv.time);
        header_recv.ttl_flag_random.u16 = ntohs(header_recv.ttl_flag_random.u16);
        if(header_recv.ttl_flag_random.bit.random != 0)
        {
            DEBUG("tunif %s received packet: group not match!", global_tunif.name);
            continue;
        }
        
        dst_id = ntohs(header_recv.dst_id);
        src_id = ntohs(header_recv.src_id);
        bigger_id = dst_id > src_id ? dst_id : src_id;

        if(NULL == peer_table[bigger_id] || peer_table[bigger_id]->valid == false)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: invalid peer: %d.%d!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, bigger_id/256, bigger_id%256);
            continue;
        }
        //if(bigger_id != global_self_id && NULL == peer_table[bigger_id])
        if(src_id == 0 || src_id == 1 || src_id == global_self_id)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: invalid src_id!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }
        if(CHECK_RESTRICTED_IP && peer_table[src_id] != NULL && peer_table[src_id]->restricted == true)
        {
            //if dst_id == global_self_id, don't ckeck but write to tunif
            if(dst_id != global_self_id && binary_search(global_trusted_ip, 0, global_trusted_ip_cnt, peeraddr->sin_addr.s_addr) == -1)
            {
                DEBUG("tunif %s received packet from %d.%d to %d.%d: src_id addr not trusted!", 
                    global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
                continue;
            }
        }

        buf_psk = peer_table[bigger_id]->psk;

        encrypt(buf_icv, buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv
        if(strncmp((char*)buf_icv, (char*)(buf_recv+HEADER_LEN), ICV_LEN) != 0)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: icv doesn't match!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }
        //store the src's UDP socket only when src_id is bigger.
        //otherwise, the bigger id may forge any smaller id's source address.
        if(src_id > dst_id && !(peer_table[src_id]->restricted))
            memcpy(peer_table[src_id]->peeraddr, peeraddr, sizeof(struct sockaddr_in));

        header_recv.m_type_len.u16 = ntohs(header_recv.m_type_len.u16);
        len_load = header_recv.m_type_len.bit.len;
        type = header_recv.m_type_len.bit.type;
        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;

        if(type == HEAD_TYPE_MSG)
        {
            if(nr_aes_block > 10)
            {
                DEBUG("msg too long, drop it now! will handle it when msg has seq number in header.");
                continue;
            }
            //printf("============== recv msg type\n");
            for(i=0; i<nr_aes_block; i++)
                decrypt(buf_load+i*AES_TEXT_LEN, buf_recv+HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);
            memcpy(&ack_msg, buf_load, len_load);
            ack_msg.src_id = ntohs(ack_msg.src_id);
            ack_msg.dst_id = ntohs(ack_msg.dst_id);
            ack_msg.ack_type = ntohl(ack_msg.ack_type);
            ack_msg.timestamp = ntohl(ack_msg.timestamp);
            ack_msg.seq = ntohl(ack_msg.seq);

            // DEBUG(">>> recv ack %d:%d, type %d", ack_msg.timestamp, ack_msg.seq, ack_msg.ack_type);

            if(ack_msg.timestamp == global_local_time)
            {
                //printf("time == \n");
            }
            else if(ack_msg.timestamp == (global_local_time-1))
            {
                //printf("time -- \n");
            }
            else
            {
                //printf("time ------ \n");
                continue;
            }

            int max_seq = 0, min_seq = 0;
            if(ack_msg.ack_type == TIMER_TYPE_LAST)
            {
                int after_last_nr = 1;   //may adjust the num.
                min_seq = ack_msg.seq + 1;
                max_seq = (ack_msg.seq + after_last_nr) < peer_table[ack_msg.dst_id]->local_seq ? (ack_msg.seq + after_last_nr) : peer_table[ack_msg.dst_id]->local_seq;
            }
            else
            {
                min_seq = ack_msg.seq;
                max_seq = ack_msg.seq;
            }
            if(max_seq > SEQ_LEVEL_1)
                continue;

            int seq;
            for(seq = min_seq; seq <= max_seq; seq++)
            {
                uint32_t * pkt_index_array_pre = peer_table[ack_msg.dst_id]->pkt_index_array_pre;
                uint32_t * pkt_index_array_now = peer_table[ack_msg.dst_id]->pkt_index_array_now;
                
                uint32_t buf_index_pre = pkt_index_array_pre[seq];
                uint32_t buf_index_now = pkt_index_array_now[seq];
                if(buf_index_pre > SEND_BUF_SIZE || buf_index_now > SEND_BUF_SIZE)
                {
                    // DEBUG("buf_index_pre: %d, buf_index_now: %d", buf_index_pre, buf_index_now);
                    continue;
                }
    
                if(pthread_mutex_lock(&global_send_mutex) != 0)
                {
                    ERROR(errno, "pthread_mutex_lock");
                    ERROR(0, "ignore this ack_msg to dst_id: %d.%d", ack_msg.dst_id/256, ack_msg.dst_id%256);
                    continue;
                }

                uint32_t buf_index;
                if(global_send_buf[buf_index_pre].dst_id == ack_msg.dst_id && 
                    global_send_buf[buf_index_pre].src_id == ack_msg.src_id &&
                    global_send_buf[buf_index_pre].timestamp == ack_msg.timestamp &&
                    global_send_buf[buf_index_pre].seq == seq)
                {
                    buf_index = buf_index_pre;
                }
                else if(global_send_buf[buf_index_now].dst_id == ack_msg.dst_id && 
                    global_send_buf[buf_index_now].src_id == ack_msg.src_id &&
                    global_send_buf[buf_index_now].timestamp == ack_msg.timestamp &&
                    global_send_buf[buf_index_now].seq == seq)
                {
                    buf_index = buf_index_now;
                }
                else
                {
                    DEBUG("--- retrans packet not found, ack_type: %d", ack_msg.ack_type);
                    if(pthread_mutex_unlock(&global_send_mutex) != 0)
                        ERROR(errno, "pthread_mutex_unlock");
                    continue;  
                }
    
                int sockfd = global_send_buf[buf_index].send_fd;
                int len = global_send_buf[buf_index].len;
                dst_id = global_send_buf[buf_index].dst_id;
                memcpy(peeraddr, global_send_buf[buf_index].dst_addr, sizeof(struct sockaddr_in));
                memcpy(buf_send, global_send_buf[buf_index].buf_packet, len);

                pthread_cond_signal(&global_send_cond);
    
                if(pthread_mutex_unlock(&global_send_mutex) != 0)
                    ERROR(errno, "pthread_mutex_unlock");
            
                // DEBUG("=== resend packet %d:%d", global_send_buf[buf_index].timestamp, global_send_buf[buf_index].seq);

                int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
                if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)peeraddr, sizeof(*peeraddr)) < 0 )
                    ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", global_tunif.name, dst_id/256, dst_id%256);
            }

            continue;
        }
        
        uint32_t pkt_time = ntohl(header_recv.time);
        header_recv.seq_frag_off.u32 = ntohl(header_recv.seq_frag_off.u32);
        uint32_t pkt_seq = header_recv.seq_frag_off.bit.seq;

        if(pthread_spin_lock(&global_stat_spin) != 0)
        {
            ERROR(errno, "pthread_spin_lock");
            continue;
        }
        int fs = flow_filter(pkt_time, pkt_seq, src_id, dst_id, peer_table);
        if(pthread_spin_unlock(&global_stat_spin) != 0)
        {
            ERROR(errno, "pthread_spin_unlock");
            continue;
        }
        if(fs == -2)
            DEBUG("tunif %s received packet from %d.%d to %d.%d: replay limit exceeded!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
        if(fs == -6)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: replay limit exceeded!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            DEBUG("tunif %s set peer %d.%d to invalid: involve limit exceeded!", 
                global_tunif.name, dst_id/256, dst_id%256);
        }
        if(fs == -3)
            DEBUG("tunif %s received packet from %d.%d to %d.%d: time jump limit exceeded!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
        if(fs == -5)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: time jump limit exceeded!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            DEBUG("tunif %s set peer %d.%d to invalid: involve limit exceeded!", 
                global_tunif.name, dst_id/256, dst_id%256);
        }
        if(fs < 0)
            continue;

        //todo: do I need to add a lock here?
        check_timerfd(pkt_time, pkt_seq, src_id, dst_id, peer_table);
        
        for(i=0; i<nr_aes_block_ipv4_header; i++)
            decrypt(buf_load+i*AES_TEXT_LEN, buf_recv+HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);
        
        memcpy(&ip_h, buf_load, IPV4_HEAD_LEN);
        memcpy(&ip_saddr, &ip_h.saddr, sizeof(uint32_t));
        memcpy(&ip_daddr, &ip_h.daddr, sizeof(uint32_t));

        uint32_t daddr, saddr; //network byte order

        if(header_recv.ttl_flag_random.bit.src_inside == true)
        {
            saddr = (global_tunif.addr & global_tunif.mask) | ip_h.saddr;
            ip_snat(buf_load, saddr);
        }
        else
            saddr = ip_h.saddr;

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
            DEBUG("tunif %s received packet from %d.%d to %d.%d: probe packet, drop it!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }

        if(0 == next_id)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: no route!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }
        else if(1 == next_id || global_self_id == next_id) //write to local tunif
        {
            for(i=nr_aes_block_ipv4_header; i<nr_aes_block; i++)
                decrypt(buf_load+i*AES_TEXT_LEN, buf_recv+HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);

            bool delay = should_pkt_delay(NULL, buf_load);
            if(delay)
            {
                // DEBUG("should delay");

                if(pthread_spin_lock(&global_tick_queue_spin) != 0)
                {
                    ERROR(errno, "pthread_spin_lock");
                    continue;
                }

                ll_node_t * node1 = ll_array_borrow(global_tick_list_head);  // malloc from the list and it's data pointer.

                if(node1 == NULL)
                    ERROR(0, "tick_queue write_buf is full, drop this packet to next id: %d.%d", dst_id/256, dst_id%256);
                else
                {
                    struct packet_profile_t * pkt = (struct packet_profile_t *)(node1->data);
                    start_timer(&(pkt->ms_timer), ACK_WRITE_DELAY);
                    pkt->type = pkt_write;
                    pkt->src_id = src_id;
                    pkt->dst_id = dst_id;
                    pkt->write_fd = global_tunfd;
                    pkt->len = len_load;
                    memcpy(pkt->dst_addr, peeraddr, sizeof(struct sockaddr_in));
                    memcpy(pkt->buf_packet, buf_load, len_load);

                    pq_node_t node2;
                    node2.priority = ACK_WRITE_DELAY;
                    node2.data = node1;

                    if(pq_enq(&global_tick_queue, &node2) == 0)
                        global_tick_queue.sorted = 0;
                    else
                        DEBUG("append ACK into tick_queue failed");
                }
                
                if(pthread_spin_unlock(&global_tick_queue_spin) != 0)
                {
                    ERROR(errno, "pthread_spin_unlock");
                    continue;
                }
            }
            else
            {
                // DEBUG("should write now");
                //copy write packet to write thread
                if(pthread_mutex_lock(&global_write_mutex) != 0)
                {
                    ERROR(errno, "pthread_mutex_lock");
                    ERROR(0, "Drop this packet to next id: %d.%d", dst_id/256, dst_id%256);
                    continue;
                }
        
                if((global_write_last + 1) % WRITE_BUF_SIZE == global_write_first)
                    ERROR(0, "write_buf is full, drop this packet to next id: %d.%d", dst_id/256, dst_id%256);
                else
                {
                    global_write_last = (global_write_last + 1) % WRITE_BUF_SIZE;
                    global_write_buf[global_write_last].src_id = src_id;
                    global_write_buf[global_write_last].dst_id = dst_id;
                    global_write_buf[global_write_last].write_fd = global_tunfd;
                    global_write_buf[global_write_last].len = len_load;
                    memcpy(global_write_buf[global_write_last].dst_addr, peeraddr, sizeof(struct sockaddr_in));
                    memcpy(global_write_buf[global_write_last].buf_packet, buf_load, len_load);
                }
        
                pthread_cond_signal(&global_write_cond);
        
                if(pthread_mutex_unlock(&global_write_mutex) != 0)
                    ERROR(errno, "pthread_mutex_unlock");
            }

            continue;
        }
        else  //switch to next_id or dst_id
        {
            ttl = header_recv.ttl_flag_random.bit.ttl;
            //packet dst is not local and ttl expire, drop packet. only allow 16 hops
            if(TTL_MIN == ttl)
            {
                WARNING("TTL expired! from %d.%d.%d.%d to %d.%d.%d.%d.",
                    ip_saddr.a, ip_saddr.b, ip_saddr.c, ip_saddr.d,
                    ip_daddr.a, ip_daddr.b, ip_daddr.c, ip_daddr.d);   
                continue;
            }

            if(ALLOW_P2P != true)
                if(header_recv.ttl_flag_random.bit.src_inside == true && header_recv.ttl_flag_random.bit.dst_inside == true)
                {
                    DEBUG("tunif %s received packet from %d.%d to %d.%d: peer_table not allowed!", 
                        global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
                    continue;
                }

            if(NULL == peer_table[next_id])
            {
                DEBUG("tunif %s recv packet from %d.%d to %d.%d: route to invalid next peer: %d.%d!", 
                    global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, next_id/256, next_id%256);
                continue;
            }
            if(NULL == peer_table[next_id]->peeraddr)
            {
                DEBUG("tunif %s recv packet from %d.%d to %d.%d: route to next peer %d.%d: invalid addr!", 
                    global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, next_id/256, next_id%256);
                continue;
            }

            //split horizon
            if(peeraddr->sin_addr.s_addr == peer_table[next_id]->peeraddr->sin_addr.s_addr &&
                peeraddr->sin_port == peer_table[next_id]->peeraddr->sin_port)
            {
                DEBUG("tunif %s recv packet from %d.%d to %d.%d: next peer is %d.%d, dst addr equals src addr!", 
                    global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, next_id/256, next_id%256);
                continue;
            }
            else
                memcpy(peeraddr, peer_table[next_id]->peeraddr, sizeof(struct sockaddr_in));

            ttl--;
            header_send.ttl_flag_random.bit.ttl = ttl;
            header_send.ttl_flag_random.bit.src_inside = header_recv.ttl_flag_random.bit.src_inside;
            header_send.ttl_flag_random.bit.dst_inside = header_recv.ttl_flag_random.bit.dst_inside;
            header_send.ttl_flag_random.bit.random = 0;
            header_send.ttl_flag_random.u16 = htons(header_send.ttl_flag_random.u16);

            // after reducing ttl, should re-encrypt header and icv
            memcpy(buf_header, &header_send, HEADER_LEN);
            encrypt(buf_recv, buf_header, global_buf_group_psk, AES_KEY_LEN);  //encrypt header with group PSK
            encrypt(buf_recv+HEADER_LEN, buf_header, buf_psk, AES_KEY_LEN);  //encrypt header to generate icv

            bool dup = should_pkt_dup(peer_table[bigger_id], buf_load);

            //copy send packet to send thread
            if(pthread_mutex_lock(&global_send_mutex) != 0)
            {
                ERROR(errno, "pthread_mutex_lock");
                ERROR(0, "drop this packet to next id: %d.%d", next_id/256, next_id%256);
                continue;
            }
    
            if((global_send_last + 1) % SEND_BUF_SIZE == global_send_first)
                ERROR(0, "send_buf is full, drop this packet to next id: %d.%d", next_id/256, next_id%256);
            else
            {
                int len = HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN;
                global_send_last = (global_send_last + 1) % SEND_BUF_SIZE;
                global_send_buf[global_send_last].src_id = src_id;
                global_send_buf[global_send_last].dst_id = dst_id;
                global_send_buf[global_send_last].send_fd = global_sockfd;
                global_send_buf[global_send_last].len = len;
                global_send_buf[global_send_last].dup = dup;
                memcpy(global_send_buf[global_send_last].dst_addr, peeraddr, sizeof(struct sockaddr_in));
                memcpy(global_send_buf[global_send_last].buf_packet, buf_recv, len);
                if(pkt_seq < SEQ_LEVEL_1)
                {
                    if(fs == 3 && pkt_seq == 0) //time_diff == 1, swap only once.
                    {
                        uint32_t * tmp_index = peer_table[dst_id]->pkt_index_array_pre;
                        peer_table[dst_id]->pkt_index_array_pre = peer_table[dst_id]->pkt_index_array_now;
                        peer_table[dst_id]->pkt_index_array_now = tmp_index;
                    }
                    if(fs == 1) //time_diff == -1
                        peer_table[dst_id]->pkt_index_array_pre[pkt_seq] = global_send_last;
                    else
                        peer_table[dst_id]->pkt_index_array_now[pkt_seq] = global_send_last;
                }
            }
    
            pthread_cond_signal(&global_send_cond);
    
            if(pthread_mutex_unlock(&global_send_mutex) != 0)
                ERROR(errno, "pthread_mutex_unlock");

            continue;
        }
    }

    free(peeraddr);
    free(buf_recv);
    free(buf_load);
    free(buf_send);
    pthread_cleanup_pop(0);
    return NULL;
}

int check_timerfd(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, struct peer_profile_t ** peer_table)
{
    if(ACK_NUM <= 0)  // don't send any ack msg
        return 0;

    struct timerfd_info_t * ti = peer_table[src_id]->timerfd_info;
    struct flow_profile_t * fp = peer_table[src_id]->flow_src;
    struct bit_array_t * ba = NULL;

    if(pkt_seq >= ti->ack_array_size)
    {
        DEBUG("pkt_seq beyond ack_array_size, ignore this packet from %d.%d to %d.%d.", 
            src_id/256, src_id%256, dst_id/256, dst_id%256);
        return 0;
    }
    
    int time_diff = pkt_time - ti->time_now;
    if(time_diff >= 1 || time_diff <= -MAX_DELAY_TIME)
    {
        if(time_diff == 1)
        {
            close_all_timerfd(ti->ack_array_pre, SEQ_LEVEL_1);  //this function slows down the tunnel from 100% to about 98% bps. don't care it now.
            struct ack_info_t * tmp_info = ti->ack_array_pre;
            ti->ack_array_pre = ti->ack_array_now;
            ti->ack_array_now = tmp_info;
            ti->max_ack_pre = ti->max_ack_now;
            ti->max_ack_now = pkt_seq;
        }
        else
        {
            close_all_timerfd(ti->ack_array_pre, SEQ_LEVEL_1);
            close_all_timerfd(ti->ack_array_now, SEQ_LEVEL_1);
            ti->max_ack_pre = 0;
            ti->max_ack_now = pkt_seq;  //don't set max_ack_now to timer_nr, otherwise fd_max_cnt doesn't make sense.
        }

        ti->time_now = pkt_time;
        ti->time_pre = pkt_time - 1;
        
        struct ack_info_t * ack_array = ti->ack_array_now;
        
        int timer_nr = (pkt_seq < ti->fd_max_cnt) ? pkt_seq : ti->fd_max_cnt;  //only create timer for the first fd_max_cnt pkt, to avoid too many ack msg
        int i;
        for(i = 0; i < timer_nr; i++)
        {
            ack_array[i].cnt = 0;
            ack_array[i].src_id = src_id;
            ack_array[i].dst_id = dst_id;
            ack_array[i].timestamp = pkt_time;
            ack_array[i].seq = i;
            add_timerfd_epoll(global_epoll_fd_recv, TIMER_TYPE_MID, &(ack_array[i]));
        }

        ack_array[pkt_seq].cnt = 0;
        ack_array[pkt_seq].src_id = src_id;
        ack_array[pkt_seq].dst_id = dst_id;
        ack_array[pkt_seq].timestamp = pkt_time;
        ack_array[pkt_seq].seq = pkt_seq;
        add_timerfd_epoll(global_epoll_fd_recv, TIMER_TYPE_LAST, &(ack_array[pkt_seq]));
    }
    else if(time_diff == 0 || time_diff == -1)
    {
        uint32_t max_ack_seq = 0;
        struct ack_info_t * ack_array = NULL;
        if(time_diff == 0)
        {
            ack_array = ti->ack_array_now;
            max_ack_seq = ti->max_ack_now;
            if(pkt_seq > max_ack_seq)
                ti->max_ack_now = pkt_seq;
            ba = fp->ba_now;
        }
        else if(time_diff == -1)
        {
            ack_array = ti->ack_array_pre;
            max_ack_seq = ti->max_ack_pre;
            if(pkt_seq > max_ack_seq)
                ti->max_ack_pre = pkt_seq;
            ba = fp->ba_pre;
        }

        //if(pkt_seq == max_ack_seq), do nothing.
        if(pkt_seq < max_ack_seq && ack_array[pkt_seq].fd != 0)
        {
            //printf("close: mid %d\n", pkt_seq);
            close(ack_array[pkt_seq].fd);
            ack_array[pkt_seq].fd = 0;
        }
        else if(pkt_seq > max_ack_seq)
        {
            //printf("close: max %d\n", max_ack_seq);
            close(ack_array[max_ack_seq].fd);
            ack_array[max_ack_seq].fd = 0;

            ack_array[pkt_seq].cnt = 0;
            ack_array[pkt_seq].src_id = src_id;
            ack_array[pkt_seq].dst_id = dst_id;
            ack_array[pkt_seq].timestamp = pkt_time;
            ack_array[pkt_seq].seq = pkt_seq;
            add_timerfd_epoll(global_epoll_fd_recv, TIMER_TYPE_LAST, &(ack_array[pkt_seq]));

            int lost_nr = pkt_seq - max_ack_seq;
            int timer_nr = (lost_nr < ti->fd_max_cnt) ? lost_nr : ti->fd_max_cnt;  //only create timer for the first fd_max_cnt pkt, to avoid too many ack msg
            int i;
            for(i = max_ack_seq+1; i < max_ack_seq+timer_nr; i++)
            {
                //if HEAD_TYPE_MSG/HEAD_TYPE_DATA share the same seq number, it will be diffict to handle here.
                //if the msg lost, there will be a timerfd too, that's wrong.
                if(bit_array_get(ba, i) == 0)
                {
                    ack_array[i].cnt = 0;
                    ack_array[i].src_id = src_id;
                    ack_array[i].dst_id = dst_id;
                    ack_array[i].timestamp = pkt_time;
                    ack_array[i].seq = i;
                    add_timerfd_epoll(global_epoll_fd_recv, TIMER_TYPE_MID, &(ack_array[i]));
                }
            }
        }
    }

    return 0;
}

//this function slows down the tunnel from 100% to 70% bps. should rewrite it latter.
int add_timerfd_epoll(int epfd, uint8_t type, struct ack_info_t * info)
{
    if(type == TIMER_TYPE_LAST)
        return 0; // don't send last recived ack, because I found it useless, only cause dup packets.

    struct itimerspec new_value;
    new_value.it_value.tv_sec = 0;
    new_value.it_value.tv_nsec = ACK_FIRST_TIME;
    new_value.it_interval.tv_sec = 0;
    new_value.it_interval.tv_nsec = ACK_INTERVAL;

    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if(fd == -1)
    {
        ERROR(errno, "timerfd_create");
        return -1;
    }
    if(timerfd_settime(fd, 0, &new_value, NULL) == -1)
    {
        ERROR(errno, "timerfd_settime");
        close(fd);
        return -1;
    }
    info->fd = fd;
    info->type = type;
    
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = (void *)info;
    if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1)
    {
        ERROR(errno, "epoll_ctl");
        close(fd);
        return -1;
    }

    return 0;
}

/*
  need to filter 2 elements:pkt_time and pkt_seq;
  1) pkt_time can NOT run too fast, if faster than system, let's call it a jump. if too many jumps, then it may be an attack.
  2) pkt_seq can NOT duplicate.

  return value: return 0, valid packet; return negative number, invalid packet.
  invalid packets will be droped.
*/
int flow_filter(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, struct peer_profile_t ** peer_table)
{
    // DEBUG("=== recv pkt, %d:%d", pkt_time, pkt_seq);

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
            // DEBUG("---------- recv dup, %d:%d, time_diff: 0", pkt_time, pkt_seq);
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
            // DEBUG("---------- recv dup, %d:%d, time_diff: -1", pkt_time, pkt_seq);
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
