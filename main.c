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
#include "secret.h"
#include "ip.h"
#include "tunnel.h"
#include "header.h"
#include "config.h"
#include "cmd_helper.h"

#include "data-struct/data-struct.h"

#define PROCESS_NAME    "alpaca-tunnel"
#define VERSION         "4.2.1"

/*
 * Config file path choose order:
 * 1) if user specify the path with -C, this path will be used.
 * 2) if exe is located at `/usr/bin/`, config will be `/etc/alpaca-tunnel.d/config.json`.
 * 3) if exe is located at `/usr/local/bin/`, config will be `/usr/local/etc/alpaca-tunnel.d/config.json`.
 * 4) config will be at the relative path `alpaca-tunnel.d/config.json` to exe file.
 *
 * Secret file path choose order:
 * 1) if user specify the path in json, this path will be used. if this path is a relative path, it's relative to the config json.
 * 2) Otherwise, the secret file MUST be located at the relative path `./secrets` to the config json, NOT with exe!
*/

#define ABSOLUTE_PATH_TO_JSON        "/etc/alpaca-tunnel.d/config.json"
#define ABSOLUTE_PATH_TO_JSON_LOCAL  "/usr/local/etc/alpaca-tunnel.d/config.json"
#define RELATIVE_PATH_TO_JSON        "alpaca-tunnel.d/config.json"
#define RELATIVE_PATH_TO_SECRETS     "secrets"
#define RELATIVE_PATH_TO_ROUTE       "route_data_cidr"
#define CONFIG_JSON_NAME             "config.json"
#define SECRET_NAME                  "secrets"

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
typedef struct
{
    int type;
    uint16_t src_id;
    uint16_t dst_id;
    bool forward;
    uint32_t timestamp;
    uint32_t seq;
    int send_fd;
    int write_fd;
    int timer_fd;
    int send_cnt;
    int len;
    bool dup;
    timer_ms_t ms_timer;
    struct sockaddr_in dst_addr;  // only used when dup send pkt
    struct sockaddr_in src_addr;  // if forward == true, this is the recv peeraddr, used to check split horizon
    byte * buf_packet;
} packet_profile_t;

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


static queue_t * global_send_q = NULL;
static queue_t * global_write_q = NULL;
static tick_queue_t * global_delay_q = NULL;

static int global_running = 0;
static int global_sysroute_change = 0;
static int global_secret_change = 0;
static uint16_t global_self_id = 0;
static uint global_pkt_cnt = 0;
static pthread_mutex_t global_stat_lock;
static pthread_mutex_t global_time_seq_lock;
// static pthread_mutex_t global_tick_queue_lock;

//in network byte order.
static if_info_t global_tunif;
static if_info_t *global_if_list;

static char global_exe_path[PATH_LEN] = "\0";
static char global_json_path[PATH_LEN] = "\0";
static char global_secrets_path[PATH_LEN] = "\0";
static char global_secret_dir[PATH_LEN] = "\0";
static char global_config_dir[PATH_LEN] = "\0";

enum {mode_none, mode_server, mode_client} global_mode = mode_none;
static byte global_buf_group_psk[2*AES_TEXT_LEN] = "FUCKnimadeGFW!";
static int global_tunfd, global_sockfd;
static uint32_t global_local_time;
//static uint32_t global_local_seq;
static int64_t* global_trusted_ip = NULL;  // int64_t can hold uint32_t(IPv4 address)
static int global_trusted_ip_cnt = 0;

// static queue_t global_tick_queue;

static uint16_t * global_forwarders = NULL;
static int global_forwarder_nr = 0;

void* pkt_delay_dup(void *arg);

//client_read and client_recv are obsoleted
void* client_read(void *arg);
void* client_recv(void *arg);

void* server_read(void *arg);
void* server_recv(void *arg);
void* server_write(void *arg);
void* server_send(void *arg);

void* server_reset_stat(void *arg);
void* watch_link_route(void *arg);
void* watch_secret(void *arg);
void* update_secret(void *arg);
void* reset_link_route(void *arg);
void clean_lock_all(void *arg);
int init_global_values();

int usage(char *pname);
void sig_handler(int signum);
int flow_filter(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, peer_profile_t ** peer_table);

/* get next hop id form route_table or system route table
 * return value:
 * 0 : actually, will never return 0. instead, return 1.
 * 1 : local or link dst, should write to tunnel interface
 * >1: the ID of other tunnel server
 * if next_hop_id == global_self_id, return 1
*/
uint16_t get_next_hop_id(uint32_t ip_dst, uint32_t ip_src);
uint16_t get_dst_id(uint32_t ip_dst, uint32_t ip_src);

int chnroute_add(char * data_path, uint32_t gw_ip, int table, int gw_dev);
int chnroute_del(char * data_path, int table);


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
    pthread_mutex_unlock(&global_stat_lock);
    unlock_route_mutex();

    return;
}

int init_global_values()
{
    if(init_route_lock() < 0)
    {
        ERROR(0, "init_route_lock");
        return -1;
    }
    if(pthread_mutex_init(&global_stat_lock, NULL) != 0)
    {
        ERROR(errno, "pthread_mutex_init");
        return -1;
    }
    if(pthread_mutex_init(&global_time_seq_lock, NULL) != 0)
    {
        ERROR(errno, "pthread_mutex_init");
        return -1;
    }

    global_send_q = queue_init(QUEUE_TYPE_FIFO);
    global_write_q = queue_init(QUEUE_TYPE_FIFO);
    global_delay_q = tick_queue_init();

    return 0;
}

int destory_global_values()
{
    destroy_route_lock();
    pthread_mutex_destroy(&global_stat_lock);
    pthread_mutex_destroy(&global_time_seq_lock);

    queue_destroy(global_send_q, NULL);
    queue_destroy(global_write_q, NULL);
    tick_queue_destroy(global_delay_q, NULL);

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

    if(HEADER_LEN != sizeof(tunnel_header_t))
    {
        ERROR(0, "header size error!");
        INFO("sizeof tunnel_header_t: %d", sizeof(tunnel_header_t));
        INFO("sizeof type_len_m_u: %d", sizeof(union type_len_m_u));
        INFO("sizeof pi_u: %d", sizeof(union pi_u));
        INFO("sizeof struct pi_s: %d", sizeof(struct pi_s));
        INFO("sizeof ttl_pi_sd_u: %d", sizeof(union ttl_pi_sd_u));
        INFO("sizeof ttl_pi_sd_s: %d", sizeof(struct ttl_pi_sd_s));
        INFO("sizeof seq_rand_u: %d", sizeof(union seq_rand_u));
        exit(1);
    }

    /******************* init global/main variables *******************/

    srandom(time(NULL));

    peer_profile_t ** peer_table = NULL;
    config_t config;
    memset(&config, 0, sizeof(config));

    bool start_success = false;
    bool default_route_changed = false;
    bool chnroute_set = false;
    bool server_ip_route_added = false;

    char default_gw_ip[IP_LEN] = "\0";
    char default_gw_dev[IFNAMSIZ] = "\0";
    char chnroute_path[PATH_LEN] = "\0";
    int chnroute_table = 0;

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

        if(str_equal(global_exe_path, "/usr/bin/"))
            strcpy(global_json_path, ABSOLUTE_PATH_TO_JSON);
        else if(str_equal(global_exe_path, "/usr/local/bin/"))
            strcpy(global_json_path, ABSOLUTE_PATH_TO_JSON_LOCAL);
        else
        {
            strcpy(global_json_path, global_exe_path);
            strcat(global_json_path, RELATIVE_PATH_TO_JSON);
        }
    }

    strcpy(global_config_dir, global_json_path);
    path_len = strlen(global_config_dir);
    while(global_config_dir[path_len] != '/' && path_len >= 0)
    {
        global_config_dir[path_len] = '\0';
        path_len--;
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

    if(str_equal(config.mode, "client"))
        global_mode = mode_client;
    else if(str_equal(config.mode, "server"))
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
            if(get_default_route(default_gw_ip, default_gw_dev) == 0)
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

    global_forwarders = (uint16_t *)malloc(config.forwarder_nr * sizeof(uint16_t));
    global_forwarder_nr = config.forwarder_nr;
    int forwarder_nr = 0;
    while(!queue_is_empty(config.forwarders))
    {
        char * forwarder_str = NULL;
        queue_get(config.forwarders, (void **)&forwarder_str, NULL);
        int forwarder_id = inet_ptons(forwarder_str);
        global_forwarders[forwarder_nr] = forwarder_id;
        forwarder_nr++;
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

    strcpy(global_secret_dir, global_secrets_path);
    path_len = strlen(global_secret_dir);
    while(global_secret_dir[path_len] != '/' && path_len >= 0)
    {
        global_secret_dir[path_len] = '\0';
        path_len--;
    }

    DEBUG("config_dir: %s", global_config_dir);
    INFO("json_path: %s", global_json_path);
    DEBUG("secret_dir: %s", global_secret_dir);
    INFO("secrets_path: %s", global_secrets_path);
    

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
        {
            if(peer_table[i] != NULL && peer_table[i]->path_array[0].peeraddr.sin_addr.s_addr != 0)
            {
                global_trusted_ip[global_trusted_ip_cnt] = peer_table[i]->path_array[0].peeraddr.sin_addr.s_addr;
                global_trusted_ip_cnt++;
            }
        }
        merge_sort(global_trusted_ip, global_trusted_ip_cnt);
    }


    /******************* setup tunnel interface *******************/

    // before bring tunnel interface up
    run_cmd_list(config.pre_up_cmds);

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
    run_cmd_list(config.post_up_cmds);

    enable_ip_forward();

    if(config.chnroute)
    {
        if(config.chnroute->data == NULL)
        {
            strcpy(chnroute_path, global_config_dir);
            strcat(chnroute_path, RELATIVE_PATH_TO_ROUTE);
        }
        else if(config.chnroute->data[0] == '/')
            strcpy(chnroute_path, config.chnroute->data);
        else
        {
            strcpy(chnroute_path, global_config_dir);
            strcat(chnroute_path, config.chnroute->data);
        }

        uint32_t gw_ip = 0;
        int gw_dev = 0;
        chnroute_table = get_rt_table(config.chnroute->table);
        if(chnroute_table == 0)
        {
            chnroute_table = RT_TABLE_DEFAULT;
            WARNING("will use table default %d for chnroute.", chnroute_table);
        }

        if(default_gw_ip[0] != '\0')
            inet_pton(AF_INET, default_gw_ip, &gw_ip);
        if(default_gw_dev[0] != '\0')
            gw_dev = get_strif_local(default_gw_dev, global_if_list);

        if(config.chnroute->gateway == NULL || str_equal(config.chnroute->gateway, "default"))
            ;
        else
            inet_pton(AF_INET, config.chnroute->gateway, &gw_ip);

        if(chnroute_add(chnroute_path, gw_ip, chnroute_table, gw_dev) == 0)
            chnroute_set = true;
    }

    // setup route
    if(global_mode == mode_client)
    {
        char gw_ip_str[IP_LEN];
        sprintf(gw_ip_str, "%s.%s", config.net, config.gateway);
    
        if(default_gw_ip[0] != '\0' || default_gw_dev[0] != '\0')
        {
            change_default_route(gw_ip_str, NULL);
            default_route_changed = true;
        }

        for(int i = 0; i < MAX_ID+1; i++)
        {
            server_ip_route_added = true;
            if(peer_table[i] != NULL && peer_table[i]->path_array[0].peeraddr.sin_addr.s_addr != 0)
            {
                struct in_addr in;
                in.s_addr = peer_table[i]->path_array[0].peeraddr.sin_addr.s_addr;
                char * server_ip_str = inet_ntoa(in);
                add_iproute(server_ip_str, default_gw_ip, default_gw_dev, "default");
            }
        }

        while(!queue_is_empty(config.local_routes))
        {
            char * local_route;
            queue_get(config.local_routes, (void **)&local_route, NULL);
            add_iproute(local_route, default_gw_ip, default_gw_dev, "default");
            DEBUG("add local_route: %s to table default", local_route);
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

    pthread_t tid1=0, tid2=0, tid3=0, tid4=0, tid5=0, tid6=0, tid7=0, tid8=0, tid9=0, tid11=0;

    if(pthread_create(&tid1, NULL, server_recv, peer_table) != 0)
    {
        ERROR(errno, "pthread_error: create rc1"); 
        goto _END;
    }
    if(pthread_create(&tid2, NULL, server_read, peer_table) != 0)
    {
        ERROR(errno, "pthread_error: create rc2"); 
        goto _END;
    }
    if(pthread_create(&tid3, NULL, server_write, peer_table) != 0)
    {
        ERROR(errno, "pthread_error: create rc3"); 
        goto _END;
    }
    if(pthread_create(&tid4, NULL, server_send, peer_table) != 0)
    {
        ERROR(errno, "pthread_error: create rc4"); 
        goto _END;
    }

    if(pthread_create(&tid5, NULL, watch_link_route, NULL) != 0)
    {
        ERROR(errno, "pthread_error: create rc5"); 
        goto _END;
    }
    if(pthread_create(&tid6, NULL, reset_link_route, NULL) != 0)
    {
        ERROR(errno, "pthread_error: create rc6"); 
        goto _END;
    }
    if(pthread_create(&tid7, NULL, watch_secret, NULL) != 0)
    {
        ERROR(errno, "pthread_error: create rc7"); 
        goto _END;
    }
    if(pthread_create(&tid8, NULL, update_secret, peer_table) != 0)
    {
        ERROR(errno, "pthread_error: create rc8"); 
        goto _END;
    }
    if(pthread_create(&tid9, NULL, server_reset_stat, peer_table) != 0)
    {
        ERROR(errno, "pthread_error: create rc9"); 
        goto _END;
    }

    if(pthread_create(&tid11, NULL, pkt_delay_dup, NULL) != 0)
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
    pthread_cancel(tid11);

    // what happens to a locked lock when cancel the thread?
    // what happens when destory a locked lock?


/******************* clear env *******************/

_END:

    global_running = 0;

    if(global_mode == mode_client)
    {
        if(default_route_changed)
            restore_default_route(default_gw_ip, default_gw_dev);

        for(int i = 0; i < MAX_ID+1; i++)
            if(server_ip_route_added && peer_table != NULL && peer_table[i] != NULL && peer_table[i]->path_array[0].peeraddr.sin_addr.s_addr != 0)
            {
                struct in_addr in;
                in.s_addr = peer_table[i]->path_array[0].peeraddr.sin_addr.s_addr;
                char * server_ip_str = inet_ntoa(in);
                del_iproute(server_ip_str, "default");
            }

        while(!queue_is_empty(config.local_routes_bakup))
        {
            char * local_route;
            queue_get(config.local_routes_bakup, (void **)&local_route, NULL);
            del_iproute(local_route, "default");
            DEBUG("add local_route: %s to table default", local_route);
        }
    }

    if(chnroute_set == true)
        chnroute_del(chnroute_path, chnroute_table);

    if(global_mode == mode_server)
    {
        char tun_net[IP_LEN+4];
        sprintf(tun_net, "%s.0.0/%d", config.net, TUN_MASK_LEN);
        del_iptables_nat(tun_net);
    }

    del_iptables_tcpmss(TCPMSS);

    // before turn tunnel interface down 
    run_cmd_list(config.pre_down_cmds);

    // close the fd will delete the tunnel interface.
    close(global_tunfd);

    // after turn tunnel interface down 
    run_cmd_list(config.post_down_cmds);

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


int chnroute(char * data_path, uint32_t gw_ip, int gw_dev, int table, int action)
{
    if(access(data_path, R_OK) == -1)
    {
        ERROR(errno, "cann't read route data: %s", data_path);
        return -1;
    }
    
    FILE *chnroute_file = NULL;
    if((chnroute_file = fopen(data_path, "r")) == NULL)
    {
        ERROR(errno, "open file: %s", data_path);
        return -1;
    }
    
    INFO("route_data: %s", data_path);
    INFO("start chnroute");
    
    int i = 1;
    size_t len = 1024;
    char *line = (char *)malloc(len);
    while(-1 != getline(&line, &len, chnroute_file))
    {
        char *ip_str = NULL;
        char *mask_str = NULL;
        ip_str = strtok(line, "/");
        mask_str = strtok(NULL, "/");
        
        int mask = 0;
        if(mask_str != NULL)
            mask = atoi(mask_str);
    
        if(mask < 1)
        {
            WARNING("line %d, mask may be wrong or too small: %s", i, mask_str);
            continue;
        }
        else
        {
            uint32_t ip_dst_tmp;
            if(inet_pton(AF_INET, ip_str, &ip_dst_tmp) == 1)
            {
                if(action == 0)
                    add_sys_iproute(ip_dst_tmp, mask, gw_ip, gw_dev, table);
                else if(action == 1)
                    del_sys_iproute(ip_dst_tmp, mask, gw_ip, gw_dev, table);
                else
                    WARNING("chnroute action not supported: %d", action);
            }
            else
                WARNING("line %d, IP may be wrong: %s", i, ip_str);
        }
        i++;
    }
    free(line);
    fclose(chnroute_file);
    
    INFO("end chnroute");

    return 0;
}

int chnroute_add(char * data_path, uint32_t gw_ip, int table, int gw_dev)
{
    return chnroute(data_path, gw_ip, gw_dev, table, 0);
}

int chnroute_del(char * data_path, int table)
{
    return chnroute(data_path, 0, 0, table, 1);
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

uint16_t get_dst_id(uint32_t ip_dst, uint32_t ip_src)
{
    // ip_dst is in tunif's subnet
    if((ip_dst & global_tunif.mask) == (global_tunif.addr & global_tunif.mask))
        return (uint16_t)ntohl(ip_dst);

    // ip_dst is via default gateway
    // todo: get the default gateway should be enough
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


void* pkt_delay_dup(void *arg)
{
    struct sockaddr_in peeraddr;
    byte * buf_write = (byte *)malloc(TUN_MTU);
    byte * buf_send = (byte *)malloc(ETH_MTU);
    int i;
    for(i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    int sockfd = 0;
    int len = 0;
    uint16_t dst_id = 0;
    int tunfd = 0;

    while(global_running)
    {
        packet_profile_t * pkt;
        pkt = tick_queue_get(global_delay_q);
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
                ERROR(errno, "tunif %s write error of dst_id %d.%d", global_tunif.name, dst_id/256, dst_id%256);
        }

        if(pkt->type == pkt_send)
        {
            // DEBUG("send delayed pkt");
            sockfd = pkt->send_fd;
            len = pkt->len;

            dst_id = pkt->dst_id;
            peeraddr = pkt->dst_addr;
            memcpy(buf_send, pkt->buf_packet, len);

            int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
            if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr)) < 0 )
                ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", global_tunif.name, dst_id/256, dst_id%256);
        }

        delete_pkt(pkt);
    }

    free(buf_write);
    free(buf_send);
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

    wd = inotify_add_watch(fd, global_secret_dir, IN_MODIFY | IN_CREATE | IN_DELETE);
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
                if(str_equal(event->name, SECRET_NAME))
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
    peer_profile_t ** peer_table = (peer_profile_t **)arg;
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
                    if(peer_table[i] != NULL && peer_table[i]->path_array[0].peeraddr.sin_addr.s_addr != 0)
                    {
                        if(global_trusted_ip_cnt > MAX_ID)
                            continue;
                        global_trusted_ip[global_trusted_ip_cnt] = peer_table[i]->path_array[0].peeraddr.sin_addr.s_addr;
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
    rtnl_handle_t rth;
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
    peer_profile_t ** peer_table = (peer_profile_t **)arg;
    int peer_num = MAX_ID+1;
    //int pre = global_pkt_cnt;

    int i, j = 0;
    while(global_running)
    {
        sleep(RESET_STAT_INTERVAL);
        j++;
        for(i = 0; i < peer_num; i++)
        {
            peer_profile_t *p = peer_table[i];
            if(p != NULL)
            {
                if(pthread_mutex_lock(&global_stat_lock) != 0)
                {
                    ERROR(errno, "pthread_mutex_lock");
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
                if(pthread_mutex_unlock(&global_stat_lock) != 0)
                {
                    ERROR(errno, "pthread_mutex_unlock");
                    continue;
                }
            }
        }
    }
    pthread_cleanup_pop(0);
    return NULL;
}

bool should_pkt_dup(peer_profile_t * p, byte* ip_load)
{
    return false;

    if(p == NULL || p->tcp_info == NULL || ip_load == NULL)
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

bool should_pkt_delay(peer_profile_t * p, byte* ip_load)
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
    tunnel_header_t header_send;
    peer_profile_t ** peer_table = (peer_profile_t **)arg;
    uint16_t src_id;
    uint16_t dst_id;
    uint16_t bigger_id;
    struct iphdr ip_h;
    uint16_t len_load, nr_aes_block;
    byte * buf_load = (byte *)malloc(TUN_MTU);
    byte * buf_send = (byte *)malloc(ETH_MTU);
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
        dst_id = get_dst_id(ip_h.daddr, ip_h.saddr);
        src_id = global_self_id;
        // INFO("==========>>>dst_id: %d, src_id: %d", dst_id, src_id);

        if(NULL == peer_table[dst_id] || 1 == dst_id || global_self_id == dst_id)
        {
            DEBUG("tunif %s read packet to peer %d.%d: invalid peer!", global_tunif.name, dst_id/256, dst_id%256);
            continue;
        }

        //dst addr is in the same network with global_tunif
        bool dst_inside = ((ip_h.daddr & global_tunif.mask) == (global_tunif.addr & global_tunif.mask));
        //src addr is in the same network with global_tunif
        bool src_inside = ((ip_h.saddr & global_tunif.mask) == (global_tunif.addr & global_tunif.mask));
        //src addr is local tunif
        bool src_local = (ip_h.saddr == global_tunif.addr);
        
        // not supported now: read packet in tunif's subnet but ID mismatch
        if(src_inside != src_local)
        {
            DEBUG("tunif %s read packet from other peer, ignore it!", global_tunif.name);
            continue;
        }
        else if(!dst_inside && !src_inside) // not supported now: outside IP to outside IP
        {
            DEBUG("tunif %s read packet from outside net to outside net, ignore it!", global_tunif.name);
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
            DEBUG("tunif %s read packet of invalid peer: %d.%d!", global_tunif.name, bigger_id/256, bigger_id%256);
            continue;
        }

        buf_psk = peer_table[bigger_id]->psk;
        header_send.dst_id = htons(dst_id);
        header_send.src_id = htons(src_id);
        header_send.type_len_m.bit.type = HEAD_TYPE_DATA;
        header_send.type_len_m.bit.len = len_load;
        header_send.type_len_m.bit.more = HEAD_MORE_FALSE;
        header_send.type_len_m.u16 = htons(header_send.type_len_m.u16);
        header_send.ttl_pi_sd.bit.ttl = TTL_MAX;
        header_send.ttl_pi_sd.bit.pi_a = 0;
        header_send.ttl_pi_sd.bit.pi_b = 0;
        header_send.ttl_pi_sd.u16 = htons(header_send.ttl_pi_sd.u16);

        uint32_t now = time(NULL);
        header_send.time_magic.bit.time = now;
        header_send.time_magic.bit.magic = HEADER_MAGIC;
        header_send.time_magic.u32 = htonl(header_send.time_magic.u32);
        if(pthread_mutex_lock(&global_time_seq_lock) != 0)
        {
            ERROR(errno, "pthread_mutex_lock");
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
        header_send.seq_rand.bit.seq = peer_table[dst_id]->local_seq;
        if(pthread_mutex_unlock(&global_time_seq_lock) != 0)
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
        for(i=0; i<nr_aes_block; i++)
            encrypt(buf_send+HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN, buf_load+i*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);

        bool dup = should_pkt_dup(peer_table[bigger_id], buf_load);
        int len = HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN;

        packet_profile_t * pkt = new_pkt();

        pkt->src_id = global_self_id;
        pkt->dst_id = dst_id;
        pkt->forward = false;
        pkt->send_fd = global_sockfd;
        pkt->dup = dup;
        pkt->len = len;
        pkt->timestamp = now;
        pkt->seq = peer_table[dst_id]->local_seq;
        memcpy(pkt->buf_packet, buf_send, len);

        queue_put(global_send_q, pkt, 0);

        // peer_table[dst_id]->pkt_index_array_now[peer_table[dst_id]->local_seq] = global_send_last;

        continue;
    }

    free(buf_load);
    free(buf_send);
    pthread_cleanup_pop(0);
    return NULL;
}

void* server_send(void *arg)
{
    pthread_cleanup_push(clean_lock_all, NULL);
    peer_profile_t ** peer_table = (peer_profile_t **)arg;

    struct sockaddr_in peeraddr;
    byte * buf_send = (byte *)malloc(ETH_MTU);
    byte buf_header[HEADER_LEN];
    tunnel_header_t header_send;
    int i;
    for(i=0; i<ETH_MTU; i++)   //set random padding data
        buf_send[i] = random();
    byte * buf_psk;
    int sockfd = 0;
    int len = 0;
    uint16_t dst_id = 0;
    uint16_t src_id = 0;
    uint16_t bigger_id = 0;

    while(global_running)
    {
        packet_profile_t * pkt;
        queue_get(global_send_q, (void **)&pkt, NULL);
        
        sockfd = pkt->send_fd;
        len = pkt->len;
        bool dup = pkt->dup;
        bool forward = pkt->forward;
        struct sockaddr_in src_addr = pkt->src_addr;
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
    
        // DEBUG("forwarder_nr: %d, dst_id: %d, src_id: %d", global_forwarder_nr, dst_id, src_id);
        if(global_forwarder_nr > 0 && dst_id < src_id)  // send to forwarders
        {
            for(int i = 0; i < global_forwarder_nr; ++i)
            {
                header_send.ttl_pi_sd.u16 = ntohs(header_send.ttl_pi_sd.u16);
                if(forward)
                    header_send.ttl_pi_sd.bit.pi_a += i;
                else
                    header_send.ttl_pi_sd.bit.pi_b += i;
                header_send.ttl_pi_sd.u16 = htons(header_send.ttl_pi_sd.u16);

                memcpy(buf_header, &header_send, HEADER_LEN);
                encrypt(buf_send, buf_header, global_buf_group_psk, AES_KEY_LEN);  // encrypt header with group PSK
                encrypt(buf_send+HEADER_LEN, buf_header, buf_psk, AES_KEY_LEN);  // encrypt header to generate icv

                int forwarder_id = global_forwarders[i];
                if(peer_table[forwarder_id] == NULL)
                    continue;
                peeraddr = peer_table[forwarder_id]->path_array[0].peeraddr;  // only forward to first path

                if(forward)
                {
                    // split horizon
                    if(peeraddr.sin_addr.s_addr == src_addr.sin_addr.s_addr && peeraddr.sin_port == src_addr.sin_port)
                    {
                        // DEBUG("tunif %s recv packet from %d.%d to %d.%d: next peer is %d.%d, dst addr equals src addr!", 
                            // global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, dst_id/256, dst_id%256);
                        continue;
                    }
                }

                int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
                if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr)) < 0 )
                    ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", global_tunif.name, dst_id/256, dst_id%256);
            }
        }
        else  // send directly to peer
        {
            memcpy(buf_header, &header_send, HEADER_LEN);
            encrypt(buf_send, buf_header, global_buf_group_psk, AES_KEY_LEN);  // encrypt header with group PSK
            encrypt(buf_send+HEADER_LEN, buf_header, buf_psk, AES_KEY_LEN);  // encrypt header to generate icv

            for(int i = 0; i <= MAX_PATH; i++)
            {
                peeraddr = peer_table[dst_id]->path_array[i].peeraddr;
                if(peeraddr.sin_addr.s_addr == 0)
                {
                    // DEBUG("path not avaliable: %d", i);
                    continue;
                }

                // at the very beginning, both last_time are 0
                uint path_last_time = peer_table[dst_id]->path_array[i].last_time;
                uint peer_last_time = peer_table[dst_id]->last_time;
                if(abs(peer_last_time - path_last_time) > PATH_LIFE)
                {
                    peer_table[dst_id]->path_array[i].peeraddr.sin_addr.s_addr = 0;
                    // DEBUG("path timeout: %d, peer: %d, path: %d", i, peer_last_time, path_last_time);
                    continue;
                }

                if(forward)
                {
                    // split horizon
                    if(peeraddr.sin_addr.s_addr == src_addr.sin_addr.s_addr && peeraddr.sin_port == src_addr.sin_port)
                    {
                        // DEBUG("tunif %s recv packet from %d.%d to %d.%d: next peer is %d.%d, dst addr equals src addr!", 
                            // global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, dst_id/256, dst_id%256);
                        continue;
                    }
                }

                int len_pad = (len > ETH_MTU/3) ? 0 : (ETH_MTU/6 + (random() & ETH_MTU/3) );
                if(sendto(sockfd, buf_send, len + len_pad, 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr)) < 0 )
                    ERROR(errno, "tunif %s sendto dst_id %d.%d socket error", global_tunif.name, dst_id/256, dst_id%256);
            }
        }

        if(dup)  // add to pkt_delay_dup for delay
        {
            packet_profile_t * pkt = new_pkt();

            pkt->type = pkt_send;
            pkt->send_fd = sockfd;
            pkt->len = len;
            pkt->dst_id = dst_id;
            pkt->dst_addr = peer_table[dst_id]->path_array[0].peeraddr;
            memcpy(pkt->buf_packet, buf_send, len);

            tick_queue_put(global_delay_q, pkt, UDP_DUP_DELAY);
        }

        continue;
    }

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
        packet_profile_t * pkt;
        queue_get(global_write_q, (void **)&pkt, NULL);

        tunfd = pkt->write_fd;
        len = pkt->len;
        dst_id = pkt->dst_id;
        memcpy(buf_write, pkt->buf_packet, len);
        delete_pkt(pkt);

        if(write(tunfd, buf_write, len) < 0)
            ERROR(errno, "tunif %s write error of dst_id %d.%d", global_tunif.name, dst_id/256, dst_id%256);

        continue;
    }

    free(buf_write);
    pthread_cleanup_pop(0);
    return NULL;
}

void* server_recv(void *arg)
{
    pthread_cleanup_push(clean_lock_all, NULL);
    tunnel_header_t header_recv, header_send;
    peer_profile_t ** peer_table = (peer_profile_t **)arg;
    uint16_t dst_id = 0;
    uint16_t src_id = 0;
    uint16_t bigger_id = 0;
    uint ttl;
    struct sockaddr_in peeraddr;
    socklen_t peeraddr_len = sizeof(peeraddr);
    ip_dot_decimal_t ip_daddr;
    ip_dot_decimal_t ip_saddr;
    uint16_t len_load, nr_aes_block;
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
        if(recvfrom(global_sockfd, buf_recv, ETH_MTU, 0, (struct sockaddr *)&peeraddr, &peeraddr_len) < HEADER_LEN+ICV_LEN)
        {
            ERROR(errno, "tunif %s recvfrom socket error", global_tunif.name);
            continue;
        }

        decrypt(buf_header, buf_recv, global_buf_group_psk, AES_KEY_LEN);  //decrypt header with group PSK
        memcpy(&header_recv, buf_header, HEADER_LEN);
        memcpy(&header_send, buf_header, HEADER_LEN);

        header_recv.time_magic.u32 = ntohl(header_recv.time_magic.u32);
        if(header_recv.time_magic.bit.magic != HEADER_MAGIC)
        {
            DEBUG("tunif %s received packet: group not match!", global_tunif.name);
            continue;
        }

        header_recv.ttl_pi_sd.u16 = ntohs(header_recv.ttl_pi_sd.u16);
        uint pi = (header_recv.ttl_pi_sd.bit.pi_a << 2) + header_recv.ttl_pi_sd.bit.pi_b;
        
        dst_id = ntohs(header_recv.dst_id);
        src_id = ntohs(header_recv.src_id);
        bigger_id = dst_id > src_id ? dst_id : src_id;

        if(NULL == peer_table[bigger_id] || peer_table[bigger_id]->valid == false)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: invalid peer: %d.%d!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, bigger_id/256, bigger_id%256);
            continue;
        }

        if(src_id == 0 || src_id == 1 || src_id == global_self_id)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: invalid src_id!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }
        if(CHECK_RESTRICTED_IP && peer_table[src_id] != NULL && peer_table[src_id]->restricted == true)
        {
            //if dst_id == global_self_id, don't ckeck but write to tunif
            if(dst_id != global_self_id && binary_search(global_trusted_ip, 0, global_trusted_ip_cnt, peeraddr.sin_addr.s_addr) == -1)
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

        header_recv.type_len_m.u16 = ntohs(header_recv.type_len_m.u16);
        len_load = header_recv.type_len_m.bit.len;
        type = header_recv.type_len_m.bit.type;
        nr_aes_block = (len_load + AES_TEXT_LEN - 1) / AES_TEXT_LEN;

        if(type != HEAD_TYPE_DATA)
        {
            INFO("only HEAD_TYPE_DATA supported!");
            continue;
        }

        header_recv.seq_rand.u32 = ntohl(header_recv.seq_rand.u32);
        uint32_t pkt_time = header_recv.time_magic.bit.time;
        uint32_t pkt_seq = header_recv.seq_rand.bit.seq;

        // todo: may attack here
        if(!(peer_table[src_id]->restricted))
        {
            peer_table[src_id]->path_array[pi].peeraddr = peeraddr;
        }
        peer_table[src_id]->path_array[pi].last_time = pkt_time;
        peer_table[src_id]->last_time = pkt_time;


        if(pthread_mutex_lock(&global_stat_lock) != 0)
        {
            ERROR(errno, "pthread_mutex_lock");
            continue;
        }
        int fs = flow_filter(pkt_time, pkt_seq, src_id, dst_id, peer_table);
        if(pthread_mutex_unlock(&global_stat_lock) != 0)
        {
            ERROR(errno, "pthread_mutex_unlock");
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

        
        if(0 == dst_id || 0 == src_id)
        {
            DEBUG("tunif %s received packet from %d.%d to %d.%d: no route!", 
                global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
            continue;
        }
        else if(global_self_id == dst_id) // write to local tunif
        {
            for(i=0; i<nr_aes_block; i++)
                decrypt(buf_load+i*AES_TEXT_LEN, buf_recv+HEADER_LEN+ICV_LEN+i*AES_TEXT_LEN, buf_psk, AES_KEY_LEN);

            uint32_t daddr, saddr; // network byte order
            if(header_recv.ttl_pi_sd.bit.si == true)
            {
                saddr = (global_tunif.addr & global_tunif.mask) | peer_table[src_id]->vip;
                ip_snat(buf_load, saddr);
            }
            if(header_recv.ttl_pi_sd.bit.di == true)
            {
                daddr = (global_tunif.addr & global_tunif.mask) | peer_table[dst_id]->vip;
                ip_dnat(buf_load, daddr);
            }

            packet_profile_t * pkt = new_pkt();

            pkt->src_id = src_id;
            pkt->dst_id = dst_id;
            pkt->write_fd = global_tunfd;
            pkt->len = len_load;
            memcpy(pkt->buf_packet, buf_load, len_load);

            queue_put(global_write_q, pkt, 0);

            continue;
        }
        else  // forward to dst_id
        {
            ttl = header_recv.ttl_pi_sd.bit.ttl;
            //packet dst is not local and ttl expire, drop packet. only allow 16 hops
            if(TTL_MIN == ttl)
            {
                WARNING("TTL expired! from %d.%d.%d.%d to %d.%d.%d.%d.",
                    ip_saddr.a, ip_saddr.b, ip_saddr.c, ip_saddr.d,
                    ip_daddr.a, ip_daddr.b, ip_daddr.c, ip_daddr.d);   
                continue;
            }

            if(ALLOW_P2P != true)
            {
                if(header_recv.ttl_pi_sd.bit.si == true && header_recv.ttl_pi_sd.bit.di == true)
                {
                    DEBUG("tunif %s received packet from %d.%d to %d.%d: peer_table not allowed!", 
                        global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256);
                    continue;
                }
            }

            if(NULL == peer_table[dst_id])
            {
                DEBUG("tunif %s recv packet from %d.%d to %d.%d: route to invalid next peer: %d.%d!", 
                    global_tunif.name, src_id/256, src_id%256, dst_id/256, dst_id%256, dst_id/256, dst_id%256);
                continue;
            }

            ttl--;
            header_send.ttl_pi_sd.u16 = ntohs(header_send.ttl_pi_sd.u16);
            header_send.ttl_pi_sd.bit.ttl = ttl;
            header_send.ttl_pi_sd.u16 = htons(header_send.ttl_pi_sd.u16);

            memcpy(buf_recv, &header_send, HEADER_LEN);

            bool dup = should_pkt_dup(peer_table[bigger_id], NULL);
            int len = HEADER_LEN + ICV_LEN + nr_aes_block*AES_TEXT_LEN;

            packet_profile_t * pkt = new_pkt();

            pkt->src_id = src_id;
            pkt->dst_id = dst_id;
            pkt->forward = true;
            pkt->src_addr = peeraddr;
            pkt->send_fd = global_sockfd;
            pkt->len = len;
            pkt->dup = dup;
            memcpy(pkt->buf_packet, buf_recv, len);
            queue_put(global_send_q, pkt, 0);

            if(pkt_seq < SEQ_LEVEL_1)
            {
                if(fs == 3 && pkt_seq == 0) //time_diff == 1, swap only once.
                {
                    uint32_t * tmp_index = peer_table[dst_id]->pkt_index_array_pre;
                    peer_table[dst_id]->pkt_index_array_pre = peer_table[dst_id]->pkt_index_array_now;
                    peer_table[dst_id]->pkt_index_array_now = tmp_index;
                }
                // if(fs == 1) //time_diff == -1
                    // peer_table[dst_id]->pkt_index_array_pre[pkt_seq] = global_send_last;
                // else
                    // peer_table[dst_id]->pkt_index_array_now[pkt_seq] = global_send_last;
            }

            continue;
        }
    }

    free(buf_recv);
    free(buf_load);
    free(buf_send);
    pthread_cleanup_pop(0);
    return NULL;
}


/*
  need to filter 2 elements:pkt_time and pkt_seq;
  1) pkt_time can NOT run too fast, if faster than system, let's call it a jump. if too many jumps, then it may be an attack.
  2) pkt_seq can NOT duplicate.

  return value: return 0, valid packet; return negative number, invalid packet.
  invalid packets will be droped.
*/
int flow_filter(uint32_t pkt_time, uint32_t pkt_seq, uint16_t src_id, uint16_t dst_id, peer_profile_t ** peer_table)
{
    // DEBUG("=== recv pkt, %d:%d", pkt_time, pkt_seq);

    global_pkt_cnt++;
    flow_profile_t * fp = NULL;

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

        bit_array_t * ba_tmp;
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
