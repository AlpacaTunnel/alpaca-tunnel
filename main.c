#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>


/*
****** dependence tree (not include data-struct and log) ******

main.c
├── vpn.h
│   ├── policy.h
│   │   └── peer.h
│   │       ├── aes.h
│   │       └── ip.h
│   ├── config.h
│   │   └── header.h
│   └── route.h
├── log.h
├── cmd.h
├── monitor.h
├── signal.h
└── tunif.h


config.c
└──ip.h

peer.c
└──header.h

monitor.c
└──route.h


*/


#include "vpn.h"
#include "log.h"
#include "cmd.h"
#include "monitor.h"
#include "tunif.h"
#include "signal.h"


#define PROCESS_NAME    "alpaca-tunnel"
#define VERSION         "6.0"

#define ALLOW_P2P true
// #define CHECK_RESTRICTED_IP true
#define TCPMSS 1300


int usage(char *pname);
void sig_handler(void * arg);
void reset_link_route(void * arg);
void update_secret(void * arg);

void reset_peer_status_all(void *arg);
void clear_forwarding_table_timedout(void *arg);


int main(int argc, char *argv[])
{
    vpn_context_t * vpn_ctx = vpn_context_init();
    if(vpn_ctx == NULL)
    {
        ERROR(0, "vpn_context_init() failed.");
        exit(1);
    }

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
            strncpy((char*)vpn_ctx->json_path, optarg, PATH_LEN);
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
        // INFO("sizeof pi_u: %d", sizeof(union pi_u));
        // INFO("sizeof struct pi_s: %d", sizeof(struct pi_s));
        INFO("sizeof ttl_pi_sd_u: %d", sizeof(union ttl_pi_sd_u));
        INFO("sizeof ttl_pi_sd_s: %d", sizeof(struct ttl_pi_sd_s));
        INFO("sizeof seq_rand_u: %d", sizeof(union seq_rand_u));
        exit(1);
    }


    /******************* init main variables *******************/

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
    monitor_t * route_monitor = NULL;
    monitor_t * secret_monitor = NULL;
    monitor_t * cronjob_reset_peer_status = NULL;
    monitor_t * cronjob_clear_forwarding_table = NULL;


    /******************* load json config *******************/

    int path_len;
    if('\0' == vpn_ctx->json_path[0])
    {
        path_len = readlink("/proc/self/exe", vpn_ctx->exe_path, PATH_LEN);
        if(path_len < 0)
        {
            ERROR(errno, "readlink: /proc/self/exe");
            goto _END;
        }
        else if(path_len > (PATH_LEN-40))   //40 is reserved for strcat.
        {
            ERROR(0, "readlink: file path too long: %s", vpn_ctx->exe_path);
            goto _END;
        }
        while(vpn_ctx->exe_path[path_len] != '/')
        {
            vpn_ctx->exe_path[path_len] = '\0';
            path_len--;
        }

        if(str_equal(vpn_ctx->exe_path, "/usr/bin/"))
            strcpy(vpn_ctx->json_path, ABSOLUTE_PATH_TO_JSON);
        else if(str_equal(vpn_ctx->exe_path, "/usr/local/bin/"))
            strcpy(vpn_ctx->json_path, ABSOLUTE_PATH_TO_JSON_LOCAL);
        else
        {
            strcpy(vpn_ctx->json_path, vpn_ctx->exe_path);
            strcat(vpn_ctx->json_path, RELATIVE_PATH_TO_JSON);
        }
    }

    strcpy(vpn_ctx->config_dir, vpn_ctx->json_path);
    path_len = strlen(vpn_ctx->config_dir);
    while(vpn_ctx->config_dir[path_len] != '/' && path_len >= 0)
    {
        vpn_ctx->config_dir[path_len] = '\0';
        path_len--;
    }

    if(load_config(vpn_ctx->json_path, &config) != 0)
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
        vpn_ctx->mode = VPN_MODE_CLIENT;
    else if(str_equal(config.mode, "server"))
        vpn_ctx->mode = VPN_MODE_SERVER;

    strncpy((char*)vpn_ctx->buf_group_psk, config.group, 2*AES_BLOCKLEN);
    AES_init_ctx(vpn_ctx->group_aes_ctx, vpn_ctx->buf_group_psk);

    vpn_ctx->self_id = inet_ptons(config.id);
    
    // wait default route to come up
    if(vpn_ctx->mode == VPN_MODE_CLIENT)
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

    vpn_ctx->forwarder_cnt = 0;
    while(!queue_is_empty(config.forwarders))
    {
        char * forwarder_str = NULL;
        queue_get(config.forwarders, (void **)&forwarder_str, NULL);
        int forwarder_id = inet_ptons(forwarder_str);
        if(forwarder_id <= 1 || forwarder_id >= HEAD_MAX_ID)
        {
            ERROR(0, "forwarder must between 0.2 and 255.254: %s", forwarder_str);
            goto _END;
        }
        vpn_ctx->forwarders[vpn_ctx->forwarder_cnt] = forwarder_id;
        vpn_ctx->forwarder_cnt++;
    }
    if(vpn_ctx->forwarder_cnt > MAX_FORWARDER_CNT)
    {
        ERROR(0, "too many forwarders, only %d allowed!", MAX_FORWARDER_CNT);
        goto _END;
    }


    /******************* bind UDP socket *******************/

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(config.port);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    vpn_ctx->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(bind(vpn_ctx->sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        ERROR(errno, "bind port %d", config.port);
        goto _END;
    }


    /******************* get secret file *******************/

    if(config.secret_file != NULL && config.secret_file[0] == '/')
        strcpy(vpn_ctx->secrets_path, config.secret_file);
    else
    {
        strcpy(vpn_ctx->secrets_path, vpn_ctx->json_path);
        path_len = strlen(vpn_ctx->secrets_path);
        while(vpn_ctx->secrets_path[path_len] != '/' && path_len >= 0)
        {
            vpn_ctx->secrets_path[path_len] = '\0';
            path_len--;
        }
        if(config.secret_file == NULL)
            strcat(vpn_ctx->secrets_path, RELATIVE_PATH_TO_SECRETS);
        else
            strcat(vpn_ctx->secrets_path, config.secret_file);
    }

    if(access(vpn_ctx->secrets_path, R_OK) == -1)
    {
        ERROR(errno, "cann't read secret file: %s", vpn_ctx->secrets_path);
        goto _END;
    }

    strcpy(vpn_ctx->secret_dir, vpn_ctx->secrets_path);
    path_len = strlen(vpn_ctx->secret_dir);
    while(vpn_ctx->secret_dir[path_len] != '/' && path_len >= 0)
    {
        vpn_ctx->secret_dir[path_len] = '\0';
        path_len--;
    }

    DEBUG("config_dir: %s", vpn_ctx->config_dir);
    INFO("json_path: %s", vpn_ctx->json_path);
    DEBUG("secret_dir: %s", vpn_ctx->secret_dir);
    INFO("secrets_path: %s", vpn_ctx->secrets_path);


    /******************* load secret file *******************/

    if((peer_table = init_peer_table()) == NULL)
    {
        ERROR(0, "Init peer failed!");
        goto _END;
    }

    FILE *secrets_file = NULL;
    if((secrets_file = fopen(vpn_ctx->secrets_path, "r")) == NULL)
    {
        ERROR(errno, "open file: %s", vpn_ctx->secrets_path);
        goto _END;
    }
    if(update_peer_table(peer_table, secrets_file) < 0)
    {
        ERROR(0, "update_peer_table failed"); 
        fclose(secrets_file);
        goto _END;
    }
    fclose(secrets_file);

    if(NULL == peer_table[vpn_ctx->self_id])
    {
        ERROR(0, "Init peer: didn't find self profile in secert file!");
        goto _END;
    }
    vpn_ctx->peer_table = peer_table;


    /******************* setup tunnel interface *******************/

    // before bring tunnel interface up
    run_cmd_list(config.pre_up_cmds);

    char tun_name[IFNAMSIZ] = "\0";
    if( (vpn_ctx->tunfd = tun_alloc(tun_name)) < 0 )
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

    vpn_ctx->if_list = NULL;
    collect_if_info(&vpn_ctx->if_list);
    strncpy(vpn_ctx->tunif.name, tun_name, IFNAMSIZ);

    // get ip address of the tunnel interface    
    int tmp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq tmp_ifr;
    tmp_ifr.ifr_addr.sa_family = AF_INET;
    strncpy(tmp_ifr.ifr_name, tun_name, IFNAMSIZ-1);
    if(ioctl(tmp_sockfd, SIOCGIFADDR, &tmp_ifr) < 0)
    {
        ERROR(errno, "ioctl(SIOCGIFADDR): %s",vpn_ctx->tunif.name);
        close(tmp_sockfd);
        goto _END;
    }
    close(tmp_sockfd);

    struct sockaddr_in *tmp_in = (struct sockaddr_in *)&tmp_ifr.ifr_addr;
    vpn_ctx->tunif.addr = tmp_in->sin_addr.s_addr;
    vpn_ctx->tunif.mask = get_ipmask(vpn_ctx->tunif.addr, vpn_ctx->if_list);
    //tunif IP must be a /16 network, and must match self ID! otherwise, from/to peer will be confusing.
    if(TUN_NETMASK != ntohl(vpn_ctx->tunif.mask))
    {
        ERROR(0, "Tunnel mask is not /16.");
        goto _END;
    }
    if((uint16_t)(ntohl(vpn_ctx->tunif.addr)) != vpn_ctx->self_id)
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
            strcpy(chnroute_path, vpn_ctx->config_dir);
            strcat(chnroute_path, RELATIVE_PATH_TO_ROUTE);
        }
        else if(config.chnroute->data[0] == '/')
            strcpy(chnroute_path, config.chnroute->data);
        else
        {
            strcpy(chnroute_path, vpn_ctx->config_dir);
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
            gw_dev = get_strif_local(default_gw_dev, vpn_ctx->if_list);

        if(config.chnroute->gateway == NULL || str_equal(config.chnroute->gateway, "default"))
            ;
        else
            inet_pton(AF_INET, config.chnroute->gateway, &gw_ip);

        if(chnroute_add(chnroute_path, gw_ip, chnroute_table, gw_dev) == 0)
            chnroute_set = true;
    }

    // setup route
    if(vpn_ctx->mode == VPN_MODE_CLIENT)
    {
        char gw_ip_str[IP_LEN];
        sprintf(gw_ip_str, "%s.%s", config.net, config.gateway);
    
        if(default_gw_ip[0] != '\0' || default_gw_dev[0] != '\0')
        {
            change_default_route(gw_ip_str, NULL);
            default_route_changed = true;
        }

        for(int i = 0; i < HEAD_MAX_ID+1; i++)
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

    if(vpn_ctx->mode == VPN_MODE_SERVER)
    {
        char tun_net[IP_LEN+4];
        sprintf(tun_net, "%s.0.0/%d", config.net, TUN_MASK_LEN);
        add_iptables_nat(tun_net);
    }

    add_iptables_tcpmss(TCPMSS);

    
    /******************* start all working threads *******************/

    vpn_ctx->running = 1;
    vpn_ctx->allow_p2p = ALLOW_P2P;

    route_monitor = monitor_route_start(MONITOR_TYPE_ROUTE_IPV4, 1, reset_link_route, vpn_ctx);
    secret_monitor = monitor_file_start(vpn_ctx->secrets_path, 1, update_secret, vpn_ctx);
    cronjob_reset_peer_status = cronjob_start(RESET_STAT_INTERVAL, reset_peer_status_all, vpn_ctx->peer_table);
    cronjob_clear_forwarding_table = cronjob_start(FORWARDING_TABLE_CLEAR_INTERVAL, clear_forwarding_table_timedout, vpn_ctx->forwarding_table);

    pthread_t tid1=0, tid2=0, tid3=0, tid4=0, tid11=0;

    if(pthread_create(&tid1, NULL, server_recv, vpn_ctx) != 0)
    {
        ERROR(errno, "pthread_error: create rc1"); 
        goto _END;
    }
    if(pthread_create(&tid2, NULL, server_read, vpn_ctx) != 0)
    {
        ERROR(errno, "pthread_error: create rc2"); 
        goto _END;
    }
    if(pthread_create(&tid3, NULL, server_write, vpn_ctx) != 0)
    {
        ERROR(errno, "pthread_error: create rc3"); 
        goto _END;
    }
    if(pthread_create(&tid4, NULL, server_send, vpn_ctx) != 0)
    {
        ERROR(errno, "pthread_error: create rc4"); 
        goto _END;
    }

    if(pthread_create(&tid11, NULL, pkt_delay_dup, vpn_ctx) != 0)
    {
        ERROR(errno, "pthread_error: create rc11"); 
        goto _END;
    }


    /******************* main thread sleeps during running *******************/

    signal_init();
    signal_install(SIGINT, sig_handler, vpn_ctx);
    signal_install(SIGTERM, sig_handler, vpn_ctx);
    // Note: nohup won't work when SIGHUP installed.
    signal_install(SIGHUP, sig_handler, vpn_ctx);
    INFO("%s has started.", PROCESS_NAME);
    start_success = true;

    while(vpn_ctx->running)
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
    pthread_cancel(tid11);

    // what happens to a locked lock when cancel the thread?
    // what happens when destory a locked lock?


/******************* clear env *******************/

_END:

    vpn_ctx->running = 0;
    if(route_monitor)
        monitor_route_stop(route_monitor);
    if(secret_monitor)
        monitor_file_stop(secret_monitor);
    if(cronjob_reset_peer_status)
        cronjob_stop(cronjob_reset_peer_status);
    if(cronjob_clear_forwarding_table)
        cronjob_stop(cronjob_clear_forwarding_table);

    if(vpn_ctx->mode == VPN_MODE_CLIENT)
    {
        if(default_route_changed)
            restore_default_route(default_gw_ip, default_gw_dev);

        for(int i = 0; i < HEAD_MAX_ID+1; i++)
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
            DEBUG("del local_route: %s from table default", local_route);
        }
    }

    if(chnroute_set == true)
        chnroute_del(chnroute_path, chnroute_table);

    if(vpn_ctx->mode == VPN_MODE_SERVER)
    {
        char tun_net[IP_LEN+4];
        sprintf(tun_net, "%s.0.0/%d", config.net, TUN_MASK_LEN);
        del_iptables_nat(tun_net);
    }

    del_iptables_tcpmss(TCPMSS);

    // before turn tunnel interface down 
    run_cmd_list(config.pre_down_cmds);

    // close the fd will delete the tunnel interface.
    close(vpn_ctx->tunfd);

    // after turn tunnel interface down 
    run_cmd_list(config.post_down_cmds);

    free_config(&config);

    close(vpn_ctx->sockfd);
    clear_if_info(vpn_ctx->if_list);
    vpn_ctx->if_list = NULL;

    vpn_context_destory(vpn_ctx);

    destroy_peer_table(peer_table);
    peer_table = NULL;

    ERROR(0, "%s has exited.", PROCESS_NAME);
    if(start_success)
        exit(0);
    else
        exit(1);
}


int usage(char *pname)
{
    printf("Usage: %s [-t|T] [-v|V] [-c|C config]\n", pname);
    return 0;
}


void sig_handler(void * arg)
{
    vpn_context_t * vpn_ctx = (vpn_context_t *)arg;
    vpn_ctx->running = 0;
}


void reset_link_route(void * arg)
{
    vpn_context_t * vpn_ctx = (vpn_context_t *)arg;

    DEBUG("RTNETLINK: route changed.");

    clear_if_info(vpn_ctx->if_list);

    if(collect_if_info(&vpn_ctx->if_list) != 0)
        ERROR(0, "collect if_list failed");

    //must clear if_info_t first, then forwarding_table_clear
    if(forwarding_table_clear(vpn_ctx->forwarding_table) != 0)
        ERROR(0, "clear forwarding_table failed");

    DEBUG("RTNETLINK: route table reset.");

    return;
}


// don't delete peers, otherwise may Segmentation fault since memory is unreadable.
void update_secret(void * arg)
{
    vpn_context_t * vpn_ctx = (vpn_context_t *)arg;
    peer_profile_t ** peer_table = vpn_ctx->peer_table;

    if(access(vpn_ctx->secrets_path, F_OK) == -1)
    {
        ERROR(errno, "update_secret %s", vpn_ctx->secrets_path);
        return;
    }

    FILE *secrets_file = NULL;
    if((secrets_file = fopen(vpn_ctx->secrets_path, "r")) == NULL)
    {
        ERROR(errno, "open file failed when update_secret: %s", vpn_ctx->secrets_path);
        return;
    }

    if(update_peer_table(peer_table, secrets_file) < 0)
    {
        ERROR(0, "update secret file failed!");
        return;
    }

    INFO("FILE: secret file reloaded!");
    fclose(secrets_file);

    if(NULL == peer_table[vpn_ctx->self_id])
        ERROR(0, "update_secret: didn't find self profile in secert file!");

    return;
}


void reset_peer_status_all(void *arg)
{
    peer_profile_t ** peer_table = (peer_profile_t **)arg;
    reset_peer_table_flow(peer_table);

    return;
}

void clear_forwarding_table_timedout(void *arg)
{
    forwarding_table_t * forwarding_table = (forwarding_table_t *)arg;
    forwarding_table_timedout(forwarding_table);
    DEBUG("clear_forwarding_table_timedout called");

    return;
}
