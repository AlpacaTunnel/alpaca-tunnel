#ifndef CONFIG_H_
#define CONFIG_H_

/* handle the json config file */

#include <stdint.h>

#include "data_struct.h"

//reserved ID: 0.0, 0.1, 255.255, any server/client cann't use.
#define MAX_ID 65535
#define MAX_ID_LEN 7  // 254.254
#define CONFIG_TOKEN_NR_MAX 1280  // max number of elements(each key or value is an element) in config file

//tunnel MTU must not be greater than 1440
#define TUN_MTU 1440
#define TUN_MTU_MIN 68


typedef struct
{
    char * table;
    char * gateway;
    char * data;
} chnroute_t;


struct config_t
{
    char * mode;  // server/client
    char * group;
    char id[MAX_ID_LEN+1];  // 0.2 - 254.254
    char net[MAX_ID_LEN+1];  // 10.17
    char gateway[MAX_ID_LEN+1];
    int port;
    int mtu;
    char * log_level;
    char * secret_file;
    chnroute_t * chnroute;
    ll_node_t * local_routes;   // a list of networks or hosts
    ll_node_t * use_dns;  // a list of dns servers, not used now
    ll_node_t * pre_up_cmds;
    ll_node_t * post_up_cmds;
    ll_node_t * pre_down_cmds;
    ll_node_t * post_down_cmds;
};

int free_config(struct config_t * configure);
int load_config(const char * config_file, struct config_t * config);
int get_log_level(char* log_level);
int check_config(struct config_t * config);

#endif
