/*
 * handle the json config file
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <stdint.h>

#include "data-struct/data-struct.h"

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


typedef struct
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
    int forwarder_nr;
    chnroute_t * chnroute;
    queue_t * forwarders;   // a list of forwarder IDs, will send outter UDP to them
    queue_t * local_routes;   // a list of networks or hosts
    queue_t * local_routes_bakup;   // backup routes, restore when exit()
    queue_t * use_dns;  // a list of dns servers, not used now
    queue_t * pre_up_cmds;
    queue_t * post_up_cmds;
    queue_t * pre_down_cmds;
    queue_t * post_down_cmds;
} config_t;

int free_config(config_t * configure);
int load_config(const char * config_file, config_t * config);
int get_log_level(char* log_level);
int check_config(config_t * config);

#endif
