/*
 * handle the json config file
 */

#ifndef CONFIG_H_
#define CONFIG_H_


#include "data-struct/data-struct.h"
#include "header.h"


/*
 * Config file path choose order:
 * 1) if user specify the path with -c, this path will be used.
 * 2) if exe is located at `/usr/bin/`, config will be `/etc/alpaca-tunnel.d/config.json`.
 * 3) if exe is located at `/usr/local/bin/`, config will be `/usr/local/etc/alpaca-tunnel.d/config.json`.
 * 4) config will be at the relative path `alpaca-tunnel.d/config.json` to exe file.
 *
 * Secret file path choose order:
 * 1) if user specify the path in json, this path will be used. if this path is a relative path, it's relative to the config json.
 * 2) Otherwise, the secret file MUST be located at the relative path `./secrets` to the config json, NOT with exe!
*/

#define PATH_LEN 1024

#define ABSOLUTE_PATH_TO_JSON        "/etc/alpaca-tunnel.d/config.json"
#define ABSOLUTE_PATH_TO_JSON_LOCAL  "/usr/local/etc/alpaca-tunnel.d/config.json"
#define RELATIVE_PATH_TO_JSON        "alpaca-tunnel.d/config.json"
#define RELATIVE_PATH_TO_SECRETS     "secrets.txt"
#define RELATIVE_PATH_TO_ROUTE       "route_data_cidr.txt"


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
    char id[HEAD_ID_MAX_LEN+1];  // 0.2 - 254.254
    char net[HEAD_ID_MAX_LEN+1];  // 10.17
    char gateway[HEAD_ID_MAX_LEN+1];
    int port;
    int mtu;
    char * log_level;
    char * secret_file;
    // int forwarder_nr;
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
