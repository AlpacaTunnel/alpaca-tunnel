#ifndef CMD_HELPER_H_
#define CMD_HELPER_H_

/* functions to run system cmd */


#include "data_struct.h"

int run_cmd_list(struct string_node ** cmd_list);  // after calling this func, cmd_list will be emptied.

int enable_ip_forward();

int get_popen(const char * cmd, char ** output);  // Caller must free the output latter.

int get_default_route(char default_gw_ip[], char default_gw_dev[]);

int add_iproute(const char * dst, const char * gw_ip, const char * table);
int del_iproute(const char * dst, const char * table);

int change_default_route(const char gw_ip[]);
int restore_default_route(const char gw_ip[]);

int add_iptables_nat(const char * source);
int del_iptables_nat(const char * source);

int add_iptables_tcpmss(int mss);
int del_iptables_tcpmss(int mss);


#endif
