#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "jsmn.h"
#include "log.h"
#include "ip.h"
#include "config.h"
#include "data_struct.h"


/*
 * This file was written on top of jsmn's example code.
 * I really don't understand it, but it works.
 */


static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if(tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start
            && strncmp(json + tok->start, s, tok->end - tok->start) == 0)
        return 0;
    else
        return -1;
}


int free_config(struct config_t * config)
{
    free(config->mode);
    free(config->group);
    free(config->log_level);
    free(config->secret_file);

    free_string_node(&config->use_dns);
    free_string_node(&config->local_routes);
    free_string_node(&config->pre_up_cmds);
    free_string_node(&config->post_up_cmds);
    free_string_node(&config->pre_down_cmds);
    free_string_node(&config->post_down_cmds);

    return 0;
}


int load_config(const char * config_file, struct config_t * config)
{
    int i;
    int r;
    jsmn_parser p;
    jsmntok_t * t = (jsmntok_t *)malloc(CONFIG_TOKEN_NR_MAX*2);
    if(t == NULL)
        return -1;

    FILE *f = fopen(config_file, "r");
    if(f == NULL)
    {
        ERROR(errno, "open %s", config_file);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *json_string = malloc(fsize + 1);
    if(fread(json_string, fsize, 1, f) < 1)
    {
        ERROR(0, "fread %s size too small", config_file);
        return -1;
    }
    fclose(f);
    
    json_string[fsize] = 0;

    jsmn_init(&p);
    r = jsmn_parse(&p, json_string, strlen(json_string), t, CONFIG_TOKEN_NR_MAX*2);
    if(r < 0)
    {
        ERROR(0, "Failed to parse JSON: %d.", r);
        return -1;
    }

    /* Assume the top-level element is an object */
    if(r < 1 || t[0].type != JSMN_OBJECT)
    {
        ERROR(0, "JSON Object expected at the top-level!");
        return -1;
    }

    /* Loop over all keys of the root object */
    for(i = 1; i < r; i++)
    {
        char * start = json_string + t[i+1].start;
        int len = t[i+1].end - t[i+1].start;

        if(jsoneq(json_string, &t[i], "mode") == 0)
        {
            config->mode = strndup(start, len);
            int i_tmp = 0;
            for(i_tmp = 0; i_tmp < len; i_tmp++)
                config->mode[i_tmp] = tolower(config->mode[i_tmp]);
            i++;
        } 
        else if(jsoneq(json_string, &t[i], "group") == 0)
        {
            config->group = strndup(start, len);
            i++;
        } 
        else if(jsoneq(json_string, &t[i], "id") == 0) 
        {
            int len_id = len < MAX_ID_LEN ? len : MAX_ID_LEN;
            strncpy(config->id, start, len_id);
            i++;
        } 
        else if(jsoneq(json_string, &t[i], "gateway") == 0) 
        {
            int len_id = len < MAX_ID_LEN ? len : MAX_ID_LEN;
            strncpy(config->gateway, start, len_id);
            i++;
        } 
        else if(jsoneq(json_string, &t[i], "net") == 0) 
        {
            int len_id = len < MAX_ID_LEN ? len : MAX_ID_LEN;
            strncpy(config->net, start, len_id);
            i++;
        } 
        else if(jsoneq(json_string, &t[i], "port") == 0) 
        {
            char * cc = strndup(start, len);
            config->port = strtol(cc, NULL, 10);
            free(cc);
            i++;
        } 
        else if(jsoneq(json_string, &t[i], "mtu") == 0) 
        {
            char * cc = strndup(start, len);
            config->mtu = strtol(cc, NULL, 10);
            free(cc);
            i++;
        } 
        else if(jsoneq(json_string, &t[i], "log_level") == 0) 
        {
            config->log_level = strndup(start, len);
            i++;
        } 
        else if(jsoneq(json_string, &t[i], "secret_file") == 0) 
        {
            config->secret_file = strndup(start, len);
            i++;
        } 
        else if(jsoneq(json_string, &t[i], "use_dns") == 0) 
        {
            int j;
            if(t[i+1].type != JSMN_ARRAY) 
                continue;
            for(j = 0; j < t[i+1].size; j++) 
            {
                jsmntok_t *g = &t[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                append_string_node(&config->use_dns, cg);
            }
            i += t[i+1].size + 1;
        }
        else if(jsoneq(json_string, &t[i], "local_routes") == 0) 
        {
            int j;
            if(t[i+1].type != JSMN_ARRAY) 
                continue;
            for(j = 0; j < t[i+1].size; j++) 
            {
                jsmntok_t *g = &t[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                append_string_node(&config->local_routes, cg);
            }
            i += t[i+1].size + 1;
        } 
        else if(jsoneq(json_string, &t[i], "pre_up_cmds") == 0) 
        {
            int j;
            if(t[i+1].type != JSMN_ARRAY) 
                continue;
            for(j = 0; j < t[i+1].size; j++) 
            {
                jsmntok_t *g = &t[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                append_string_node(&config->pre_up_cmds, cg);
            }
            i += t[i+1].size + 1;
        } 
        else if(jsoneq(json_string, &t[i], "post_up_cmds") == 0) 
        {
            int j;
            if(t[i+1].type != JSMN_ARRAY)
                continue;
            for(j = 0; j < t[i+1].size; j++) 
            {
                jsmntok_t *g = &t[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                append_string_node(&config->post_up_cmds, cg);
            }
            i += t[i+1].size + 1;
        }
        else if(jsoneq(json_string, &t[i], "pre_down_cmds") == 0) 
        {
            int j;
            if(t[i+1].type != JSMN_ARRAY) 
                continue;
            for(j = 0; j < t[i+1].size; j++) 
            {
                jsmntok_t *g = &t[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                append_string_node(&config->pre_down_cmds, cg);
            }
            i += t[i+1].size + 1;
        } 
        else if(jsoneq(json_string, &t[i], "post_down_cmds") == 0) 
        {
            int j;
            if(t[i+1].type != JSMN_ARRAY)
                continue;
            for(j = 0; j < t[i+1].size; j++) 
            {
                jsmntok_t *g = &t[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                append_string_node(&config->post_down_cmds, cg);
            }
            i += t[i+1].size + 1;
        }
        else 
            WARNING("Unexpected key: %.*s", t[i].end-t[i].start, json_string + t[i].start);
    }

    free(json_string);
    free(t);

    return 0;
}


int get_log_level(char* log_level)
{
    char level[16];
    memset(level, 0, 16);
    int len = strlen(log_level) < 16 ? strlen(log_level) : 16;
    int i;
    for(i = 0; i < len; ++i)
        level[i] = tolower(log_level[i]);

    if(strcmp(level, "critical") == 0)
        return LOG_LEVEL_CRITICAL;
    else if(strcmp(level, "error") == 0)
        return LOG_LEVEL_ERROR;
    else if(strcmp(level, "warning") == 0)
        return LOG_LEVEL_WARNING;
    else if(strcmp(level, "info") == 0)
        return LOG_LEVEL_INFO;
    else if(strcmp(level, "debug") == 0)
        return LOG_LEVEL_DEBUG;
    else if(strcmp(level, "notset") == 0)
        return LOG_LEVEL_NOTSET;
    
    return LOG_LEVEL_INFO;
}


int check_config(struct config_t * config)
{
    if(config->mode == NULL || config->group == NULL || config->id[0] == '\0' || config->net[0] == '\0')
    {
        ERROR(0, "mode/group/id/net cannot be empty!");
        return -1;
    }

    if(strcmp(config->mode, "client") != 0 && strcmp(config->mode, "server") != 0)
    {
        ERROR(0, "mode must be client or server: %s", config->mode);
        return -1;
    }

    int self_id = inet_ptons(config->id);
    if(self_id <= 1 || self_id >= MAX_ID)
    {
        ERROR(0, "ID must between 0.2 and 255.254: %s", config->id);
        return -1;
    }

    int net_id = inet_ptons(config->net);
    if(net_id < 256 || net_id > MAX_ID)
    {
        ERROR(0, "NET must between 1.0 and 255.255: %s", config->net);
        return -1;
    }

    if(strcmp(config->mode, "client") == 0)
    {
        if(config->gateway[0] == '\0')
            WARNING("please specify a gateway for the client!");
        else
        {
            int gateway_id = inet_ptons(config->gateway);
            if(gateway_id <= 1 || gateway_id >= MAX_ID)
            {
                ERROR(0, "gateway must between 0.2 and 255.254: %s", config->gateway);
                return -1;
            }
        }
    }

    if(config->port < 0 || config->port > 65534)
    {
        ERROR(0, "port must be between %d and %d: %d", 0, 65534, config->port);
        return -1;
    }

    if(config->mtu < TUN_MTU_MIN || config->mtu > TUN_MTU)
    {
        ERROR(0, "MTU must be between %d and %d: %d", TUN_MTU_MIN, TUN_MTU, config->mtu);
        return -1;
    }

    return 0;
}

