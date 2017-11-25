/*
 * This file was written on top of jsmn's example code.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "log.h"
#include "ip.h"
#include "config.h"


#define CONFIG_TOKEN_NR_MAX 1280  // max number of elements(each key or value is an element) in config file


static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if(tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start
            && strn_equal(json + tok->start, s, tok->end - tok->start))
        return 0;
    else
        return -1;
}


int free_config(config_t * config)
{
    free(config->mode);
    free(config->group);
    free(config->log_level);
    free(config->secret_file);
    free(config->chnroute);

    queue_destroy(config->forwarders, NULL);
    queue_destroy(config->use_dns, NULL);
    queue_destroy(config->local_routes, NULL);
    queue_destroy(config->local_routes_bakup, NULL);
    queue_destroy(config->pre_up_cmds, NULL);
    queue_destroy(config->post_up_cmds, NULL);
    queue_destroy(config->pre_down_cmds, NULL);
    queue_destroy(config->post_down_cmds, NULL);

    return 0;
}


int init_config_queue(config_t * config)
{
    config->forwarders          = queue_init(QUEUE_TYPE_FIFO);
    config->use_dns             = queue_init(QUEUE_TYPE_FIFO);
    config->local_routes        = queue_init(QUEUE_TYPE_FIFO);
    config->local_routes_bakup  = queue_init(QUEUE_TYPE_FIFO);
    config->pre_up_cmds         = queue_init(QUEUE_TYPE_FIFO);
    config->post_up_cmds        = queue_init(QUEUE_TYPE_FIFO);
    config->pre_down_cmds       = queue_init(QUEUE_TYPE_FIFO);
    config->post_down_cmds      = queue_init(QUEUE_TYPE_FIFO);

    if(!config->forwarders || !config->use_dns 
        || !config->local_routes || !config->local_routes_bakup
        || !config->pre_up_cmds || !config->post_up_cmds
        || !config->pre_down_cmds || !config->post_down_cmds)
        return -1;

    return 0;
}

int load_config(const char * config_file, config_t * config)
{

    if(init_config_queue(config) != 0)
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

    jsmn_parser p;
    int tok_nr;
    jsmntok_t * tok;

    // jsmn_init(&p);
    // tok_nr = jsmn_parse(&p, json_string, strlen(json_string), NULL, 0);

    tok = (jsmntok_t *)malloc(CONFIG_TOKEN_NR_MAX*2);
    if(tok == NULL)
        return -1;

    jsmn_init(&p);
    tok_nr = jsmn_parse(&p, json_string, strlen(json_string), tok, CONFIG_TOKEN_NR_MAX*2);

    if(tok_nr < 0)
    {
        ERROR(0, "Failed to parse JSON: %d.", tok_nr);
        return -1;
    }

    /* Assume the top-level element is an object */
    if(tok_nr < 1 || tok[0].type != JSMN_OBJECT)
    {
        ERROR(0, "JSON Object expected at the top-level!");
        return -1;
    }

    /* Loop over all keys of the root object */
    int i;
    for(i = 1; i < tok_nr; i++)
    {
        char * start = json_string + tok[i+1].start;
        int len = tok[i+1].end - tok[i+1].start;

        if(jsoneq(json_string, &tok[i], "mode") == 0)
        {
            config->mode = strndup(start, len);
            int i_tmp = 0;
            for(i_tmp = 0; i_tmp < len; i_tmp++)
                config->mode[i_tmp] = tolower(config->mode[i_tmp]);
            i++;
        } 
        else if(jsoneq(json_string, &tok[i], "group") == 0)
        {
            config->group = strndup(start, len);
            i++;
        } 
        else if(jsoneq(json_string, &tok[i], "id") == 0) 
        {
            int len_id = len < HEAD_ID_MAX_LEN ? len : HEAD_ID_MAX_LEN;
            strncpy(config->id, start, len_id);
            i++;
        } 
        else if(jsoneq(json_string, &tok[i], "gateway") == 0) 
        {
            int len_id = len < HEAD_ID_MAX_LEN ? len : HEAD_ID_MAX_LEN;
            strncpy(config->gateway, start, len_id);
            i++;
        } 
        else if(jsoneq(json_string, &tok[i], "net") == 0) 
        {
            int len_id = len < HEAD_ID_MAX_LEN ? len : HEAD_ID_MAX_LEN;
            strncpy(config->net, start, len_id);
            i++;
        } 
        else if(jsoneq(json_string, &tok[i], "port") == 0) 
        {
            char * cc = strndup(start, len);
            config->port = strtol(cc, NULL, 10);
            free(cc);
            i++;
        } 
        else if(jsoneq(json_string, &tok[i], "mtu") == 0) 
        {
            char * cc = strndup(start, len);
            config->mtu = strtol(cc, NULL, 10);
            free(cc);
            i++;
        } 
        else if(jsoneq(json_string, &tok[i], "log_level") == 0) 
        {
            config->log_level = strndup(start, len);
            i++;
        } 
        else if(jsoneq(json_string, &tok[i], "secret_file") == 0) 
        {
            config->secret_file = strndup(start, len);
            i++;
        }
        else if(jsoneq(json_string, &tok[i], "forwarders") == 0) 
        {
            int j;
            if(tok[i+1].type != JSMN_ARRAY) 
                continue;
            for(j = 0; j < tok[i+1].size; j++) 
            {
                jsmntok_t *g = &tok[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                queue_put(config->forwarders, cg, 0);
            }
            i += tok[i+1].size + 1;
        }
        else if(jsoneq(json_string, &tok[i], "use_dns") == 0) 
        {
            int j;
            if(tok[i+1].type != JSMN_ARRAY) 
                continue;
            for(j = 0; j < tok[i+1].size; j++) 
            {
                jsmntok_t *g = &tok[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                queue_put(config->use_dns, cg, 0);
            }
            i += tok[i+1].size + 1;
        }
        else if(jsoneq(json_string, &tok[i], "local_routes") == 0) 
        {
            int j;
            if(tok[i+1].type != JSMN_ARRAY) 
                continue;
            for(j = 0; j < tok[i+1].size; j++) 
            {
                jsmntok_t *g = &tok[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                queue_put(config->local_routes, cg, 0);
                queue_put(config->local_routes_bakup, cg, 0);
            }
            i += tok[i+1].size + 1;
        } 
        else if(jsoneq(json_string, &tok[i], "pre_up_cmds") == 0) 
        {
            int j;
            if(tok[i+1].type != JSMN_ARRAY) 
                continue;
            for(j = 0; j < tok[i+1].size; j++) 
            {
                jsmntok_t *g = &tok[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                queue_put(config->pre_up_cmds, cg, 0);
            }
            i += tok[i+1].size + 1;
        } 
        else if(jsoneq(json_string, &tok[i], "post_up_cmds") == 0) 
        {
            int j;
            if(tok[i+1].type != JSMN_ARRAY)
                continue;
            for(j = 0; j < tok[i+1].size; j++) 
            {
                jsmntok_t *g = &tok[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                queue_put(config->post_up_cmds, cg, 0);
            }
            i += tok[i+1].size + 1;
        }
        else if(jsoneq(json_string, &tok[i], "pre_down_cmds") == 0) 
        {
            int j;
            if(tok[i+1].type != JSMN_ARRAY) 
                continue;
            for(j = 0; j < tok[i+1].size; j++) 
            {
                jsmntok_t *g = &tok[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                queue_put(config->pre_down_cmds, cg, 0);
            }
            i += tok[i+1].size + 1;
        } 
        else if(jsoneq(json_string, &tok[i], "post_down_cmds") == 0) 
        {
            int j;
            if(tok[i+1].type != JSMN_ARRAY)
                continue;
            for(j = 0; j < tok[i+1].size; j++) 
            {
                jsmntok_t *g = &tok[i+j+2];
                char * start_g = json_string + g->start;
                int len_g = g->end - g->start;
                char * cg = strndup(start_g, len_g);
                queue_put(config->post_down_cmds, cg, 0);
            }
            i += tok[i+1].size + 1;
        }
        else if(jsoneq(json_string, &tok[i], "chnroute") == 0) 
        {
            jsmntok_t *sub_tok = &tok[i+1];
            if(sub_tok[0].type != JSMN_OBJECT)
                continue;

            config->chnroute = (chnroute_t *)malloc(sizeof(chnroute_t));

            int left = tok_nr - (i+1);
            int j;
            int sub_tok_nr = 0;
            for(j = 1; j < left && sub_tok[j].end < sub_tok[0].end; j++) 
            {
                jsmntok_t *t = &sub_tok[j+1];
                char * start_t = json_string + t->start;
                int len_t = t->end - t->start;
                char * cg = strndup(start_t, len_t);
                
                if(jsoneq(json_string, &sub_tok[j], "table") == 0)
                {
                    config->chnroute->table = cg;
                    sub_tok_nr++;
                }
                else if(jsoneq(json_string, &sub_tok[j], "gateway") == 0)
                {
                    config->chnroute->gateway = cg;
                    sub_tok_nr++;
                }
                else if(jsoneq(json_string, &sub_tok[j], "data") == 0)
                {
                    config->chnroute->data = cg;
                    sub_tok_nr++;
                }
                j++;
                sub_tok_nr++;
            }
            i += sub_tok_nr + 1;
        }
        else 
            WARNING("Unexpected key: %.*s", tok[i].end-tok[i].start, json_string + tok[i].start);
    }

    free(json_string);
    free(tok);

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

    if(str_equal(level, "critical"))
        return LOG_LEVEL_CRITICAL;
    else if(str_equal(level, "error"))
        return LOG_LEVEL_ERROR;
    else if(str_equal(level, "warning"))
        return LOG_LEVEL_WARNING;
    else if(str_equal(level, "info"))
        return LOG_LEVEL_INFO;
    else if(str_equal(level, "debug"))
        return LOG_LEVEL_DEBUG;
    else if(str_equal(level, "notset"))
        return LOG_LEVEL_NOTSET;
    
    return LOG_LEVEL_INFO;
}


int check_config(config_t * config)
{
    if(config->mode == NULL || config->group == NULL || config->id[0] == '\0' || config->net[0] == '\0')
    {
        ERROR(0, "mode/group/id/net cannot be empty!");
        return -1;
    }

    if(!str_equal(config->mode, "client") && !str_equal(config->mode, "server"))
    {
        ERROR(0, "mode must be client or server: %s", config->mode);
        return -1;
    }

    int self_id = inet_ptons(config->id);
    if(self_id <= 1 || self_id >= HEAD_MAX_ID)
    {
        ERROR(0, "ID must between 0.2 and 255.254: %s", config->id);
        return -1;
    }

    int net_id = inet_ptons(config->net);
    if(net_id < 256 || net_id > HEAD_MAX_ID)
    {
        ERROR(0, "NET must between 1.0 and 255.255: %s", config->net);
        return -1;
    }

    if(str_equal(config->mode, "client"))
    {
        if(str_is_empty(config->gateway))
        {
            ERROR(0, "please specify a gateway for the client!");
            return -1;
        }

        int gateway_id = inet_ptons(config->gateway);
        if(gateway_id <= 1 || gateway_id >= HEAD_MAX_ID)
        {
            ERROR(0, "gateway must between 0.2 and 255.254: %s", config->gateway);
            return -1;
        }
    }

    // config->forwarder_nr = 0;

    // while(!queue_is_empty(config->forwarders))
    // {
    //     config->forwarder_nr++;
    //     char * forwarder_str = NULL;
    //     queue_get(config->forwarders, (void **)&forwarder_str, NULL);
    //     int forwarder_id = inet_ptons(forwarder_str);
    //     if(forwarder_id <= 1 || forwarder_id >= HEAD_MAX_ID)
    //     {
    //         ERROR(0, "forwarder must between 0.2 and 255.254: %s", forwarder_str);
    //         return -1;
    //     }
    //     INFO("forwarder: %s", forwarder_str);
    // }
    // if(config->forwarder_nr > MAX_FORWARDER_CNT)
        // WARNING("too many forwarders, only %d allowed!", MAX_FORWARDER_CNT);

    if(config->port < 0 || config->port > 65534)
    {
        ERROR(0, "port must be between %d and %d: %d", 0, 65534, config->port);
        return -1;
    }

    if(config->mtu < TUN_MTU_MIN || config->mtu > TUN_MTU_MAX)
    {
        ERROR(0, "MTU must be between %d and %d: %d", TUN_MTU_MIN, TUN_MTU_MAX, config->mtu);
        return -1;
    }

    return 0;
}

