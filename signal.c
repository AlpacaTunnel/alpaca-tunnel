#include <stdlib.h> 
#include <signal.h>
#include <strings.h>

#include "signal.h"
#include "log.h"

#define MIN_SIGNAL_NUM 1
#define MAX_SIGNAL_NUM 32


typedef struct
{
    int signum;
    void (*action)(void *);
    void * action_arg;
} signal_t;


static signal_t * global_signal_array = NULL;


char * get_signal_name(int signum)
{
     switch(signum)
     {
        case SIGHUP:
            return "SIGHUP";
        case SIGTERM:
            return "SIGTERM";
        case SIGINT:
            return "SIGINT";
        default:
            return "Unknown SIG";
    }
}


void handle_signal(int signum)
{
    INFO("Received signal: %s", get_signal_name(signum));
    signal_t * this_signal = &global_signal_array[signum];
    if(this_signal->signum != 0)
        this_signal->action(this_signal->action_arg);
}


int signal_init()
{
    if(global_signal_array != NULL)
    {
        ERROR(0, "Can NOT call signal_init() more than once.");
        return -1;
    }

    global_signal_array = (signal_t *)malloc(sizeof(signal_t) * (MAX_SIGNAL_NUM + 1));
    if(global_signal_array == NULL)
    {
        ERROR(errno, "signal_init: malloc");
        return -1;
    }
    bzero(global_signal_array, sizeof(signal_t) * (MAX_SIGNAL_NUM + 1));

    return 0;
}


int signal_install(int signum, void (*action)(void *), void * action_arg)
{
    if(global_signal_array == NULL)
    {
        ERROR(0, "Must call signal_init() first");
        return -1;
    }

    if(signum < MIN_SIGNAL_NUM || signum > MAX_SIGNAL_NUM)
    {
        ERROR(0, "signum must be between %d and %d", MIN_SIGNAL_NUM, MAX_SIGNAL_NUM);
        return -1;
    }

    signal_t * this_signal = &global_signal_array[signum];

    if(this_signal->signum != 0)
    {
        ERROR(0, "Can NOT install the same signal more than once: %s", get_signal_name(signum));
        return -1;
    }

    this_signal->signum = signum;
    this_signal->action = action;
    this_signal->action_arg = action_arg;

    struct sigaction sa;
    sa.sa_handler = &handle_signal;
    // Restart the system call, if at all possible
    sa.sa_flags = SA_RESTART;
    // Block every signal during the handler
    sigfillset(&sa.sa_mask);

    if (sigaction(signum, &sa, NULL) == -1) {
        ERROR(errno, "install signal failed: %s", signum);
        return -1;
    }

    INFO("Installed signal: %s", get_signal_name(signum));

    return 0;
}

