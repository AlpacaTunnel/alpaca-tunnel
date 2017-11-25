#ifndef SIGNAL_H_
#define SIGNAL_H_

#include <signal.h>


/* 
 * sigaction wrapper that takes argument.
*/


int signal_init();
int signal_install(int signum, void (*action)(void *), void * action_arg);


#endif
