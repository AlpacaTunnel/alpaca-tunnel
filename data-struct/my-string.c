#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "my-string.h"


/* Just experimental.
 * Some talks here: Optimum size for malloc() allocation?
 * https://groups.google.com/forum/#!msg/marpa-parser/CLvjpAIvcaE/MKhDg_yUCxQJ
*/
#ifndef ALIGNED_MALLOC_
#define ALIGNED_MALLOC_
#define ALIGNED_BYTE 4096
#define MALLOC_MHEAD 16
#endif
void *aligned_malloc(size_t size)
{
    if(size <= 0)
        return NULL;

    uint blocks = size / ALIGNED_BYTE;
    uint fragment = size % ALIGNED_BYTE;
    if( (fragment+MALLOC_MHEAD) > ALIGNED_BYTE )
        blocks += 2;
    else
        blocks += 1;

    size_t aligned_size = blocks * ALIGNED_BYTE - MALLOC_MHEAD;
    // INFO("aligned_size: %d", aligned_size);
    return malloc(aligned_size);
    return malloc(size);
}


bool str_is_empty(const char * str)
{
    return str[0] == '\0';
}


bool str_equal(const char * str1, const char * str2)
{
    if(strcmp(str1, str2) == 0)
        return true;
    else
        return false;
}


bool strn_equal(const char * str1, const char * str2, int n)
{
    if(strncmp(str1, str2, n) == 0)
        return true;
    else
        return false;
}

