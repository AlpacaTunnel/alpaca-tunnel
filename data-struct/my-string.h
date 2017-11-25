#ifndef MY_STRING_H_
#define MY_STRING_H_


#include "types.h"


void *aligned_malloc(size_t size);

bool str_is_empty(const char * str);
bool str_equal(const char * str1, const char * str2);
bool strn_equal(const char * str1, const char * str2, int n);


#endif
