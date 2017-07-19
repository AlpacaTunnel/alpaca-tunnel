#ifndef SEARCH_SORT_H_
#define SEARCH_SORT_H_

#include <stdint.h>

int binary_search(const int64_t arr[], int start, int end, int64_t key);  // todo: return -1 as error? what if the key is -1?

void bubble_sort(int64_t arr[], int len);

void merge_sort(int64_t arr[], int len);


#endif
