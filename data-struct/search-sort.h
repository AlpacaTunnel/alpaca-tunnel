#ifndef SEARCH_SORT_H_
#define SEARCH_SORT_H_

#include <stdint.h>


/* return the index in the array. if not found, return -1 */
int binary_search_int(const int64_t arr[], int start, int end, int64_t key);

/* return the index in the array. if not found, return -1 
 * compare: return -1, 0, 1 on one <, =, > two
 */
int binary_search(void * arr, int unit_size, int start, int end, void * key, int (*compare)(void *one, void *two));

void bubble_sort_int(int64_t arr[], int len);

void merge_sort_int(int64_t arr[], int len);

void quick_sort(void * arr, int unit_size, int len, int (*compare)(void *one, void *two), void (*swap)(void *one, void *two));


#endif
