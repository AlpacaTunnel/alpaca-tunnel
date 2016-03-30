#ifndef DATA_STRUCT_H_
#define DATA_STRUCT_H_

#include <stdint.h>

#define BIT_ARRAY_MAX_SIZE (1<<24)
#define BIT_ARRAY_UNIT_SIZE 8
//#define BIT_ARRAY_UNIT_MASK 0xFF
typedef uint8_t bit_array_unit;

struct bit_array_t 
{
    bit_array_unit *array;
    uint32_t size;
};


//must call at first
struct bit_array_t* bit_array_create(uint32_t size);
//must call at the end
int bit_array_destroy(struct bit_array_t *ba);
int bit_array_copy(struct bit_array_t *dst, struct bit_array_t *src);

int bit_array_clearall(struct bit_array_t *ba);
int bit_array_setall(struct bit_array_t *ba);

/*
  return -1: error
  return 0: empty
  return 1: occupy
*/
int bit_array_set(struct bit_array_t *ba, uint32_t index);
int bit_array_clear(struct bit_array_t *ba, uint32_t index);
int bit_array_get(struct bit_array_t *ba, uint32_t index);

int binary_search(const uint32_t arr[], int start, int end, int key);
void bubble_sort(uint32_t arr[], int len);

#endif
