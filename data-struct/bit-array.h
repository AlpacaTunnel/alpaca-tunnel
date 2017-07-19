#ifndef BIT_ARRAY_H_
#define BIT_ARRAY_H_

#include <stdint.h>


#define BIT_ARRAY_MAX_SIZE (1<<24)
#define BIT_ARRAY_UNIT_SIZE 8
//#define BIT_ARRAY_UNIT_MASK 0xFF
typedef uint8_t bit_array_unit;


typedef struct 
{
    bit_array_unit *array;
    uint32_t size;
} bit_array_t;



//must call at first
bit_array_t* bit_array_init(uint32_t size);
//must call at the end
int bit_array_destroy(bit_array_t *ba);
int bit_array_copy(bit_array_t *dst, bit_array_t *src);

int bit_array_clearall(bit_array_t *ba);
int bit_array_setall(bit_array_t *ba);

/*
  return -1: error
  return 0: empty
  return 1: occupy
*/
int bit_array_set(bit_array_t *ba, uint32_t index);
int bit_array_clear(bit_array_t *ba, uint32_t index);
int bit_array_get(bit_array_t *ba, uint32_t index);


#endif
