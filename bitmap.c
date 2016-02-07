#include "bitmap.h"
#include <stdlib.h>
#include <strings.h>

struct bit_array_t* bit_array_create(uint32_t size)
{
    if(size == 0 || size > BIT_ARRAY_MAX_SIZE)
        return NULL;

    struct bit_array_t * ba = (struct bit_array_t *)malloc(sizeof(struct bit_array_t));
    if(ba == NULL)
        return NULL;
    else
        bzero(ba, sizeof(struct bit_array_t));

    ba->size = size;
    uint32_t unit_num = (size+BIT_ARRAY_UNIT_SIZE-1) / BIT_ARRAY_UNIT_SIZE;
    ba->array = (bit_array_unit *)malloc(unit_num);
    if(ba->array == NULL)
    {
        free(ba);
        ba = NULL;
        return NULL;
    }
    else
        bzero(ba->array, unit_num);

    return ba;
}

int bit_array_destroy(struct bit_array_t *ba)
{
    if(ba == NULL)
        return 0;

    if(ba->array != NULL)
        free(ba->array);
    ba->array = NULL;
    free(ba);
    ba = NULL;

    return 0;
}

int bit_array_clearall(struct bit_array_t *ba)
{
    int i;
    uint32_t unit_num = (ba->size+BIT_ARRAY_UNIT_SIZE-1) / BIT_ARRAY_UNIT_SIZE;
    for(i=0; i<unit_num; i++)
        ba->array[i] = 0;

    return 0;
}

int bit_array_setall(struct bit_array_t *ba)
{
    int i;
    uint32_t unit_num = (ba->size+BIT_ARRAY_UNIT_SIZE-1) / BIT_ARRAY_UNIT_SIZE;
    for(i=0; i<unit_num; i++)
        ba->array[i] = ~0;

    return 0;
}

int bit_array_set(struct bit_array_t *ba, uint32_t index)
{
    if(index > ba->size)
        return -1;

    uint32_t array_index = index / BIT_ARRAY_UNIT_SIZE;
    uint32_t bit_index = index % BIT_ARRAY_UNIT_SIZE;
    ba->array[array_index] |= (1 << bit_index);

    return 0;
}

int bit_array_clear(struct bit_array_t *ba, uint32_t index)
{
    if(index > ba->size)
        return -1;

    uint32_t array_index = index / BIT_ARRAY_UNIT_SIZE;
    uint32_t bit_index = index % BIT_ARRAY_UNIT_SIZE;
    ba->array[array_index] &= (~(1 << bit_index));

    return 0;
}

int bit_array_get(struct bit_array_t *ba, uint32_t index)
{
    if(index > ba->size)
        return -1;

    uint32_t array_index = index / BIT_ARRAY_UNIT_SIZE;
    uint32_t bit_index = index % BIT_ARRAY_UNIT_SIZE;
    int v = (ba->array[array_index] >> bit_index) & 1 ;

    return v;
}
