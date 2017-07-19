#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "bit-array.h"


bit_array_t* bit_array_init(uint32_t size)
{
    if(size == 0 || size > BIT_ARRAY_MAX_SIZE)
    {
        printf("bit_array_create: size is illegal: %d.\n", size);
        return NULL;
    }

    bit_array_t * ba = (bit_array_t *)malloc(sizeof(bit_array_t));
    if(ba == NULL)
    {
        perror("bit_array_create: malloc failed");
        return NULL;
    }
    else
        bzero(ba, sizeof(bit_array_t));

    ba->size = size;
    uint32_t unit_num = (size + BIT_ARRAY_UNIT_SIZE - 1) / BIT_ARRAY_UNIT_SIZE;
    ba->array = (bit_array_unit *)malloc(unit_num);
    if(ba->array == NULL)
    {
        perror("bit_array_create: malloc failed");
        free(ba);
        return NULL;
    }
    else
        bzero(ba->array, unit_num);

    return ba;
}


int bit_array_destroy(bit_array_t *ba)
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


int bit_array_copy(bit_array_t *dst, bit_array_t *src)
{
    if(dst == NULL || src == NULL)
    {
        printf("bit_array_copy: dst or src is NULL.\n");
        return -1;
    }
    if(dst->size != src->size)
    {
        printf("bit_array_copy: dst->size != src->size.\n");
        return -1;
    }
    uint32_t unit_num = (dst->size + BIT_ARRAY_UNIT_SIZE - 1) / BIT_ARRAY_UNIT_SIZE;
    memcpy(dst->array, src->array, unit_num);

    return 0;
}


int bit_array_clearall(bit_array_t *ba)
{
    int i;
    uint32_t unit_num = (ba->size + BIT_ARRAY_UNIT_SIZE - 1) / BIT_ARRAY_UNIT_SIZE;
    for(i=0; i<unit_num; i++)
        ba->array[i] = 0;

    return 0;
}


int bit_array_setall(bit_array_t *ba)
{
    int i;
    uint32_t unit_num = (ba->size + BIT_ARRAY_UNIT_SIZE - 1) / BIT_ARRAY_UNIT_SIZE;
    for(i=0; i<unit_num; i++)
        ba->array[i] = ~0;

    return 0;
}


int bit_array_set(bit_array_t *ba, uint32_t index)
{
    if(index > ba->size)
    {
        printf("bit_array_set: index is larger than size: %d.\n", index);
        return -1;
    }

    uint32_t array_index = index / BIT_ARRAY_UNIT_SIZE;
    uint32_t bit_index = index % BIT_ARRAY_UNIT_SIZE;
    ba->array[array_index] |= (1 << bit_index);

    return 0;
}


int bit_array_clear(bit_array_t *ba, uint32_t index)
{
    if(index > ba->size)
    {
        printf("bit_array_clear: index is larger than size: %d.\n", index);
        return -1;
    }

    uint32_t array_index = index / BIT_ARRAY_UNIT_SIZE;
    uint32_t bit_index = index % BIT_ARRAY_UNIT_SIZE;
    ba->array[array_index] &= (~(1 << bit_index));

    return 0;
}


int bit_array_get(bit_array_t *ba, uint32_t index)
{
    if(index > ba->size)
    {
        printf("bit_array_get: index is larger than size: %d.\n", index);
        return -1;
    }

    uint32_t array_index = index / BIT_ARRAY_UNIT_SIZE;
    uint32_t bit_index = index % BIT_ARRAY_UNIT_SIZE;
    int v = (ba->array[array_index] >> bit_index) & 1 ;

    return v;
}

