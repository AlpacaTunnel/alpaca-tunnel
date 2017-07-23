#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "search-sort.h"


int binary_search_int(const int64_t arr[], int start, int end, int64_t key)
{
    int mid;
    while(start <= end) 
    {
        mid = start + (end - start) / 2;
        if(arr[mid] < key)
            start = mid + 1;
        else if(arr[mid] > key)
            end = mid - 1;
        else
            return mid;
    }
    return -1;
}


int binary_search(void * arr, int unit_size, int start, int end, void * key, int (*compare)(void *one, void *two))
{
    int mid;
    while(start <= end) 
    {
        mid = start + (end - start) / 2;
        int cmp = compare(arr + mid*unit_size, key);
        if(cmp < 0)
            start = mid + 1;
        else if(cmp > 0)
            end = mid - 1;
        else
            return mid;
    }
    return -1;
}


void bubble_sort_int(int64_t arr[], int len)
{
    uint32_t i, j, temp;
    for(i = 0; i < len-1; i++)
        for(j = 0; j < len-1-i; j++)
            if(arr[j] > arr[j+1])
            {
                temp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = temp;
            }
}


int min(int x, int y)
{
    return x < y ? x : y;
}


void merge_sort_int(int64_t arr[], int len)
{
    int64_t * a = arr;
    int64_t * b = (int64_t*)malloc(len * sizeof(int64_t));
    if(b == NULL)
    {
        perror("merge_sort: malloc failed");
        return;
    }
    int64_t * mark_b = b;

    int seg, start;
    for(seg = 1; seg < len; seg += seg)
    {
        for(start = 0; start < len; start += seg + seg)
        {
            int low = start, mid = min(start + seg, len), high = min(start + seg + seg, len);
            int k = low;
            int start1 = low, end1 = mid;
            int start2 = mid, end2 = high;
            while(start1 < end1 && start2 < end2)
                if(a[start1] < a[start2])
                {
                    b[k] = a[start1];
                    k++; start1++;
                }
                else
                {
                    b[k] = a[start2];
                    k++; start2++;
                }
            while(start1 < end1)
            {
                b[k] = a[start1];
                k++; start1++;
            }
            while(start2 < end2)
            {
                b[k] = a[start2];
                k++; start2++;
            }
        }
        int64_t* temp = a;
        a = b;
        b = temp;
        // at the end, a always holds the sorted array
    }

    if(a != arr)
        for(int i = 0; i < len; i++)
            arr[i] = a[i];
    
    free(mark_b);
}


void swap_int(int64_t *x, int64_t *y)
{
    int64_t t = *x;
    *x = *y;
    *y = t;
}

void quick_sort_int_recursive(int64_t arr[], int start, int end)
{
    if(start >= end)
        return;

    int64_t mid = arr[end];
    int left = start, right = end - 1;

    while(left < right)
    {
        while(arr[left] < mid && left < right)
            left++;
        while(arr[right] >= mid && left < right)
            right--;
        swap_int(&arr[left], &arr[right]);
    }

    if(arr[left] >= arr[end])
        swap_int(&arr[left], &arr[end]);
    else
        left++;

    if(left)
        quick_sort_int_recursive(arr, start, left - 1);

    quick_sort_int_recursive(arr, left + 1, end);
}

void quick_sort_int(int64_t arr[], int len)
{
    quick_sort_int_recursive(arr, 0, len - 1);
}


void quick_sort_recursive(void * arr, int unit_size, int start, int end, int (*compare)(void *one, void *two), void (*swap)(void *one, void *two))
{
    if(start >= end)
        return;

    void * mid = arr + end*unit_size;
    int left = start, right = end - 1;

    while(left < right)
    {
        while(compare(arr+left*unit_size, mid) < 0 && left < right)
            left++;
        while(compare(arr+right*unit_size, mid) >= 0 && left < right)
            right--;
        swap(arr + left*unit_size, arr + right*unit_size);
    }

    if(compare(arr + left*unit_size, arr + end*unit_size) >=0)
        swap(arr + left*unit_size, arr + end*unit_size);
    else
        left++;

    if(left)
        quick_sort_recursive(arr, unit_size, start, left - 1, compare, swap);

    quick_sort_recursive(arr, unit_size, left + 1, end, compare, swap);
}

void quick_sort(void * arr, int unit_size, int len, int (*compare)(void *one, void *two), void (*swap)(void *one, void *two))
{
    quick_sort_recursive(arr, unit_size, 0, len - 1, compare, swap);
}

