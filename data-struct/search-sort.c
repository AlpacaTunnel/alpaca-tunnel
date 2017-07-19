#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "search-sort.h"


int binary_search(const int64_t arr[], int start, int end, int64_t key)
{
    int mid;
    while (start <= end) 
    {
        mid = start + (end - start) / 2;
        if (arr[mid] < key)
            start = mid + 1;
        else if (arr[mid] > key)
            end = mid - 1;
        else
            return mid;
    }
    return -1;
}


void bubble_sort(int64_t arr[], int len)
{
    uint32_t i, j, temp;
    for (i = 0; i < len-1; i++)
        for (j = 0; j < len-1-i; j++)
            if (arr[j] > arr[j+1])
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


void merge_sort(int64_t arr[], int len)
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

