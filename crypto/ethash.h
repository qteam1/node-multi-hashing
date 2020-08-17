#ifndef __ETHASH_H
#define __ETHASH_H

#include <stdint.h>

#define ETHASH_EPOCH_LENGTH 30000U
#define ETHASH_MIX_BYTES 128
#define ETHASH_HASH_BYTES 64
#define ETHASH_DATASET_PARENTS 256
#define ETHASH_CACHE_ROUNDS 3
#define ETHASH_ACCESSES 64

#define ETHASH_LIGHT_CACHE_ITEM_SIZE 64
#define ETHASH_FULL_DATASET_ITEM_SIZE 128
#define ETHASH_NUM_DATASET_ACCESSES 64

#define ETHASH_LIGHT_CACHE_INIT_SIZE (1 << 24)
#define ETHASH_LIGHT_CACHE_GROWTH (1 << 17)
#define ETHASH_LIGHT_CACHE_ROUNDS 3
#define ETHASH_FULL_DATASET_INIT_SIZE (1 << 30)
#define ETHASH_FULL_DATASET_GROWTH (1 << 23)
#define ETHASH_FULL_DATASET_ITEM_PARENTS 256

/* Checks if the number is prime. */
int is_odd_prime(int64_t number)
{
    int64_t d = 3;
    int64_t n = number;
    /* Check factors up to sqrt(n).
       To avoid computing sqrt, compare d*d <= n with 64-bit precision. */
    for (; d * d <= n; d += 2) {
        if (n % d == 0) {
            return 0;
        }
    }

    return 1;
}

int is_odd_prime_with_nsqrt(int64_t number, int64_t nsqrt)
{
    int64_t d = 3;
    int64_t n = number;
    for (; d <= nsqrt; d += 2) {
        if (n % d == 0)
            return 0;
    }

    return 1;
}

uint64_t isqrt(uint64_t number)
{
    uint64_t low = 1;
    uint64_t high = number;
    uint64_t mid = 0;
    while (low <= high) {
        mid = (low + high) >> 1;
        uint64_t target = mid * mid;
        if (target > number) {
            high = mid - 1;
        } else if (target < number) {
            low = mid + 1;
        } else {
            // exact match
            return mid;
        }
    }

    return high;
}

static int find_largest_prime(int upper_bound)
{
    int n = upper_bound;

    if (n < 2) return 0;
    if (n == 2) return 2;
    /* If even number, skip it. */
    if (n % 2 == 0) --n;
    /* Test descending odd numbers. */
    while (!is_odd_prime(n)) n -= 2;

    return n;
}

int ethash_get_cache_size(int epoch_number)
{
    static const int item_size = ETHASH_LIGHT_CACHE_ITEM_SIZE;
    static const int num_items_init = ETHASH_LIGHT_CACHE_INIT_SIZE / ETHASH_LIGHT_CACHE_ITEM_SIZE;
    static const int num_items_growth = ETHASH_LIGHT_CACHE_GROWTH / ETHASH_LIGHT_CACHE_ITEM_SIZE;

    int num_items_upper_bound = num_items_init + epoch_number * num_items_growth;
    int num_items = find_largest_prime(num_items_upper_bound);
    return num_items * item_size;
}

int ethash_get_dag_size(int epoch_number)
{
    static const int item_size = ETHASH_FULL_DATASET_ITEM_SIZE;
    static const int num_items_init = ETHASH_FULL_DATASET_INIT_SIZE / ETHASH_FULL_DATASET_ITEM_SIZE;
    static const int num_items_growth = ETHASH_FULL_DATASET_GROWTH / ETHASH_FULL_DATASET_ITEM_SIZE;

    int num_items_upper_bound = num_items_init + epoch_number * num_items_growth;
    int num_items = find_largest_prime(num_items_upper_bound);
    return num_items * item_size;
}

#endif // __ETHASH_H
