#ifndef HASH_H_INCLUDED
#define HASH_H_INCLUDED

#include <limits.h>
#include "linked-list.h"

#define ROTATE_1 4
#define ROTATE_2 23
#define ROTATE_3 15
#define ROTATE_4 7
#define TABLE_SIZE 2
#define NEXT_MULTIPLIER 2
#define MAX_LOAD_FACTOR 0.75
#define UINT_BITS (sizeof(uint32_t) * CHAR_BIT)
#define roll32(x, n) (((x) << (n)) | ((x) >> (UINT_BITS - (n))))

typedef struct hash_table_entry
{
    data_list_node_t *node;
    struct hash_table_entry *next;
} hash_table_entry_t;

void insert_into_hash_table(key_ip_pair_t *ip_pair, hash_table_entry_t ***hash_table, uint32_t *table_size);
void print_hash_table(hash_table_entry_t **hash_table, uint32_t table_size);
void free_hash_table(hash_table_entry_t **hash_table, uint32_t table_size);
uint32_t next_prime(uint32_t value);

#endif // HASH_H_INCLUDED