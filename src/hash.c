#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "hash.h"
#include "packets.h"

static void jhash(uint32_t *a, uint32_t *b);
static inline uint32_t ip_to_uint32(const uint8_t ip[IP_SECTION_SIZE]);
static inline uint32_t ip_pair_hash(const key_ip_pair_t *ip_pair, uint32_t *table_size);
static bool_t is_prime(uint32_t value);
static void rehash(hash_table_entry_t ***hash_table, uint32_t *table_size);

/* Rotate and hash utility */
static void jhash(uint32_t *a, uint32_t *b)
{
    *a ^= *b;
    *a -= roll32(*b, ROTATE_1);
    *b ^= *a;
    *b -= roll32(*a, ROTATE_2);
    *a ^= *b;
    *a -= roll32(*b, ROTATE_3);
    *b ^= *a;
    *b -= roll32(*a, ROTATE_4);

    return;
}

/* Convert an IP address to uint32 */
static inline uint32_t ip_to_uint32(const uint8_t ip[IP_SECTION_SIZE])
{
    return ((uint32_t)ip[0] << 24) |
           ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8)  |
           ((uint32_t)ip[3]);
}

/* Calculate the hash for a given IP pair */
static inline uint32_t ip_pair_hash(const key_ip_pair_t *ip_pair, uint32_t *table_size)
{
    uint32_t src_ip = 0;
    uint32_t dest_ip = 0;

    src_ip = ip_to_uint32(ip_pair->source_ip);
    dest_ip = ip_to_uint32(ip_pair->destination_ip);
    jhash(&src_ip, &dest_ip);

    return dest_ip % (*table_size);
}

static void rehash(hash_table_entry_t ***hash_table, uint32_t *table_size)
{
    uint32_t new_table_size = 0;
    hash_table_entry_t **new_table = NULL;
    hash_table_entry_t *entry = NULL;
    data_list_node_t *node = NULL;
    uint32_t hash = 0;
    uint32_t i = 0;

    new_table_size = next_prime(*table_size * NEXT_MULTIPLIER);
    new_table = (hash_table_entry_t **)calloc(new_table_size, sizeof(hash_table_entry_t *));

    if (new_table == NULL)
    {
        perror("Memory allocation failed during rehashing");
        exit(EXIT_FAILURE);
    }

    /* Rehash all existing entries into the new table */
    for (i = 0; i < (*table_size); i++)
    {
        entry = (*hash_table)[i];

        while (entry != NULL)
        {
            node = entry->node;

            /* Recalculate the hash for the new table size */
            hash = ip_pair_hash(node->ip_pair, &new_table_size);

            /* Insert the entry into the new table */
            hash_table_entry_t *temp = (hash_table_entry_t *)calloc(1, sizeof(hash_table_entry_t));

            if (temp == NULL)
            {
                perror("Memory allocation failed for new hash table entry");
                exit(EXIT_FAILURE);
            }

            temp->node = node;
            temp->next = new_table[hash];
            new_table[hash] = temp;

            entry = entry->next;
        }
    }

    /* Free the old table */
    free_hash_table(*hash_table, *table_size);
    free(*hash_table);
    *hash_table = NULL;

    /* Update the hash table and size to the new values */
    *hash_table = new_table;
    *table_size = new_table_size;

    return;
}

/* Insert an IP pair into the hash table */
void insert_into_hash_table(key_ip_pair_t *ip_pair, hash_table_entry_t ***hash_table, uint32_t *table_size)
{
    uint32_t hash = 0;
    hash_table_entry_t *entry = NULL;
    data_list_node_t *current = NULL;
    data_list_node_t *new_node = NULL;
    hash_table_entry_t *new_entry = NULL;
    static uint32_t num_elements = 0;

    if (ip_pair == NULL || *hash_table == NULL)
    {
        return;
    }

    /* Check load factor to determine if rehashing is necessary */
    if (num_elements >= (MAX_LOAD_FACTOR * (*table_size)))
    {
        rehash(hash_table, table_size);
    }

    /* Calculate the hash index for the given IP pair using the table size.*/
    hash = ip_pair_hash(ip_pair, table_size);
    entry = (*hash_table)[hash];

    while (entry != NULL)
    {
        current = entry->node;

        if (memcmp(current->ip_pair->source_ip, ip_pair->source_ip, IP_SECTION_SIZE) == 0 &&
            memcmp(current->ip_pair->destination_ip, ip_pair->destination_ip, IP_SECTION_SIZE) == 0)
        {
            current->ref_count++;

            /*Exit the function as the IP pair is already in the table.*/
            return;
        }

        entry = entry->next;
    }

    /* Create a new node for the IP pair and insert it into the linked list. */
    insert_into_linked_list(&new_node, ip_pair);
    new_entry = (hash_table_entry_t *)calloc(STRUCT_MULTIPLIER, sizeof(hash_table_entry_t));

    if (new_entry == NULL)
    {
        perror("Memory allocation failed for hash table entry");
        exit(EXIT_FAILURE);
    }

    /*Set the new node (holding the IP pair) into the new hash table entry.*/
    new_entry->node = new_node;

    /*Link the new entry at the head of the list for this hash index.*/
    new_entry->next = (*hash_table)[hash];

    /*Set the new entry as the first one in the list.*/
    (*hash_table)[hash] = new_entry;

    /* Increment the count of elements in the hash table */
    num_elements++;

    return;
}

/* Print the hash table with index information */
void print_hash_table(hash_table_entry_t **hash_table, uint32_t table_size)
{
    hash_table_entry_t *entry = NULL;
    data_list_node_t *node = NULL;
    uint32_t iteration = 0;

    puts("+--------------------------------------------------------------+");
    puts("|                       Hash Table                             |");
    puts("+-------+-------------------+-------------------+--------------+");
    puts("| Index |     Source IP     |   Destination IP  | Packet Count |");
    puts("+-------+-------------------+-------------------+--------------+");

    for (iteration = 0; iteration < table_size; iteration++)
    {
        entry = hash_table[iteration];

        if (entry == NULL)
        {
            continue;
        }

        while (entry != NULL)
        {
            node = entry->node;
            printf("| %5u |  %3hhu.%3hhu.%3hhu.%3hhu  |  %3hhu.%3hhu.%3hhu.%3hhu  | %12u |\n",
                   iteration,
                   node->ip_pair->source_ip[0], node->ip_pair->source_ip[1],
                   node->ip_pair->source_ip[2], node->ip_pair->source_ip[3],
                   node->ip_pair->destination_ip[0], node->ip_pair->destination_ip[1],
                   node->ip_pair->destination_ip[2], node->ip_pair->destination_ip[3],
                   node->ref_count);
            puts("+-------+-------------------+-------------------+--------------+");

            entry = entry->next;
        }
    }

    return;
}

/* Free the hash table */
void free_hash_table(hash_table_entry_t **hash_table, uint32_t table_size)
{
    uint32_t iteration = 0;
    hash_table_entry_t *entry = NULL;
    hash_table_entry_t *temp = NULL;

    for (iteration = 0; iteration < table_size; iteration++)
    {
        entry = hash_table[iteration];

        while (entry != NULL)
        {
            temp = entry;
            entry = entry->next;
            free(temp);
            temp = NULL;
        }
    }

    return;
}

/* Prime number utilities */
static bool_t is_prime(uint32_t value)
{
    uint32_t iteration = 0;

    if (value <= 1)
    {
        return false;
    }

    if (value <= 3)
    {
        return true;
    }

    if (value % 2 == 0 || value % 3 == 0)
    {
        return false;
    }

    for (iteration = 5; iteration * iteration <= value; iteration += 6)
    {
        if (value % iteration == 0 || value % (iteration + 2) == 0)
        {
            return false;
        }
    }

    return true;
}

uint32_t next_prime(uint32_t value)
{
    if (value <= 1)
    {
        return 2;
    }

    while (!is_prime(value))
    {
        value++;
    }

    return value;
}
