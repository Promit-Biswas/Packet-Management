#ifndef LINKED_LIST_H_INCLUDED
#define LINKED_LIST_H_INCLUDED

#include <stdint.h>
#include "packets.h"

#define INITIAL_VALUE 1

typedef struct key_ip_pair
{
    uint8_t source_ip[IP_SECTION_SIZE];
    uint8_t destination_ip[IP_SECTION_SIZE];
} key_ip_pair_t;

typedef struct data_list_node
{
    key_ip_pair_t *ip_pair;
    uint32_t ref_count;
    struct data_list_node *next;
} data_list_node_t;

extern data_list_node_t *data_list_node_root;
extern data_list_node_t *data_list_node_tail;

void insert_into_linked_list(data_list_node_t **list, const key_ip_pair_t *ip_pair);
void print_linked_list(void);
void free_linked_list(data_list_node_t *list);

#endif // LINKED_LIST_H_INCLUDED