#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "linked-list.h"
#include "packets.h"

data_list_node_t *data_list_node_root = NULL;
data_list_node_t *data_list_node_tail = NULL;

/* Insert a new node into the linked list */
void insert_into_linked_list(data_list_node_t **list, const key_ip_pair_t *ip_pair)
{
    data_list_node_t *new_node = NULL;

    new_node = (data_list_node_t *)calloc(STRUCT_MULTIPLIER, sizeof(data_list_node_t));

    if (new_node == NULL)
    {
        perror("Memory allocation failed for new list node");
        exit(EXIT_FAILURE);
    }

    new_node->ip_pair = (key_ip_pair_t *)calloc(STRUCT_MULTIPLIER, sizeof(key_ip_pair_t));

    if (new_node->ip_pair == NULL)
    {
        perror("Memory allocation failed for IP pair");
        free(new_node);
        new_node = NULL;
        exit(EXIT_FAILURE);
    }

    /* Copying the provided IP pair data into the new node */
    memcpy(new_node->ip_pair, ip_pair, sizeof(key_ip_pair_t));
    new_node->ref_count = INITIAL_VALUE;
    new_node->next = NULL;

    /* Setting the list pointer to the new node for hashing purpose*/
    *list = new_node;

    if (data_list_node_root == NULL)
    {
        data_list_node_root = new_node;
    }
    else
    {
        data_list_node_tail->next = new_node;
    }

    /* Updating the tail pointer to the new node */
    data_list_node_tail = new_node;

    return;
}

/*Printing the Linked List*/
void print_linked_list(void)
{
    data_list_node_t *current = data_list_node_root;
    uint32_t serial = 0;
    uint32_t total_counter = 0;

    puts("+------------------------------------------------------------+");
    puts("|                      Linked List                           |");
    puts("+-----+-------------------+-------------------+--------------+");
    puts("|  No |     Source IP     |   Destination IP  | Packet Count |");
    puts("+-----+-------------------+-------------------+--------------+");

    while (current != NULL)
    {
        printf("| %3u |  %3hhu.%3hhu.%3hhu.%3hhu  |  %3hhu.%3hhu.%3hhu.%3hhu  | %12u |\n",
               ++serial,
               current->ip_pair->source_ip[0], current->ip_pair->source_ip[1],
               current->ip_pair->source_ip[2], current->ip_pair->source_ip[3],
               current->ip_pair->destination_ip[0], current->ip_pair->destination_ip[1],
               current->ip_pair->destination_ip[2], current->ip_pair->destination_ip[3],
               current->ref_count);
        puts("+-----+-------------------+-------------------+--------------+");

        total_counter += current->ref_count;
        current = current->next;
    }

    printf("|               Total Packet Count            | %12u |\n", total_counter);
    puts("+---------------------------------------------+--------------+");

    return;
}

/* Free the linked list */
void free_linked_list(data_list_node_t *list)
{
    data_list_node_t *temp = NULL;

    /* Begin traversing the list to free each node */
    while (list != NULL)
    {
        temp = list;
        free(list->ip_pair);
        list->ip_pair = NULL;
        list = list->next;
        free(temp);
        temp = NULL;
    }

    return;
}
