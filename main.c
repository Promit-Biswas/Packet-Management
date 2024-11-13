#include "src/file-handler.h"
#include "src/linked-list.h"
#include "src/hash.h"

int main()
{
    if (process_extracted_packets(PACKET_FILE, INPUT_FILE))
    {
        uint32_t table_size = 0;
        hash_table_entry_t **hash_table = NULL;

        table_size = next_prime(TABLE_SIZE);
        hash_table = (hash_table_entry_t **)calloc(table_size, sizeof(hash_table_entry_t *));

        if(hash_table == NULL)
        {
            perror("Memory Initialized Failed For Hash Table");
            exit(EXIT_FAILURE);
        }

        process_input_file(INPUT_FILE, &hash_table, &table_size);
        print_linked_list();
        print_hash_table(hash_table, table_size);
        free_hash_table(hash_table, table_size);
        free_linked_list(data_list_node_root);
        free(hash_table);
    }

    return EXIT_SUCCESS;
}