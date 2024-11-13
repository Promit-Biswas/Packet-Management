#ifndef FILE_HANDLER_H_INCLUDED
#define FILE_HANDLER_H_INCLUDED

#include <stdio.h>
#include "packets.h"
#include "hash.h"

#define INPUT_FILE "data/input.txt"
#define PACKET_FILE "data/exported-packets.txt"
#define SEPARATOR '\n'
#define MAX_LINE_LENGTH 257
#define BUFFER_SIZE 257
#define FIRST_SIX_CHAR 6
#define MAX_HEX_IN_LINE 16

void process_input_file(const char *file_name, hash_table_entry_t ***hash_table, uint32_t *table_size);
bool_t process_extracted_packets(const char *export, const char *input);

#endif // FILE_HANDLER_H_INCLUDED