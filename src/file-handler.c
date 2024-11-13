#include <stdlib.h>
#include <string.h>
#include "file-handler.h"
#include "linked-list.h"
#include "hash.h"

static void process_line(char *line, FILE *output_file, bool_t *skip_newline_flag);

bool_t process_extracted_packets(const char *export, const char *input)
{
    FILE *exported_file = NULL;
    FILE *input_file_for_processing = NULL;
    char line[MAX_LINE_LENGTH] = {0};
    bool_t skip_newline_flag = false;

    input_file_for_processing = fopen(input, "r");

    /*If the processed file already exists, then no need to Process a new file*/
    if (input_file_for_processing != NULL)
    {
        fclose(input_file_for_processing);

        return true;
    }

    exported_file = fopen(export, "r");

    if (exported_file == NULL)
    {
        fprintf(stderr, "Error opening file: %s\n", PACKET_FILE);

        return false;
    }

    input_file_for_processing = fopen(input, "w");

    if (input_file_for_processing == NULL)
    {
        fprintf(stderr, "Error opening file: %s\n", INPUT_FILE);
        fclose(exported_file);

        return false;
    }

    /* Read each line and process it */
    while (fgets(line, sizeof(line), exported_file))
    {
        process_line(line, input_file_for_processing, &skip_newline_flag);
    }

    fclose(exported_file);
    fclose(input_file_for_processing);

    return true;
}

void process_input_file(const char *file_name, hash_table_entry_t ***hash_table, uint32_t *table_size)
{
    char input_buffer[BUFFER_SIZE] = {0};
    FILE *input_file = NULL;
    ethernet_header_t *ethernet_header = NULL;
    ipv4_header_t *ipv4_header = NULL;
    udp_header_t *udp_header = NULL;
    key_ip_pair_t *ip_pair = NULL;
    size_t len = 0;
    int ch = 0;

    input_file = fopen(file_name, "r");

    if (input_file == NULL)
    {
        fprintf(stderr, "Error opening file: %s\n", file_name);
        exit(EXIT_FAILURE);
    }

    ethernet_header = (ethernet_header_t *)calloc(STRUCT_MULTIPLIER, sizeof(ethernet_header_t));
    ipv4_header = (ipv4_header_t *)calloc(STRUCT_MULTIPLIER, sizeof(ipv4_header_t));
    udp_header = (udp_header_t *)calloc(STRUCT_MULTIPLIER, sizeof(udp_header_t));
    ip_pair = (key_ip_pair_t *)calloc(STRUCT_MULTIPLIER, sizeof(key_ip_pair_t));

    if (ethernet_header == NULL || ipv4_header == NULL || udp_header == NULL || ip_pair == NULL)
    {
        perror("Memory allocation failed for header structures");
        free(ethernet_header);
        free(ipv4_header);
        free(udp_header);
        free(ip_pair);
        fclose(input_file);
        ethernet_header = NULL;
        ipv4_header = NULL;
        udp_header = NULL;
        ip_pair = NULL;
        exit(EXIT_FAILURE);
    }

    /* Read the input file line by line */
    while (fgets(input_buffer, sizeof(input_buffer), input_file))
    {
        /* Get the length of the input line */
        len = strlen(input_buffer);

        /* If the line exceeds the buffer size, discard the excess */
        if (len == BUFFER_SIZE - 1 && input_buffer[BUFFER_SIZE - 2] != '\n')
        {
            /* Discard the rest of the line, This is payload.*/
            while ((ch = fgetc(input_file)) != '\n' && ch != EOF)
            {
                /* Continue reading until end of line */
            }
        }

        /* Remove the newline character if present */
        if (len > 0 && input_buffer[len - 1] == '\n')
        {
            input_buffer[len - 1] = '\0';
        }

        process_ethernet_header(input_buffer, ethernet_header);

        if (is_ipv4(ethernet_header))
        {
            process_ipv4_header(input_buffer, ipv4_header);

            if (is_udp(ipv4_header))
            {
                process_udp_header(input_buffer, udp_header, ipv4_header);
                memcpy(ip_pair->source_ip, ipv4_header->source_ip, IP_SECTION_SIZE);
                memcpy(ip_pair->destination_ip, ipv4_header->destination_ip, IP_SECTION_SIZE);
                insert_into_hash_table(ip_pair, hash_table, table_size);

                /*If Debug is turned on then this will work*/
                PRINT_ETHERNET(ethernet_header);
                PRINT_IP(ipv4_header);
                PRINT_UDP(udp_header);
            }
        }
    }

    free(ethernet_header);
    free(ipv4_header);
    free(udp_header);
    free(ip_pair);
    fclose(input_file);
    ethernet_header = NULL;
    ipv4_header = NULL;
    udp_header = NULL;
    ip_pair = NULL;

    return;
}

static void process_line(char *line, FILE *output_file, bool_t *skip_newline_flag)
{
    uint8_t iteration = 0;

    /* If a new block starts, add a separator before the data */
    if (*skip_newline_flag && strncmp(line, "0000", 4) == 0)
    {
        fputc(SEPARATOR, output_file);
    }

    /* Move the pointer 6 characters forward to skip the address */
    if (strlen(line) >= FIRST_SIX_CHAR)
    {
        line += FIRST_SIX_CHAR;
    }
    else
    {
        /* Avoid out-of-bounds access */
        return;
    }

    /* Process the next 16 bytes of hex data */
    for (iteration = 0; iteration < MAX_HEX_IN_LINE; iteration++)
    {
        if (*line != ' ') /* Skip spaces */
        {
            fwrite(line, 1, 2, output_file); /* Write two characters (hex byte) */
        }

        line += 3; /* Move pointer to the next hex byte, skipping the space */

        if (strlen(line) < 3) /* Ensure that the pointer doesn't go out of bounds */
        {
            break;
        }
    }

    /* Set the skip_newline_flag to skip the newline at the beginning of the output file */
    if (*skip_newline_flag == 0)
    {
        *skip_newline_flag = 1;
    }

    return;
}