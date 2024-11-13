#include <string.h>
#include <stdio.h>
#include "packets.h"
#include "byte-order.h"

static void hex_to_byte_array(const char *hex_strm, uint8_t byte_array[], uint8_t len);
static void parse_eth_header(ethernet_header_t *ethernet_header, const uint8_t *ethernet_byte_array);
static void parse_ipv4_header(ipv4_header_t *ipv4_header, const uint8_t *ipv4_byte_array);
static void parse_udp_header(udp_header_t *udp_header, const uint8_t *udp_byte_array);

bool_t is_ipv4(ethernet_header_t *ethernet_header)
{
    return ethernet_header->ip_protocol == IPV4_PROTOCOL;
}

bool_t is_udp(ipv4_header_t *ipv4_header)
{
    return ipv4_header->protocol == UDP_PROTOCOL;
}

static void hex_to_byte_array(const char *hex_strm, uint8_t byte_array[], uint8_t len)
{
    uint8_t iteration = 0;

    for (iteration = 0; iteration < len; iteration++)
    {
        /* sscanf reads 2 hex digits from hex_strm and stores the result in byte_array[iteration] */
        sscanf(&hex_strm[iteration * 2], "%2hhx", &byte_array[iteration]);
    }

    return;
}

static void parse_eth_header(ethernet_header_t *ethernet_header, const uint8_t *ethernet_byte_array)
{
    memcpy(&ethernet_header->destination_mac, ethernet_byte_array, MAC_SECTION_SIZE);
    memcpy(&ethernet_header->source_mac, ethernet_byte_array + 6, MAC_SECTION_SIZE);
    memcpy(&ethernet_header->ip_protocol, ethernet_byte_array + 12, UINT16_T_SIZE);

    if (is_little_endian())
    {
        ethernet_header->ip_protocol = custom_ntohs(ethernet_header->ip_protocol);
    }

    return;
}

static void parse_ipv4_header(ipv4_header_t *ipv4_header, const uint8_t *ipv4_byte_array)
{
    ipv4_header->version = (ipv4_byte_array[0] >> 4) & 0xF;
    ipv4_header->header_len = ipv4_byte_array[0] & 0xF;
    ipv4_header->tos = ipv4_byte_array[1];
    memcpy(&ipv4_header->total_len, &ipv4_byte_array[2], UINT16_T_SIZE);
    memcpy(&ipv4_header->identification, &ipv4_byte_array[4], UINT16_T_SIZE);
    ipv4_header->flags = (ipv4_byte_array[6] >> 5) & 0x7;
    ipv4_header->frag_offset = ((ipv4_byte_array[6] & 0x1F) << 8) | ipv4_byte_array[7];
    ipv4_header->ttl = ipv4_byte_array[8];
    ipv4_header->protocol = ipv4_byte_array[9];
    memcpy(&ipv4_header->checksum, &ipv4_byte_array[10], UINT16_T_SIZE);
    memcpy(ipv4_header->source_ip, &ipv4_byte_array[12], IP_SECTION_SIZE);
    memcpy(ipv4_header->destination_ip, &ipv4_byte_array[16], IP_SECTION_SIZE);
    ipv4_header->option_size = (ipv4_header->header_len) * 4 - 20;

    if (is_little_endian())
    {
        ipv4_header->total_len = custom_ntohs(ipv4_header->total_len);
        ipv4_header->identification = custom_ntohs(ipv4_header->identification);
        ipv4_header->checksum = custom_ntohs(ipv4_header->checksum);
    }

    return;
}

static void parse_udp_header(udp_header_t *udp_header, const uint8_t *udp_byte_array)
{
    memcpy(&udp_header->source_port, &udp_byte_array[0], UINT16_T_SIZE);
    memcpy(&udp_header->destination_port, &udp_byte_array[2], UINT16_T_SIZE);
    memcpy(&udp_header->length, &udp_byte_array[4], UINT16_T_SIZE);
    memcpy(&udp_header->checksum, &udp_byte_array[6], UINT16_T_SIZE);

    if (is_little_endian())
    {
        udp_header->source_port = custom_ntohs(udp_header->source_port);
        udp_header->destination_port = custom_ntohs(udp_header->destination_port);
        udp_header->length = custom_ntohs(udp_header->length);
        udp_header->checksum = custom_ntohs(udp_header->checksum);
    }

    return;
}

void process_ethernet_header(const char *input_buffer, ethernet_header_t *ethernet_header)
{
    uint8_t ethernet_byte_array[ETHERNET_HEADER_SIZE] = {0};

    hex_to_byte_array(input_buffer, ethernet_byte_array, ETHERNET_HEADER_SIZE);
    parse_eth_header(ethernet_header, ethernet_byte_array);

    return;
}

void process_ipv4_header(const char *input_buffer, ipv4_header_t *ipv4_header)
{
    uint8_t ipv4_byte_array[IPV4_HEADER_SIZE] = {0};
    uint8_t *options_byte_array = NULL;
    uint8_t offset = 0;

    hex_to_byte_array(input_buffer + ETHERNET_HEADER_SIZE * 2, ipv4_byte_array, IPV4_HEADER_SIZE);
    parse_ipv4_header(ipv4_header, ipv4_byte_array);

    if (ipv4_header->option_size > 0)
    {
        options_byte_array = (uint8_t *)calloc(1, ipv4_header->option_size);

        if (options_byte_array == NULL)
        {
            perror("Memory Not Allocated");
            exit(EXIT_FAILURE);
        }

        offset = ETHERNET_HEADER_SIZE * 2 + IPV4_HEADER_SIZE * 2;
        hex_to_byte_array(input_buffer + offset, options_byte_array, ipv4_header->option_size);

        free(options_byte_array);
        options_byte_array = NULL;
    }

    return;
}

void process_udp_header(const char *input_buffer, udp_header_t *udp_header, ipv4_header_t *ipv4_header)
{
    uint8_t offset = 0;
    uint8_t udp_byte_array[UDP_HEADER_SIZE] = {0};

    offset = ETHERNET_HEADER_SIZE;
    offset += IPV4_HEADER_SIZE + ipv4_header->option_size;
    hex_to_byte_array(input_buffer + offset * 2, udp_byte_array, UDP_HEADER_SIZE);
    parse_udp_header(udp_header, udp_byte_array);

    return;
}

void print_ethernet(const ethernet_header_t *ethernet_header)
{
    puts("****************************************");
    puts("Ethernet Header Information  ");
    printf("    Destination Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->destination_mac[0], ethernet_header->destination_mac[1], ethernet_header->destination_mac[2],
           ethernet_header->destination_mac[3], ethernet_header->destination_mac[4], ethernet_header->destination_mac[5]);
    printf("    Source Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->source_mac[0], ethernet_header->source_mac[1], ethernet_header->source_mac[2],
           ethernet_header->source_mac[3], ethernet_header->source_mac[4], ethernet_header->source_mac[5]);
    printf("    Version: %04hx\n", ethernet_header->ip_protocol);
    puts("****************************************");

    return;
}

void print_ip(const ipv4_header_t *ipv4_header)
{
    puts("****************************************");
    puts("IP Header Information");
    printf("    Version: %x, IHL: %x\n", ipv4_header->version, ipv4_header->header_len);
    printf("    Source IP: %hu.%hu.%hu.%hu\n", ipv4_header->source_ip[0], ipv4_header->source_ip[1], ipv4_header->source_ip[2], ipv4_header->source_ip[3]);
    printf("    Destination IP: %hu.%hu.%hu.%hu\n", ipv4_header->destination_ip[0], ipv4_header->destination_ip[1], ipv4_header->destination_ip[2], ipv4_header->destination_ip[3]);
    puts("****************************************");

    return;
}

void print_udp(const udp_header_t *udp_header)
{
    puts("****************************************");
    puts("UDP Header Information");
    printf("    Source Port: %u\n", udp_header->source_port);
    printf("    Destination Port: %u\n", udp_header->destination_port);
    printf("    Length: %u\n", udp_header->length);
    printf("    Checksum: %04x\n", udp_header->checksum);
    puts("****************************************");
    puts("\n\n");

    return;
}