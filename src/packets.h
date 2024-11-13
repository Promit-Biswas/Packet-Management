#ifndef PACKET_HEADERS_H_INCLUDED
#define PACKET_HEADERS_H_INCLUDED

#include <stdlib.h>
#include <stdint.h>

#ifdef DEBUG
    #define PRINT_ETHERNET(ethernet_header) print_ethernet(ethernet_header)
    #define PRINT_IP(ipv4_header) print_ip(ipv4_header)
    #define PRINT_UDP(udp_header) print_udp(udp_header)
#else
    #define PRINT_ETHERNET(ethernet_header) ((void)0)
    #define PRINT_IP(ipv4_header) ((void)0)
    #define PRINT_UDP(udp_header) ((void)0)
#endif

#define ETHERNET_HEADER_SIZE 14
#define IPV4_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define IPV4_PROTOCOL 0x0800
#define UDP_PROTOCOL 0x11
#define MAC_SECTION_SIZE 6
#define IP_SECTION_SIZE 4
#define UINT16_T_SIZE 2
#define STRUCT_MULTIPLIER 1

typedef enum
{
    false = 0,
    true
} bool_t;

typedef struct ethernet_header
{
    uint8_t destination_mac[MAC_SECTION_SIZE];
    uint8_t source_mac[MAC_SECTION_SIZE];
    uint16_t ip_protocol;
} ethernet_header_t;

typedef struct ipv4_header
{
    uint8_t version : 4;
    uint8_t header_len : 4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t identification;
    uint16_t flags : 3;
    uint16_t frag_offset : 13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t source_ip[IP_SECTION_SIZE];
    uint8_t destination_ip[IP_SECTION_SIZE];
    size_t option_size;
} ipv4_header_t;

typedef struct udp_header
{
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

bool_t is_ipv4(ethernet_header_t *ethernet_header);
bool_t is_udp(ipv4_header_t *ipv4_header);
void process_ethernet_header(const char *input_buffer, ethernet_header_t *ethernet_header);
void process_ipv4_header(const char *input_buffer, ipv4_header_t *ipv4_header);
void process_udp_header(const char *input_buffer, udp_header_t *udp_header, ipv4_header_t *ipv4_header);
void print_ethernet(const ethernet_header_t *ethernet_header);
void print_ip(const ipv4_header_t *ipv4_header);
void print_udp(const udp_header_t *udp_header);

#endif // PACKET_HEADERS_H_INCLUDED