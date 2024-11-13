#ifndef BYTE_ORDER_H_INCLUDED
#define BYTE_ORDER_H_INCLUDED

#include <stdint.h>
#include "packets.h"

uint16_t custom_ntohs(uint16_t data);
uint32_t custom_ntohl(uint32_t data);
bool_t is_little_endian(void);

#endif // BYTE_ORDER_H_INCLUDED