#include "byte-order.h"

uint16_t custom_ntohs(uint16_t data)
{
    /*If Little Endian Shifting MSB with LSB*/
    return ((data << 8) & 0xFF00) | ((data >> 8) & 0x00FF);
}

uint32_t custom_ntohl(uint32_t data)
{
    /* If Little Endian, shifting bytes to swap MSB with LSB and middle bytes */
    return ((data << 24) & 0xFF000000) |
           ((data << 8)  & 0x00FF0000) |
           ((data >> 8)  & 0x0000FF00) |
           ((data >> 24) & 0x000000FF);
}

bool_t is_little_endian()
{
    union
    {
        uint16_t value;
        uint8_t char_value[2];
    } checker = {0x0102};

    /*If little, Endian LSB will placed first, If Big Endian, MSB in the first*/
    if (checker.char_value[0] == 0x02)
    {
        return true;
    }

    return false;
}