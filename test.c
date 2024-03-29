#include "test.h"

void dump_mem(const void *ptr, int len)
{
    for (int i = 0; i < len; ++i)
    {
        if (i % 16 == 0 && i != 0)
        {
            printf(" ");
        }
        if (i % 32 == 0 && i != 0)
            printf("\n");
        printf("%02x", *((uint8_t *)ptr + i));
        // printf("%02x ", *((uint8_t *)ptr + i));
    }
    printf("\n");
}

int HexChar2Int(char c)
{
    if (c >= '0' && c <= '9')
    {
        return (c - '0');
    }
    else if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    else if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    else
    {
        return -1;
    }
}

void HexString2Hex(const char *str, int len, uint8_t *out)
{
    for (int i = 0; i < len; i++)
    {
        out[i] = (HexChar2Int(str[i * 2]) << 4) | HexChar2Int(str[i * 2 + 1]);
    }
}