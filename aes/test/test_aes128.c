
#include <stdio.h>
#include "../../test.h"
#include "../aes.h"

int main(int argc, char **argv)
{
    uint32_t a=0x012345678;
    uint32_t *b=&a;
    uint8_t p_str[32] = "00112233445566778899aabbccddeeff";
    uint8_t k_str[32] = "000102030405060708090a0b0c0d0e0f";
    uint8_t c_str[32] = "69c4e0d86a7b0430d8cdb78070b4c55a";
    uint8_t p[16];
    HexString2Hex(p_str, 16, p);
    uint8_t key[16];
    HexString2Hex(k_str, 16, key);
    uint8_t c[16];

    AES_KEY aes_key;
    aes_set_encrypt_key(&aes_key, key, 16);
    aes_encrypt(&aes_key, p, c);

    dump_mem(c, 16);

    uint8_t p_out[16];
    aes_set_decrypt_key(&aes_key, key, 16);
    aes_decrypt(&aes_key, c, p_out);
    dump_mem(p_out, 16);
    return 0;
}