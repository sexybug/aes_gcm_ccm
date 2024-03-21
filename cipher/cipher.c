
#include "cipher.h"

void cipher_init(CIPHER_CTX *ctx)
{
    
}

int main(int argc, char **argv)
{
    uint8_t p_str[32] = "00112233445566778899aabbccddeeff";
    uint8_t k_str[32] = "000102030405060708090a0b0c0d0e0f";
    uint8_t c_str[32] = "69c4e0d86a7b0430d8cdb78070b4c55a";
    uint8_t p[16];
    HexString2Hex(p_str, 16, p);
    uint8_t key[16];
    HexString2Hex(k_str, 16, key);
    uint8_t c[16];

    AES_CTX aes;
    cipher_init_f cipher_init = (cipher_init_f)aes_init;
    cipher_update_f cipher_update = (cipher_update_f)aes_update;

    aes.key = key;
    aes.key_len = 16;
    aes.enc_dec=AES_ENCRYPT;

    cipher_init(&aes);

    cipher_update(&aes, p, c);
    dump_mem(c, 16);
    cipher_update(&aes, p, c);
    dump_mem(c, 16);
    return 0;
}