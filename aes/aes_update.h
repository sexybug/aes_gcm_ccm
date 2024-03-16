
#ifndef _AES_UPDATE_H_
#define _AES_UPDATE_H_

#include <stdint.h>
#include <stdlib.h>
#include "../align.h"
#include "aes.h"

typedef enum
{
    AES_ENCRYPT = 0,
    AES_DECRYPT = 1
} AES_ENC_DEC_MODE;

typedef enum
{
    AES128_KEY_LEN = 16,
    AES192_KEY_LEN = 24,
    AES256_KEY_LEN = 32
} AES_KEY_LEN;

typedef int (*aes_set_encrypt_decrypt_key_f)(AES_KEY *key, const uint8_t *raw_key, size_t raw_key_len);
typedef void (*aes_encrypt_decrypt_f)(const AES_KEY *key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);

typedef struct
{
    AES_ENC_DEC_MODE enc_dec_mode;
    uint8_t *key;
    AES_KEY_LEN key_len;
    AES_KEY round_key;
    aes_set_encrypt_decrypt_key_f set_key;
    aes_encrypt_decrypt_f enc_dec;
} __align4 AES_CTX;

void aes_init(AES_CTX *ctx);
void aes_update(AES_CTX *ctx, const uint8_t in[16], uint8_t out[16]);
void aes_final(AES_CTX *ctx);

#endif // _AES_UPDATE_H_