
#ifndef _CIPHER_H_
#define _CIPHER_H_

#include "../align.h"
#include "../aes/aes_update.h"

typedef enum
{
    AES,
    SM4
} CIPHER_ALGORITHM;

typedef struct
{
    CIPHER_ALGORITHM alg;
    uint8_t *key;
    union
    {
        AES_CTX aes;
        AES_CTX sm4;
    };
} __align4 CIPHER_CTX;

typedef void (*cipher_init_f)(CIPHER_CTX *ctx);
typedef void (*cipher_update_f)(CIPHER_CTX *ctx, const uint8_t in[16], uint8_t out[16]);
typedef void (*cipher_final_f)(CIPHER_CTX *ctx);

#endif // _CIPHER_H_