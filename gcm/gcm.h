/**
 * @file gcm.h
 * @author your name (you@domain.com)
 * @brief an implementation of NIST Special Publication 800-38D November, 2007 (Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC)
 * @version 0.1
 * @date 2024-03-13
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef _GCM_H
#define _GCM_H

#include <stdint.h>
#include <stdbool.h>

typedef void (*cipher_f)(const uint8_t *key, const uint8_t *in, uint8_t *out);

typedef struct
{
    uint8_t H[16];
    uint8_t buf[16];
    uint8_t Y[16];
    int total_len;
} GHASH_CTX;

typedef struct
{
    uint8_t K[32];
    uint8_t CB[16];
    uint8_t buf[16];
    int total_len;
    cipher_f cipher;
    int K_len;
} GCTR_CTX;

typedef struct
{
    uint8_t J0[16];
    GHASH_CTX ghash;
    GCTR_CTX gctr;
    int tag_len;
    int AAD_len;
} GCM_CTX;

void gcm_init(GCM_CTX *ctx, cipher_f cipher, const uint8_t *K, int K_len, const uint8_t *IV, int IV_len, int TAG_len);
void gcm_updateAAD(GCM_CTX *ctx, const uint8_t *AAD, int AAD_len, bool is_last);
void gcm_update(GCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);
void gcm_final(GCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *Tag);

#endif //_GCM_H