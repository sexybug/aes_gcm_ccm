
#ifndef _CBC_H_
#define _CBC_H_

#include <stdint.h>
#include "../align.h"

typedef void (*cipher_f)(const uint8_t *key, const uint8_t *in, uint8_t *out);

typedef enum
{
    CBC_ENCRYPT = 0,
    CBC_DECRYPT = 1
} CBC_ENC_DEC_MODE;

typedef struct
{
    uint8_t K[32];
    uint8_t IV[16];
    uint8_t in_buf[16];
    int block_len;
    int total_len;
    cipher_f cipher;
    CBC_ENC_DEC_MODE enc_dec;
} __align4 CBC_CTX;

void cbc_init(CBC_CTX *ctx, cipher_f cipher, CBC_ENC_DEC_MODE enc_dec, uint8_t *key, int key_len, uint8_t *IV, int block_len);
void cbc_encrypt_update(CBC_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);
void cbc_decrypt_update(CBC_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);

/**
 * @brief CBC加密/解密
 * 支持持续输入，支持任何输入长度。
 * 注意: 输入总长度达到整分组后才会有输出。示例：分组16, update(15)->out_len=0, update(17)->out_len=32.
 *
 * @param ctx
 * @param in
 * @param in_len
 * @param out
 * @param out_len
 */
void cbc_update(CBC_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);

#endif // _CBC_H_