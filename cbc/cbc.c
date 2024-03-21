
#include "cbc.h"
#include <string.h>

static void XOR(uint8_t *Z, const uint8_t *X, const uint8_t *Y, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        Z[i] = X[i] ^ Y[i];
    }
}

void cbc_init(CBC_CTX *ctx, cipher_f cipher, CBC_ENC_DEC_MODE enc_dec, uint8_t *key, int key_len, uint8_t *IV, int block_len)
{
    memcpy(ctx->K, key, key_len);
    memcpy(ctx->IV, IV, block_len);
    ctx->block_len = block_len;
    ctx->total_len = 0;
    ctx->cipher = cipher;
    ctx->enc_dec = enc_dec;
}

void cbc_encrypt_update(CBC_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    *out_len = 0;
    if (in_len <= 0)
    {
        return;
    }

    int block_len = ctx->block_len;
    int buf_len = ctx->total_len % block_len;
    ctx->total_len += in_len;
    if (buf_len > 0)
    {
        if ((buf_len + in_len) < block_len)
        {
            memcpy(ctx->in_buf + buf_len, in, in_len);
            return;
        }
        else
        {
            int copy_len = block_len - buf_len;
            memcpy(ctx->in_buf + buf_len, in, copy_len);

            XOR(out, ctx->IV, ctx->in_buf, block_len);
            ctx->cipher(ctx->K, out, out);
            memcpy(ctx->IV, out, block_len);

            in += copy_len;
            in_len -= copy_len;
            out += block_len;
            *out_len += block_len;
        }
    }
    while (in_len >= block_len)
    {
        XOR(out, ctx->IV, in, block_len);
        ctx->cipher(ctx->K, out, out);
        memcpy(ctx->IV, out, block_len);

        in += block_len;
        in_len -= block_len;
        out += block_len;
        *out_len += block_len;
    }
    if (in_len > 0)
    {
        memcpy(ctx->in_buf, in, in_len);
    }
}

void cbc_decrypt_update(CBC_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    *out_len = 0;
    if (in_len == 0)
    {
        return;
    }

    int block_len = ctx->block_len;
    int buf_len = ctx->total_len % block_len;
    ctx->total_len += in_len;
    if (buf_len > 0)
    {
        if ((buf_len + in_len) < block_len)
        {
            memcpy(ctx->in_buf + buf_len, in, in_len);
            return;
        }
        else
        {
            int copy_len = block_len - buf_len;
            memcpy(ctx->in_buf + buf_len, in, copy_len);

            ctx->cipher(ctx->K, ctx->in_buf, out);
            XOR(out, ctx->IV, out, block_len);
            memcpy(ctx->IV, ctx->in_buf, block_len);

            in += copy_len;
            in_len -= copy_len;
            out += block_len;
            *out_len += block_len;
        }
    }
    while (in_len >= block_len)
    {
        ctx->cipher(ctx->K, in, out);
        XOR(out, ctx->IV, out, block_len);
        memcpy(ctx->IV, in, block_len);

        in += block_len;
        in_len -= block_len;
        out += block_len;
        *out_len += block_len;
    }
    if (in_len > 0)
    {
        memcpy(ctx->in_buf, in, in_len);
    }
}

void cbc_update(CBC_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    if (ctx->enc_dec == CBC_ENCRYPT)
    {
        cbc_encrypt_update(ctx, in, in_len, out, out_len);
    }
    else
    {
        cbc_decrypt_update(ctx, in, in_len, out, out_len);
    }
}