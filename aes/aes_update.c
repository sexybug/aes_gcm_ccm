
#include "aes_update.h"

void aes_init(AES_CTX *ctx)
{
    //initialize function pointers
    if(ctx->enc_dec_mode == AES_ENCRYPT)
    {
        ctx->set_key=aes_set_encrypt_key;
        ctx->enc_dec=aes_encrypt;
    }
    else
    {
        ctx->set_key=aes_set_decrypt_key;
        ctx->enc_dec=aes_decrypt;
    }
    //initialize parameters
    ctx->set_key(&(ctx->round_key), ctx->key, ctx->key_len);
}

void aes_update(AES_CTX *ctx, const uint8_t in[16], uint8_t out[16])
{
    ctx->enc_dec(&(ctx->round_key), in, out);
}

void aes_final(AES_CTX *ctx)
{
}
