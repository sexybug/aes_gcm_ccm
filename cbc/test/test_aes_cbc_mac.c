
#include "../../test.h"
#include "../../aes/aes.h"
#include "../cbc.h"

int main()
{
    uint8_t K_str[64] = "000102030405060708090a0b0c0d0e0f";
    uint8_t IV_str[32] = "00000000000000000000000000000000";
    uint8_t P_str[128] = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
    uint8_t C_str[128] = "C6A13B37878F5B826F4F8162A1C8D879B58A1064D8ACA99BD9B0405B8545F5BBE3E68258925A820DB79DD8B6532277A3";

    int K_len = 16;
    int IV_len = 16;
    int P_len = 48;

    __align4 uint8_t std_K[32], std_IV[16], std_P[64], std_C[64], enc_out[64], dec_out[64];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(IV_str, IV_len, std_IV);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(C_str, P_len, std_C);

    CBC_CTX ctx;
    cbc_init(&ctx, aes128_enc, CBC_ENCRYPT, std_K, 16, std_IV, 16);

    int out_len;
    cbc_encrypt_update(&ctx, std_P, 7, enc_out, &out_len);
    cbc_encrypt_update(&ctx, std_P + 7, P_len - 7, enc_out + out_len, &out_len);
    dump_mem(enc_out, P_len);

    int cmpOUT = memcmp(enc_out, std_C, P_len);

    CBC_CTX dec_ctx;
    cbc_init(&dec_ctx, aes128_dec, CBC_DECRYPT, std_K, 16, std_IV, 16);

    cbc_decrypt_update(&dec_ctx, std_C, 17, dec_out, &out_len);
    cbc_decrypt_update(&dec_ctx, std_C + 17, P_len - 17, dec_out + out_len, &out_len);
    dump_mem(dec_out, P_len);

    int cmpDEC = memcmp(dec_out, std_P, P_len);

    return (cmpOUT == 0);
}
