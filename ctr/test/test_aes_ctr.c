
#include "../../test.h"
#include "../../aes/aes.h"
#include "../ctr.h"

int main()
{
    uint8_t K_str[64] = "000102030405060708090a0b0c0d0e0f";
    uint8_t IV_str[32] = "000102030405060708090a0b0c0d0e0f";
    uint8_t P_str[128] = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f112233";
    uint8_t C_str[128] = "0A9509B6456BF642F9CA9E53CA5EE4550262EE97621D749192D3F70447A901D31A2C96B01519A3FFB5CBC246C024E2485C2998";

    int K_len = 16;
    int IV_len = 16;
    int P_len = 51;

    __align4 uint8_t std_K[32], std_IV[16], std_P[64], std_C[64], enc_out[64], dec_out[64];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(IV_str, IV_len, std_IV);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(C_str, P_len, std_C);

    CTR_CTX ctx;
    ctr_init(&ctx, aes128_enc, std_K, 16, std_IV, 16);

    int out_len1, out_len2;
    ctr_update(&ctx, std_P, 7, enc_out, &out_len1);
    ctr_update(&ctx, std_P + 7, P_len - 7, enc_out + out_len1, &out_len2);
    ctr_final(&ctx, enc_out + out_len1 + out_len2, &out_len2);
    dump_mem(enc_out, P_len);

    int cmpOUT = memcmp(enc_out, std_C, P_len);

    return (cmpOUT == 0);
}
