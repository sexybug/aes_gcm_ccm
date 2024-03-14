
#include "../../test.h"
#include "../../aes/aes.h"
#include "../gcm.h"

int main()
{
    uint8_t K_str[64] = "000000000000000000000000000000000000000000000000";
    uint8_t IV_str[128] = "000000000000000000000000";
    uint8_t AAD_str[40] = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    uint8_t P_str[128] = "00000000000000000000000000000000";
    uint8_t C_str[128] = "98e7247c07f0fe411c267e4384b0f600";
    uint8_t T_str[32] = "2ff58d80033927ab8ef4d4587514f0fb";

    int K_len = 24;
    int IV_len = 12;
    int AAD_len = 0;
    int P_len = 16;
    cipher_f cipher = aes192_enc;

    uint8_t std_K[32], std_IV[64], std_AAD[20], std_P[64], std_C[64], std_T[16], enc_out[64], dec_out[64], enc_Tag[16], dec_Tag[16];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(IV_str, IV_len, std_IV);
    HexString2Hex(AAD_str, AAD_len, std_AAD);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(C_str, P_len, std_C);
    HexString2Hex(T_str, 16, std_T);

    GCM_CTX ctx;
    gcm_init(&ctx, cipher, std_K, K_len, std_IV, IV_len, 16);

    int out_len1, out_len2;
    gcm_updateAAD(&ctx, std_AAD, AAD_len, 1);
    gcm_update(&ctx, std_P, P_len, enc_out, &out_len1);

    gcm_final(&ctx, enc_out + out_len1, &out_len2, enc_Tag);
    dump_mem(enc_out, P_len);
    dump_mem(enc_Tag, 16);

    int cmpOUT = memcmp(enc_out, std_C, P_len);
    int cmpTag = memcmp(enc_Tag, std_T, 16);

    return (cmpOUT == 0) && (cmpTag == 0);
}
