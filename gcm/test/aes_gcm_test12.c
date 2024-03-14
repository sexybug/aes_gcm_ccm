
#include "../../test.h"
#include "../../aes/aes.h"
#include "../gcm.h"

int main()
{
    uint8_t K_str[64] = "feffe9928665731c6d6a8f9467308308\
feffe9928665731c";
    uint8_t IV_str[128] = "9313225df88406e555909c5aff5269aa\
6a7a9538534f7da1e4c303d2a318a728\
c3c0c95156809539fcf0e2429a6b5254\
16aedbf5a0de6a57a637b39b";
    uint8_t AAD_str[40] = "feedfacedeadbeeffeedfacedeadbeef\
abaddad2";
    uint8_t P_str[128] = "d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b39";
    uint8_t C_str[128] = "d27e88681ce3243c4830165a8fdcf9ff\
1de9a1d8e6b447ef6ef7b79828666e45\
81e79012af34ddd9e2f037589b292db3\
e67c036745fa22e7e9b7373b";
    uint8_t T_str[32] = "dcf566ff291c25bbb8568fc3d376a6d9";

    int K_len = 24;
    int IV_len = 60;
    int AAD_len = 20;
    int P_len = 60;
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
