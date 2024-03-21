
#include "../../test.h"
#include "../../aes/aes.h"
#include "../cbc_mac.h"

int main()
{
    uint8_t K_str[64] = "000102030405060708090a0b0c0d0e0f";
    uint8_t P_str[128] = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
    uint8_t MAC_str[128] = "82dd8e072117cf327887eaf144353bfc";

    int K_len = 16;
    int P_len = 48;

    __align4 uint8_t std_K[32], std_IV[16], std_P[64], std_MAC[64], out[64];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(MAC_str, 16, std_MAC);

    CBC_MAC_CTX ctx;
    cbc_mac_init(&ctx, aes128_enc, std_K, 16, 16);

    int out_len;
    cbc_mac_update(&ctx, std_P, 7);
    cbc_mac_update(&ctx, std_P + 7, 29);
    cbc_mac_update(&ctx, std_P + 7 + 29, P_len - 7 - 29);
    cbc_mac_final(&ctx, out);
    dump_mem(out, 16);

    int cmpOUT = memcmp(out, std_MAC, 16);

    return (cmpOUT == 0);
}
