#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "crypto.h"
#include "debug.h"

#define DBG_TAG "crypto"

void crypto_hex2bin(const char *hex, unsigned char *bin, size_t len) {
    for (size_t i = 0; i < len; i++) { unsigned int b=0; sscanf(hex+i*2,"%02x",&b); bin[i]=(unsigned char)b; }
}
void crypto_bin2hex(const unsigned char *bin, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) sprintf(out+i*2,"%02x",bin[i]); out[len*2]='\0';
}

int crypto_random_hex(unsigned char *hex_out, int nbytes) {
    LOG_TRACE("generando IV: %d bytes via mbedTLS CTR_DRBG...", nbytes);
    if (nbytes > 64) { LOG_ERR("nbytes=%d > 64", nbytes); return -1; }
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char buf[64];
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char*)"openuf", 6);
    if (ret != 0) { LOG_ERR("ctr_drbg_seed: -0x%04x", (unsigned)-ret); goto out; }
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, buf, nbytes);
    if (ret != 0) { LOG_ERR("ctr_drbg_random: -0x%04x", (unsigned)-ret); goto out; }
    crypto_bin2hex(buf, nbytes, (char*)hex_out);
    LOG_TRACE("IV = %.*s", nbytes*2, (char*)hex_out);
    ret = 0;
out:
    mbedtls_ctr_drbg_free(&ctr_drbg); mbedtls_entropy_free(&entropy);
    return ret;
}

int crypto_encrypt(const char *key_hex, const char *iv_hex,
                   const unsigned char *in, size_t in_len, unsigned char *out) {
    LOG_TRACE("AES-128-CBC cifrado: %zu bytes  clave=%.8s...  IV=%.8s...",
              in_len, key_hex, iv_hex);
    unsigned char key[16], iv[16];
    crypto_hex2bin(key_hex,key,16); crypto_hex2bin(iv_hex,iv,16);
    size_t pad=16-(in_len%16), padded=in_len+pad;
    LOG_TRACE("  PKCS#7: entrada=%zu relleno=%zu salida=%zu", in_len, pad, padded);
    unsigned char *tmp = malloc(padded);
    if (!tmp) { LOG_ERR("OOM malloc(%zu)", padded); return -1; }
    memcpy(tmp,in,in_len); memset(tmp+in_len,(unsigned char)pad,pad);
    mbedtls_aes_context ctx; mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx,key,128)!=0) {
        LOG_ERR("aes_setkey_enc falló"); mbedtls_aes_free(&ctx); free(tmp); return -1;
    }
    unsigned char iv_copy[16]; memcpy(iv_copy,iv,16);
    int ret = mbedtls_aes_crypt_cbc(&ctx,MBEDTLS_AES_ENCRYPT,padded,iv_copy,tmp,out);
    mbedtls_aes_free(&ctx); free(tmp);
    if (ret!=0) { LOG_ERR("aes_crypt_cbc(enc): -0x%04x", (unsigned)-ret); return -1; }
    LOG_DBG("cifrado OK: %zu → %zu bytes (pad=%zu)", in_len, padded, pad);
    DBG_HEX("primeros 32 bytes cifrados", out, padded<32?padded:32);
    return (int)padded;
}

int crypto_decrypt(const char *key_hex, const char *iv_hex,
                   const unsigned char *in, size_t in_len, unsigned char *out) {
    LOG_TRACE("AES-128-CBC descifrado: %zu bytes  IV=%.8s...", in_len, iv_hex);
    if (in_len==0||in_len%16!=0) {
        LOG_ERR("longitud inválida: %zu (debe ser múltiplo de 16)", in_len);
        return -1;
    }
    unsigned char key[16], iv[16];
    crypto_hex2bin(key_hex,key,16); crypto_hex2bin(iv_hex,iv,16);
    unsigned char iv_copy[16]; memcpy(iv_copy,iv,16);
    mbedtls_aes_context ctx; mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_dec(&ctx,key,128)!=0) {
        LOG_ERR("aes_setkey_dec falló"); mbedtls_aes_free(&ctx); return -1;
    }
    int ret = mbedtls_aes_crypt_cbc(&ctx,MBEDTLS_AES_DECRYPT,in_len,iv_copy,in,out);
    mbedtls_aes_free(&ctx);
    if (ret!=0) { LOG_ERR("aes_crypt_cbc(dec): -0x%04x", (unsigned)-ret); return -1; }
    unsigned char pad = out[in_len-1];
    if (pad==0||pad>16) { LOG_ERR("PKCS#7 inválido: 0x%02x (clave incorrecta?)",pad); return -1; }
    int plain = (int)(in_len-pad);
    LOG_DBG("descifrado OK: %zu → %d bytes (pad=%u)", in_len, plain, pad);
    LOG_TRACE("JSON inicio: %.*s", plain<100?plain:100, out);
    return plain;
}
