#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "crypto.h"

/* ─── Hex / binary helpers ──────────────────────────────────────── */
void crypto_hex2bin(const char *hex, unsigned char *bin, size_t bin_len)
{
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int b = 0;
        sscanf(hex + i * 2, "%02x", &b);
        bin[i] = (unsigned char)b;
    }
}

void crypto_bin2hex(const unsigned char *bin, size_t bin_len, char *hex_out)
{
    for (size_t i = 0; i < bin_len; i++)
        sprintf(hex_out + i * 2, "%02x", bin[i]);
    hex_out[bin_len * 2] = '\0';
}

/* ─── Random hex ────────────────────────────────────────────────── */
int crypto_random_hex(unsigned char *hex_out, int nbytes)
{
    mbedtls_entropy_context   entropy;
    mbedtls_ctr_drbg_context  ctr_drbg;
    unsigned char buf[64];
    int ret;

    if (nbytes > 64) return -1;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 (const unsigned char *)"openuf", 6);
    if (ret != 0) goto out;

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, buf, nbytes);
    if (ret != 0) goto out;

    crypto_bin2hex(buf, nbytes, (char *)hex_out);
    ret = 0;
out:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

/* ─── AES-128-CBC encrypt (PKCS#7 padding) ──────────────────────── */
int crypto_encrypt(const char *key_hex, const char *iv_hex,
                   const unsigned char *in, size_t in_len,
                   unsigned char *out)
{
    unsigned char key[16], iv[16];
    crypto_hex2bin(key_hex, key, 16);
    crypto_hex2bin(iv_hex,  iv,  16);

    /* PKCS#7: pad to next 16-byte block */
    size_t pad    = 16 - (in_len % 16);
    size_t padded = in_len + pad;

    unsigned char *tmp = malloc(padded);
    if (!tmp) return -1;
    memcpy(tmp, in, in_len);
    memset(tmp + in_len, (unsigned char)pad, pad);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key, 128) != 0) {
        mbedtls_aes_free(&ctx); free(tmp); return -1;
    }

    /* iv is modified in place by CBC – use a copy */
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);

    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT,
                                    padded, iv_copy, tmp, out);
    mbedtls_aes_free(&ctx);
    free(tmp);
    return (ret == 0) ? (int)padded : -1;
}

/* ─── AES-128-CBC decrypt (PKCS#7 unpadding) ────────────────────── */
int crypto_decrypt(const char *key_hex, const char *iv_hex,
                   const unsigned char *in, size_t in_len,
                   unsigned char *out)
{
    if (in_len == 0 || in_len % 16 != 0) return -1;

    unsigned char key[16], iv[16];
    crypto_hex2bin(key_hex, key, 16);
    crypto_hex2bin(iv_hex,  iv,  16);

    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_dec(&ctx, key, 128) != 0) {
        mbedtls_aes_free(&ctx); return -1;
    }

    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT,
                                    in_len, iv_copy, in, out);
    mbedtls_aes_free(&ctx);
    if (ret != 0) return -1;

    /* Remove PKCS#7 padding */
    unsigned char pad = out[in_len - 1];
    if (pad == 0 || pad > 16) return -1;
    return (int)(in_len - pad);
}
