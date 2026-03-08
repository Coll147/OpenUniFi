/*
 * openuf - crypto.c
 * AES-128-CBC via mbedTLS + utilidades hex/random.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mbedtls/aes.h>
#include <mbedtls/pkcs5.h>
#include "crypto.h"
#include "debug.h"

/* ─── Hex helpers ────────────────────────────────────────────────── */
void crypto_hex2bin(const char *hex, unsigned char *bin, int bin_len)
{
    DLOG("crypto: hex2bin len=%d hex=%.16s...", bin_len, hex);
    for (int i = 0; i < bin_len; i++) {
        unsigned int v = 0;
        sscanf(hex + i*2, "%02x", &v);
        bin[i] = (unsigned char)v;
    }
}

void crypto_bin2hex(const unsigned char *bin, int bin_len, char *hex_out)
{
    for (int i = 0; i < bin_len; i++)
        sprintf(hex_out + i*2, "%02x", bin[i]);
    hex_out[bin_len*2] = '\0';
    DLOG("crypto: bin2hex len=%d → %s", bin_len, hex_out);
}

int crypto_random_hex(unsigned char *hex_out, int byte_count)
{
    /* Semilla simple (suficiente para IV — no se necesita CSPRNG) */
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }

    for (int i = 0; i < byte_count; i++)
        sprintf((char*)hex_out + i*2, "%02x", rand() & 0xff);
    hex_out[byte_count*2] = '\0';
    DLOG("crypto: random IV generado: %s", hex_out);
    return 0;
}

/* ─── PKCS#7 padding helpers ─────────────────────────────────────── */
static int pkcs7_pad(unsigned char *buf, int data_len, int block_sz)
{
    int pad = block_sz - (data_len % block_sz);
    DLOG("crypto: PKCS7 pad — data_len=%d pad=%d total=%d", data_len, pad, data_len+pad);
    for (int i = 0; i < pad; i++) buf[data_len + i] = (unsigned char)pad;
    return data_len + pad;
}

static int pkcs7_unpad(unsigned char *buf, int data_len)
{
    if (data_len <= 0) return 0;
    int pad = buf[data_len - 1];
    if (pad < 1 || pad > 16) {
        DLOG("crypto: PKCS7 unpad INVALIDO — ultimo byte=%d", pad);
        return data_len;
    }
    DLOG("crypto: PKCS7 unpad — pad=%d plaintext_len=%d", pad, data_len - pad);
    return data_len - pad;
}

/* ─── AES-128-CBC cifrado ────────────────────────────────────────── */
int crypto_encrypt(const char *key_hex, const char *iv_hex,
                   const unsigned char *plain, int plain_len,
                   unsigned char *cipher_out)
{
    DLOG("crypto: encrypt — plain_len=%d key=%.8s... iv=%.8s...",
         plain_len, key_hex, iv_hex);

    unsigned char key[16], iv[16];
    crypto_hex2bin(key_hex, key, 16);
    crypto_hex2bin(iv_hex,  iv,  16);

    /* Copiar y padeamos en buffer temporal */
    unsigned char *buf = malloc(plain_len + 32);
    if (!buf) { DLOG("crypto: encrypt OOM"); return -1; }
    memcpy(buf, plain, plain_len);
    int padded_len = pkcs7_pad(buf, plain_len, 16);

    DLOG("crypto: mbedtls AES-128-CBC encrypt — padded_len=%d", padded_len);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key, 128) != 0) {
        DLOG("crypto: mbedtls_aes_setkey_enc FALLO");
        mbedtls_aes_free(&ctx); free(buf); return -1;
    }

    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);
    int rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT,
                                   padded_len, iv_copy, buf, cipher_out);
    mbedtls_aes_free(&ctx);
    free(buf);

    if (rc != 0) {
        DLOG("crypto: mbedtls_aes_crypt_cbc FALLO rc=%d", rc);
        return -1;
    }
    DLOG("crypto: encrypt OK → cipher_len=%d", padded_len);
    DLOG_HEX("cipher (primeros bytes)", cipher_out, padded_len < 32 ? padded_len : 32);
    return padded_len;
}

/* ─── AES-128-CBC descifrado ─────────────────────────────────────── */
int crypto_decrypt(const char *key_hex, const char *iv_hex,
                   const unsigned char *cipher, int cipher_len,
                   unsigned char *plain_out)
{
    DLOG("crypto: decrypt — cipher_len=%d key=%.8s... iv=%.8s...",
         cipher_len, key_hex, iv_hex);

    if (cipher_len % 16 != 0) {
        DLOG("crypto: cipher_len=%d no es multiplo de 16 — ERROR", cipher_len);
        return -1;
    }

    unsigned char key[16], iv[16];
    crypto_hex2bin(key_hex, key, 16);
    crypto_hex2bin(iv_hex,  iv,  16);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_dec(&ctx, key, 128) != 0) {
        DLOG("crypto: mbedtls_aes_setkey_dec FALLO");
        mbedtls_aes_free(&ctx); return -1;
    }

    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);
    int rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT,
                                   cipher_len, iv_copy, cipher, plain_out);
    mbedtls_aes_free(&ctx);

    if (rc != 0) {
        DLOG("crypto: mbedtls_aes_crypt_cbc FALLO rc=%d", rc);
        return -1;
    }

    int plain_len = pkcs7_unpad(plain_out, cipher_len);
    plain_out[plain_len] = '\0';
    DLOG("crypto: decrypt OK — plain_len=%d", plain_len);
    return plain_len;
}
