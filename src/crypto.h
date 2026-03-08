#ifndef OPENUF_CRYPTO_H
#define OPENUF_CRYPTO_H

#include <stddef.h>

/*
 * AES-128-CBC helpers using mbedTLS.
 *
 * All keys and IVs are passed as 32-char hex strings (16 bytes).
 * All in/out buffers are raw binary.
 */

/* Generate random bytes, return as hex string.
 * hex_out must be at least nbytes*2+1 bytes. */
int  crypto_random_hex(unsigned char *hex_out, int nbytes);

/* AES-128-CBC encrypt.
 * out must be >= in_len + 16 (PKCS#7 padded to block boundary).
 * Returns ciphertext length, or -1 on error. */
int  crypto_encrypt(const char *key_hex, const char *iv_hex,
                    const unsigned char *in, size_t in_len,
                    unsigned char *out);

/* AES-128-CBC decrypt.
 * out must be >= in_len bytes.
 * Returns plaintext length (PKCS#7 unpadded), or -1 on error. */
int  crypto_decrypt(const char *key_hex, const char *iv_hex,
                    const unsigned char *in, size_t in_len,
                    unsigned char *out);

/* Hex <-> binary conversions */
void crypto_hex2bin(const char *hex, unsigned char *bin, size_t bin_len);
void crypto_bin2hex(const unsigned char *bin, size_t bin_len, char *hex_out);

#endif /* OPENUF_CRYPTO_H */
