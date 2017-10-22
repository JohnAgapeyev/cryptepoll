/*
 *Copyright (C) 2017 John Agapeyev
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation, either version 3 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License
 *along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *cryptepoll is licensed under the GNU General Public License version 3
 *with the addition of the following special exception:
 *
 ***
 In addition, as a special exception, the copyright holders give
 permission to link the code of portions of this program with the
 OpenSSL library under certain conditions as described in each
 individual source file, and distribute linked combinations
 including the two.
 You must obey the GNU General Public License in all respects
 for all of the code used other than OpenSSL.  If you modify
 file(s) with this exception, you may extend this exception to your
 version of the file(s), but you are not obligated to do so.  If you
 do not wish to do so, delete this exception statement from your
 version.  If you delete this exception statement from all source
 files in the program, then also delete it here.
 ***
 *
 */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#include "crypto.h"
#include "macro.h"

void initCrypto(void) {
    // Load the human readable error strings for libcrypto
    ERR_load_crypto_strings();

    // Load all digest and cipher algorithms
    OpenSSL_add_all_algorithms();

    // Load config file, and other important initialisation
    if (CONF_modules_load(NULL, NULL, 0) != 1) {
        fatal_error("OpenSSL modules load");
    }
}

void cleanupCrypto(void) {
    //Cleanup config file
    CONF_modules_unload(1);

    // Removes all digests and ciphers
    EVP_cleanup();

    // if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations
    CRYPTO_cleanup_all_ex_data();

    // Remove error strings
    ERR_free_strings();
}

void fillRandom(unsigned char *buf, size_t n) {
    checkCryptoAPICall(RAND_bytes(buf, n));
}

void SecureFree(void *addr, size_t n) {
    OPENSSL_clear_free(addr, n);
}

EVP_PKEY *generateSigningKey(void) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        libcrypto_error();
    }

    checkCryptoAPICall(EVP_PKEY_paramgen_init(pctx));

    int curveNID;
    if ((curveNID = OBJ_sn2nid(SN_secp521r1)) == NID_undef) {
        libcrypto_error();
    }

    checkCryptoAPICall(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curveNID));

    EVP_PKEY *params = EVP_PKEY_new();
    if (params == NULL) {
        libcrypto_error();
    }

    checkCryptoAPICall(EVP_PKEY_paramgen(pctx, &params));

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    if (kctx == NULL) {
        libcrypto_error();
    }

    checkCryptoAPICall(EVP_PKEY_keygen_init(kctx) );

    EVP_PKEY *key = EVP_PKEY_new();

    checkCryptoAPICall(EVP_PKEY_keygen(kctx, &key));

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);

    return key;
}

void generateHMAC(const unsigned char *mesg, size_t mlen, unsigned char **hmac, size_t *hmaclen, EVP_PKEY *key) {
    if (!mesg || !mlen || !hmac || !key) {
        fprintf(stderr, "Tried to hmac with invalid values.\nMesg: %p\nmlen: %zu\nHMAC: %p\nKey: %p\n", (void *) mesg, mlen, (void *) hmac, (void *) key);
        exit(EXIT_FAILURE);
    }
    if (*hmac) {
        OPENSSL_free(*hmac);
    }
    *hmac = NULL;
    *hmaclen = 0;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL) {
        libcrypto_error();
    }

    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
        libcrypto_error();
    }

    checkCryptoAPICall(EVP_DigestInit_ex(mdctx, md, NULL));

    checkCryptoAPICall(EVP_DigestSignInit(mdctx, NULL, md, NULL, key));

    checkCryptoAPICall(EVP_DigestSignUpdate(mdctx, mesg, mlen));

    size_t requiredLen;
    checkCryptoAPICall(EVP_DigestSignFinal(mdctx, NULL, &requiredLen));

    if (requiredLen <= 0) {
        fprintf(stderr, "Required HMAC buffer length is not greater than zero\n");
        exit(EXIT_FAILURE);
    }

    *hmac = OPENSSL_malloc(requiredLen);
    if (*hmac == NULL) {
        libcrypto_error();
    }
    *hmaclen = requiredLen;

    checkCryptoAPICall(EVP_DigestSignFinal(mdctx, *hmac, hmaclen));

    if (requiredLen < *hmaclen) {
        fprintf(stderr, "Outputted HMAC length is greater than required length for HMAC\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_destroy(mdctx);
}

bool verifyHMAC(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, EVP_PKEY *key) {
    if (!mesg || !mlen || !hmac || !key) {
        fprintf(stderr, "Tried to validate hmac with invalid values.\nMesg: %p\nmlen: %zu\nHMAC: %p\nKey: %p\n", (void *) mesg, mlen, (void *) hmac, (void *) key);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL) {
        libcrypto_error();
    }

    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
        libcrypto_error();
    }

    checkCryptoAPICall(EVP_DigestInit_ex(mdctx, md, NULL));

    checkCryptoAPICall(EVP_DigestSignInit(mdctx, NULL, md, NULL, key));

    checkCryptoAPICall(EVP_DigestSignUpdate(mdctx, mesg, mlen));

    size_t requiredLen;
    checkCryptoAPICall(EVP_DigestSignFinal(mdctx, NULL, &requiredLen));

    if (requiredLen <= 0) {
        fprintf(stderr, "Required HMAC buffer length is not greater than zero\n");
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[requiredLen];
    size_t bufsize = requiredLen;

    checkCryptoAPICall(EVP_DigestSignFinal(mdctx, buffer, &bufsize));

    if (bufsize <= 0) {
        fprintf(stderr, "Generated HMAC buffer length is not greater than zero\n");
        exit(EXIT_FAILURE);
    }

    if (requiredLen < bufsize) {
        fprintf(stderr, "Outputted HMAC length is greater than required length for HMAC\n");
        exit(EXIT_FAILURE);
    }

    const size_t len = (hmaclen < bufsize) ? hmaclen : bufsize;
    bool result = CRYPTO_memcmp(hmac, buffer, len);

    EVP_MD_CTX_destroy(mdctx);

    return result;
}

size_t encrypt(const unsigned char *plaintext, size_t plaintextlen, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        libcrypto_error();
    }

    checkCryptoAPICall(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));

    int len;

    checkCryptoAPICall(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintextlen));

    int ciphertextlen = len;

    checkCryptoAPICall(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));

    ciphertextlen += len;

    EVP_CIPHER_CTX_free(ctx);

    assert(ciphertextlen >= 0);

    return ciphertextlen;
}

size_t decrypt(const unsigned char *ciphertext, size_t ciphertextlen, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        libcrypto_error();
    }

    checkCryptoAPICall(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));

    int len;

    checkCryptoAPICall(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextlen));

    int plaintextlen = len;

    checkCryptoAPICall(EVP_DecryptFinal_ex(ctx, plaintext + len, &len));

    plaintextlen += len;

    EVP_CIPHER_CTX_free(ctx);

    assert(plaintextlen >= 0);

    return plaintextlen;
}

