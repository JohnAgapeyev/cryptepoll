/*
 * HEADER FILE: crypto.h - The main cryptography code
 *
 * PROGRAM: 7005-asn4
 *
 * DATE: Dec. 2, 2017
 *
 * FUNCTIONS:
 * void initCrypto(void);
 * void cleanupCrypto(void);
 * void fillRandom(unsigned char *buf, size_t n);
 * EVP_PKEY *generateECKey(void);
 * unsigned char *generateHMAC_PKEY(const unsigned char *mesg, size_t mlen, size_t *hmaclen, EVP_PKEY *key);
 * unsigned char *generateHMAC_Buffer(const unsigned char *mesg, size_t mlen, size_t *hmaclen, unsigned char *key, size_t keyLen);
 * bool verifyHMAC_PKEY(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, EVP_PKEY *key);
 * bool verifyHMAC_Buffer(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, unsigned char *key, size_t keyLen);
 * size_t encrypt(const unsigned char *plaintext, size_t plaintextlen, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext);
 * size_t decrypt(const unsigned char *ciphertext, size_t ciphertextlen, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);
 * unsigned char *getPublicKey(EVP_PKEY *pkey, size_t *keyLen);
 * EVP_PKEY *setPublicKey(const unsigned char *newPublic, size_t len);
 * unsigned char *getSharedSecret(EVP_PKEY *keypair, EVP_PKEY *clientPublicKey);
 * EVP_PKEY *allocateKeyPair(void);
 *
 * DESIGNER: John Agapeyev
 *
 * PROGRAMMER: John Agapeyev
 */
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
#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdbool.h>

#define libcrypto_error() \
    do {\
        fprintf(stderr, "Libcrypto error %s at %s, line %d in function %s\n", ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, __func__); \
        exit(EXIT_FAILURE);\
    } while(0)

#define checkCryptoAPICall(pred) \
    do {\
        if ((pred) != 1) {\
            libcrypto_error();\
        }\
    } while(0)

#define nullCheckCryptoAPICall(pred) \
    do {\
        if ((pred) == NULL) {\
            libcrypto_error();\
        }\
    } while(0)

#define SYMMETRIC_KEY_SIZE 32
#define IV_SIZE 16
#define BLOCK_SIZE 16
#define TAG_SIZE 16
#define HASH_SIZE 32

void initCrypto(void);
void cleanupCrypto(void);
void fillRandom(unsigned char *buf, size_t n);
EVP_PKEY *generateECKey(void);
unsigned char *generateHMAC_PKEY(const unsigned char *mesg, size_t mlen, size_t *hmaclen, EVP_PKEY *key);
unsigned char *generateHMAC_Buffer(const unsigned char *mesg, size_t mlen, size_t *hmaclen, unsigned char *key, size_t keyLen);
bool verifyHMAC_PKEY(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, EVP_PKEY *key);
bool verifyHMAC_Buffer(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, unsigned char *key, size_t keyLen);
size_t encrypt(const unsigned char *plaintext, size_t plaintextlen, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext);
size_t decrypt(const unsigned char *ciphertext, size_t ciphertextlen, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);
unsigned char *getPublicKey(EVP_PKEY *pkey, size_t *keyLen);
EVP_PKEY *setPublicKey(const unsigned char *newPublic, size_t len);
unsigned char *getSharedSecret(EVP_PKEY *keypair, EVP_PKEY *clientPublicKey);
EVP_PKEY *allocateKeyPair(void);

size_t encrypt_aead(const unsigned char *plaintext, size_t plain_len, const unsigned char *aad, const size_t aad_len, const unsigned char *key,
        const unsigned char *iv, unsigned char *ciphertext, unsigned char *tag);
ssize_t decrypt_aead(const unsigned char *ciphertext, size_t cipher_len, const unsigned char *aad, const size_t aad_len, const unsigned char *key,
        const unsigned char *iv, const unsigned char *tag, unsigned char *plaintext);

#endif
