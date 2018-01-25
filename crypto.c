/*
 * SOURCE FILE: crypto.c - Implementation of functions declared in crypto.h
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
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "crypto.h"
#include "macro.h"

/*
 * FUNCTION: initCrypto
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void initCrypto(void)
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Initializes libcrypto library
 */
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

/*
 * FUNCTION: cleanupCrypto
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void cleanupCrypto(void)
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Cleans up libcrypto state.
 */
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

/*
 * FUNCTION: fillRandom
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void fillRandom(unsigned char *buf, size_t n)
 *
 * PARAMETERS:
 * unsigned char *buf - The buffer to write to
 * size_t n - The number of bytes to write
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Wrapper around libcrypto CSPRNG call.
 */
void fillRandom(unsigned char *buf, size_t n) {
    checkCryptoAPICall(RAND_bytes(buf, n));
}

/*
 * FUNCTION: generateECKey
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * EVP_PKEY *generateECKey(void);
 *
 * RETURNS:
 * EVP_PKEY * - The generated key.
 *
 * NOTES:
 * Generates a new NIST 521-bit elliptic curve keypair
 */
EVP_PKEY *generateECKey(void) {
    EVP_PKEY_CTX *pctx;
    nullCheckCryptoAPICall(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));

    checkCryptoAPICall(EVP_PKEY_paramgen_init(pctx));

    checkCryptoAPICall(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1));

    EVP_PKEY *params = allocateKeyPair();

    checkCryptoAPICall(EVP_PKEY_paramgen(pctx, &params));

    EVP_PKEY_CTX *kctx;
    nullCheckCryptoAPICall(kctx = EVP_PKEY_CTX_new(params, NULL));

    checkCryptoAPICall(EVP_PKEY_keygen_init(kctx) );

    EVP_PKEY *key = allocateKeyPair();

    checkCryptoAPICall(EVP_PKEY_keygen(kctx, &key));

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);

    return key;
}

/*
 * FUNCTION: generateHMAC_PKEY
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * unsigned char *generateHMAC_PKEY(const unsigned char *mesg, size_t mlen, size_t *hmaclen, EVP_PKEY *key);
 *
 * PARAMETERS:
 * const unsigned char *mesg - The mesg to generate the hmac over
 * size_t mlen - The length of the message
 * size_t *hmaclen - A pointer to a buffer to store the resulting hmac length
 * EVP_PKEY *key - The key used to generate the HMAC
 *
 * RETURNS:
 * unsigned char * - A buffer containing the hmac that was generated
 *
 * NOTES:
 * Grabs the key's public key and calls generateHMAC_Buffer with it
 */
unsigned char *generateHMAC_PKEY(const unsigned char *mesg, size_t mlen, size_t *hmaclen, EVP_PKEY *key) {
    size_t pubKeyLen = 0;
    unsigned char *pubKey = getPublicKey(key, &pubKeyLen);

    unsigned char *out = generateHMAC_Buffer(mesg, mlen, hmaclen, pubKey, pubKeyLen);

    OPENSSL_free(pubKey);

    return out;
}

/*
 * FUNCTION: generateHMAC_Buffer
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * unsigned char *generateHMAC_Buffer(const unsigned char *mesg, size_t mlen, size_t *hmaclen, unsigned char *key, size_t keyLen);
 *
 * PARAMETERS:
 * const unsigned char *mesg - The mesg to generate the hmac over
 * size_t mlen - The length of the message
 * size_t *hmaclen - A pointer to a buffer to store the resulting hmac length
 * unsigned char *key - The key to generate the HMAC with
 * size_t keyLen - The length of the provided key
 *
 * RETURNS:
 * char * - A buffer containing the generated HMAC
 *
 * NOTES:
 * HMAC algorithm is HMAC-SHA256.
 */
unsigned char *generateHMAC_Buffer(const unsigned char *mesg, size_t mlen, size_t *hmaclen, unsigned char *key, size_t keyLen) {
    if (!mesg || !mlen || !hmaclen || !key) {
        fprintf(stderr, "Tried to hmac with invalid values.\nMesg: %p\nmlen: %zu\nHMAC: %p\nKey: %p\n", (void *) mesg, mlen, (void *) hmaclen, (void *) key);
        exit(EXIT_FAILURE);
    }
    unsigned char *out;
    nullCheckCryptoAPICall(out = OPENSSL_malloc(EVP_MAX_MD_SIZE));

    unsigned char *rtn;
    nullCheckCryptoAPICall(rtn = HMAC(EVP_sha256(), key, keyLen, mesg, mlen, out, (unsigned int *) hmaclen));
    assert(rtn == out);

    return out;
}

/*
 * FUNCTION: verifyHMAC_PKEY
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * bool verifyHMAC_PKEY(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, EVP_PKEY *key);
 *
 * PARAMETERS:
 * const unsigned char *mesg - The mesg buffer to verify
 * size_t mlen - The length of the message buffer
 * const unsigned char *hmac - The HMAC to verify
 * size_t hmaclen - The length of the HMAC
 * EVP_PKEY *key - The key used to generate the HMAC
 *
 * RETURNS:
 * bool - Whether the HMAC is valid or not.
 */
bool verifyHMAC_PKEY(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, EVP_PKEY *key) {
    if (!mesg || !mlen || !hmac || !key) {
        fprintf(stderr, "Tried to validate hmac with invalid values.\nMesg: %p\nmlen: %zu\nHMAC: %p\nKey: %p\n", (void *) mesg, mlen, (void *) hmac, (void *) key);
        exit(EXIT_FAILURE);
    }

    size_t genHmacLen = 0;
    unsigned char *genHmac = generateHMAC_PKEY(mesg, mlen, &genHmacLen, key);

    const size_t len = (hmaclen < genHmacLen) ? hmaclen : genHmacLen;
    bool result = (CRYPTO_memcmp(hmac, genHmac, len) == 0);

    OPENSSL_free(genHmac);

    return result;
}

/*
 * FUNCTION: verifyHMAC_Buffer
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * bool verifyHMAC_Buffer(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, unsigned char *key, size_t keyLen);
 *
 * PARAMETERS:
 * const unsigned char *mesg - The message to verify
 * size_t mlen - The length of the messsage
 * const unsigned char *hmac - The HMAC to verify
 * size_t hmaclen - The length of the HMAC
 * unsigned char *key - A buffer containing the key used to generate the HMAC
 * size_t keyLen - The length of the key buffer
 *
 * RETURNS:
 * bool - Whether the HMAC is validated successfully.
 */
bool verifyHMAC_Buffer(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, unsigned char *key, size_t keyLen) {
    if (!mesg || !mlen || !hmac || !key) {
        fprintf(stderr, "Tried to validate hmac with invalid values.\nMesg: %p\nmlen: %zu\nHMAC: %p\nKey: %p\n", (void *) mesg, mlen, (void *) hmac, (void *) key);
        exit(EXIT_FAILURE);
    }

    size_t genHmacLen = 0;
    unsigned char *genHmac = generateHMAC_Buffer(mesg, mlen, &genHmacLen, key, keyLen);

    const size_t len = (hmaclen < genHmacLen) ? hmaclen : genHmacLen;
    bool result = (CRYPTO_memcmp(hmac, genHmac, len) == 0);

    OPENSSL_free(genHmac);

    return result;
}

/*
 * FUNCTION: encrypt
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * size_t encrypt(const unsigned char *plaintext, size_t plaintextlen, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext);
 *
 * PARAMETERS:
 * const unsigned char *plaintext - The plaintext
 * size_t plaintextlen - The length of the plaintext
 * const unsigned char *key - A buffer containing the encryption key
 * const unsigned char *iv - A buffer containing the IV
 * unsigned char *ciphertext - A buffer to write the ciphertext to
 *
 * RETURNS:
 * size_t - The size of the ciphertext
 *
 * NOTES:
 * Encrypts using AES-256-CBC.
 * Ciphertext buffer must be at least plaintextlen + 16 bytes long.
 */
size_t encrypt(const unsigned char *plaintext, size_t plaintextlen, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    nullCheckCryptoAPICall(ctx = EVP_CIPHER_CTX_new());

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

/*
 * FUNCTION: decrypt
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * size_t decrypt(const unsigned char *ciphertext, size_t ciphertextlen, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);
 *
 * PARAMETERS:
 * const unsigned char *ciphertext - The buffer containing the ciphertext
 * size_t ciphertextlen - The length of the ciphertext
 * const unsigned char *key - The key to decrypt with
 * const unsigned char *iv - The IV used in encrypting the ciphertext
 * unsigned char *plaintext - A buffer to write the plaintext to
 *
 * RETURNS:
 * size_t - The size of the plaintext
 *
 * NOTES:
 * plaintext must be at least ciphertextlen bytes big.
 */
size_t decrypt(const unsigned char *ciphertext, size_t ciphertextlen, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    nullCheckCryptoAPICall(ctx = EVP_CIPHER_CTX_new());

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

/*
 * FUNCTION: getPublicKey
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * unsigned char *getPublicKey(EVP_PKEY *pkey, size_t *keyLen);
 *
 * PARAMETERS:
 * EVP_PKEY *key - The keypair to extract the public key from
 * size_t keyLen - A pointer to a buffer to write the public key length to
 *
 * RETURNS:
 * unsigned char * - An allocate buffer containing the raw public key
 */
unsigned char *getPublicKey(EVP_PKEY *pkey, size_t *keyLen) {
    EC_KEY *eck;
    nullCheckCryptoAPICall(eck = EVP_PKEY_get1_EC_KEY(pkey));

    const EC_POINT *ecp;
    nullCheckCryptoAPICall(ecp = EC_KEY_get0_public_key(eck));

    BN_CTX *bnctx;
    nullCheckCryptoAPICall(bnctx = BN_CTX_new());

    EC_GROUP *ecg;
    nullCheckCryptoAPICall(ecg = EC_GROUP_new_by_curve_name(NID_secp521r1));

    size_t requiredLen = EC_POINT_point2oct(ecg, ecp, EC_GROUP_get_point_conversion_form(ecg), NULL, 0, bnctx);
    if (requiredLen == 0) {
        libcrypto_error();
    }

    unsigned char *rtn;
    nullCheckCryptoAPICall(rtn = OPENSSL_malloc(requiredLen));

    *keyLen = EC_POINT_point2oct(ecg, ecp, EC_GROUP_get_point_conversion_form(ecg), rtn, requiredLen, bnctx);
    if (*keyLen == 0) {
        libcrypto_error();
    }

    EC_GROUP_free(ecg);
    EC_KEY_free(eck);
    BN_CTX_free(bnctx);
    return  rtn;
}

/*
 * FUNCTION: setPublicKey
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * EVP_PKEY *setPublicKey(const unsigned char *newPublic, size_t len);
 *
 * PARAMETERS:
 * const unsigned char *newPublic - A buffer containing the new public key to use
 * size_t len - The length of the new public key
 *
 * RETURNS:
 * EVP_PKEY * - An allocated keypair that has the public key set to newPublic
 *
 * NOTES:
 * The returned EVP_PKEY struct will not have a valid private key, and using it is undefined
 */
EVP_PKEY *setPublicKey(const unsigned char *newPublic, size_t len) {
    BN_CTX *bnctx;
    nullCheckCryptoAPICall(bnctx = BN_CTX_new());

    EC_GROUP *ecg;
    nullCheckCryptoAPICall(ecg = EC_GROUP_new_by_curve_name(NID_secp521r1));

    EC_POINT *ecp;
    nullCheckCryptoAPICall(ecp = EC_POINT_new(ecg));

    checkCryptoAPICall(EC_POINT_oct2point(ecg, ecp, newPublic, len, bnctx));

    EC_KEY *eck;
    nullCheckCryptoAPICall(eck = EC_KEY_new_by_curve_name(NID_secp521r1));

    checkCryptoAPICall(EC_KEY_set_public_key(eck, ecp));

    EVP_PKEY *rtn = allocateKeyPair();
    checkCryptoAPICall(EVP_PKEY_set1_EC_KEY(rtn, eck));

    EC_KEY_free(eck);
    EC_POINT_free(ecp);
    EC_GROUP_free(ecg);
    BN_CTX_free(bnctx);

    return rtn;
}

/*
 * FUNCTION: getSharedSecret
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * unsigned char *getSharedSecret(EVP_PKEY *keypair, EVP_PKEY *clientPublicKey);
 *
 * PARAMETERS:
 * EVP_PKEY *keypair - The original keyPair to use
 * EVP_PKEY *clientPublicKey - The client's public key
 *
 * RETURNS:
 * unsigned char * - A buffer containing the shared secret
 *
 * NOTES:
 * keyPair must have a fully valid private and public key.
 * clientPublicKey need only have the public key.
 * The key pairs must be the same type of key.
 * The keys must be able to be used to derive a shared secret.
 * The shared secret is derived using ECDH.
 * The resut of ECDH is hashed using SHA-256, and returned.
 */
unsigned char *getSharedSecret(EVP_PKEY *keypair, EVP_PKEY *clientPublicKey) {
    EVP_PKEY_CTX *ctx;
    nullCheckCryptoAPICall(ctx = EVP_PKEY_CTX_new(keypair, NULL));

    unsigned char *secretKey;
    size_t keyLen;

    checkCryptoAPICall(EVP_PKEY_derive_init(ctx));

    checkCryptoAPICall(EVP_PKEY_derive_set_peer(ctx, clientPublicKey));

    checkCryptoAPICall(EVP_PKEY_derive(ctx, NULL, &keyLen));

    nullCheckCryptoAPICall(secretKey = OPENSSL_malloc(keyLen));

    checkCryptoAPICall(EVP_PKEY_derive(ctx, secretKey, &keyLen));

    EVP_MD_CTX *mdctx;
    nullCheckCryptoAPICall(mdctx = EVP_MD_CTX_create());

    checkCryptoAPICall(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));

    checkCryptoAPICall(EVP_DigestUpdate(mdctx, secretKey, keyLen));

    unsigned char *hashedSecret;
    nullCheckCryptoAPICall(hashedSecret = OPENSSL_malloc(EVP_MD_size(EVP_sha256())));

    unsigned int hashLen;
    checkCryptoAPICall(EVP_DigestFinal_ex(mdctx, hashedSecret, &hashLen));

    assert(hashLen == (unsigned int) EVP_MD_size(EVP_sha256()));

    EVP_MD_CTX_destroy(mdctx);
    OPENSSL_clear_free(secretKey, keyLen);
    EVP_PKEY_CTX_free(ctx);

    return hashedSecret;
}

/*
 * FUNCTION: allocateKeyPair
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * EVP_PKEY *allocateKeyPair(void);
 *
 * RETURNS:
 * EVP_PKEY * - The allocated key pair struct
 *
 * NOTES:
 * Simple wrapper over api allocation call
 */
EVP_PKEY *allocateKeyPair(void) {
    EVP_PKEY *out;
    nullCheckCryptoAPICall(out = EVP_PKEY_new());
    return out;
}

size_t encrypt_aead(const unsigned char *plaintext, size_t plain_len, const unsigned char *aad, const size_t aad_len, const unsigned char *key,
        const unsigned char *iv, unsigned char *ciphertext, unsigned char *tag) {

    EVP_CIPHER_CTX *ctx;
    nullCheckCryptoAPICall(ctx = EVP_CIPHER_CTX_new());

    checkCryptoAPICall(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TAG_SIZE, NULL));

    checkCryptoAPICall(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));

    int len;
    checkCryptoAPICall(EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len));

    checkCryptoAPICall(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len));

    int ciphertextlen = len;
    checkCryptoAPICall(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));

    ciphertextlen += len;

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag));

    EVP_CIPHER_CTX_free(ctx);

    assert(ciphertextlen >= 0);

    return ciphertextlen;
}

ssize_t decrypt_aead(const unsigned char *ciphertext, size_t cipher_len, const unsigned char *aad, const size_t aad_len, const unsigned char *key,
        const unsigned char *iv, const unsigned char *tag, unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx;
    nullCheckCryptoAPICall(ctx = EVP_CIPHER_CTX_new());

    checkCryptoAPICall(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TAG_SIZE, NULL));

    checkCryptoAPICall(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));

    int len;
    checkCryptoAPICall(EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len));

    checkCryptoAPICall(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len));

    int plaintextlen = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (unsigned char *) tag)) {
        libcrypto_error();
    }

    ssize_t ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    plaintextlen += len;

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        assert(plaintextlen >= 0);
        return plaintextlen;
    }
    return -1;
}
