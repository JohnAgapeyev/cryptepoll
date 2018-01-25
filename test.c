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
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"
#include "test.h"

static bool testEncryptDecrypt(void);
static bool testEncryptDecrypt_AAD(void);
static bool testHMAC(void);
static bool testECDH(void);
static bool testGetSetKey(void);
static void *threadRoutine(void *arg);
static bool testKeyHMAC(void);

const unsigned char *testString = (const unsigned char *) "This is a test";
const size_t testStringLen = 14;

#define THREAD_COUNT 8
#define TASK_COUNT 1000

void performTests(void) {
    initCrypto();

    assert(testEncryptDecrypt());
    assert(testHMAC());
    assert(testECDH());
    assert(testGetSetKey());
    assert(testKeyHMAC());
    assert(testEncryptDecrypt_AAD());

#if 1
    pthread_t threads[THREAD_COUNT];

    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_create(threads + i, NULL, threadRoutine, NULL);
    }

    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_join(threads[i], NULL);
    }
#endif

    cleanupCrypto();
}

bool testEncryptDecrypt(void) {
    unsigned char testKey[SYMMETRIC_KEY_SIZE];
    unsigned char testIV[IV_SIZE];

    fillRandom(testKey, SYMMETRIC_KEY_SIZE);
    fillRandom(testIV, IV_SIZE);

    unsigned char ciphertxt[testStringLen + BLOCK_SIZE];

    size_t cipherLen = encrypt(testString, testStringLen, testKey, testIV, ciphertxt);

    unsigned char plaintext[testStringLen + 1];

    assert(cipherLen <= testStringLen + BLOCK_SIZE);

    size_t plainLen = decrypt(ciphertxt, cipherLen, testKey, testIV, plaintext);

    plaintext[plainLen] = '\0';

    return strcmp((char *) plaintext, (char *) testString) == 0;
}

bool testHMAC(void) {
    EVP_PKEY *signKey = generateECKey();

    size_t hmaclen = 0;
    unsigned char *hmac = generateHMAC_PKEY(testString, testStringLen, &hmaclen, signKey);

    size_t refLen = 0;
    unsigned char *refVal = generateHMAC_PKEY(testString, testStringLen, &refLen, signKey);

#if 0
    for (size_t i = 0; i < hmaclen; ++i) {
        printf("%02x", hmac[i]);
    }
    printf("\n");

    for (size_t i = 0; i < refLen; ++i) {
        printf("%02x", refVal[i]);
    }
    printf("\n");
#endif

    assert(refLen == hmaclen);
    assert(memcmp(hmac, refVal,  refLen) == 0);

    bool rtn = verifyHMAC_PKEY(testString, testStringLen, hmac, hmaclen, signKey);

    OPENSSL_free(hmac);
    OPENSSL_free(refVal);
    EVP_PKEY_free(signKey);

    return rtn;
}

bool testECDH(void) {
    EVP_PKEY *firstKey = generateECKey();
    EVP_PKEY *secondKey = generateECKey();

    unsigned char *symKey = getSharedSecret(firstKey, secondKey);

    unsigned char testIV[IV_SIZE];

    fillRandom(testIV, IV_SIZE);

    unsigned char ciphertxt[testStringLen + BLOCK_SIZE];

    size_t cipherLen = encrypt(testString, testStringLen, symKey, testIV, ciphertxt);

    unsigned char plaintext[testStringLen + 1];

    size_t plainLen = decrypt(ciphertxt, cipherLen, symKey, testIV, plaintext);

    plaintext[plainLen] = '\0';

    EVP_PKEY_free(firstKey);
    EVP_PKEY_free(secondKey);

    OPENSSL_clear_free(symKey, EVP_MD_size(EVP_sha256()));

    return strcmp((char *) plaintext, (char *) testString) == 0;
}

bool testGetSetKey(void) {
    EVP_PKEY *origKey = generateECKey();

    size_t pubKeyLen;
    unsigned char *pub = getPublicKey(origKey, &pubKeyLen);

    EVP_PKEY *keyPairWithoutPrivate = setPublicKey(pub, pubKeyLen);

    size_t againLen;
    unsigned char *pubAgain = getPublicKey(keyPairWithoutPrivate, &againLen);

    bool rtn = (pubKeyLen == againLen && strncmp((char *) pub, (char *) pubAgain, pubKeyLen) == 0);

    EVP_PKEY_free(origKey);
    EVP_PKEY_free(keyPairWithoutPrivate);
    OPENSSL_free(pub);
    OPENSSL_free(pubAgain);

    return rtn;
}

bool testKeyHMAC(void) {
    EVP_PKEY *firstKey = generateECKey();
    EVP_PKEY *secondKey = generateECKey();

    size_t secondPubKeyLen;
    unsigned char *secondPubKey = getPublicKey(secondKey, &secondPubKeyLen);

    size_t hmacLen = 0;
    unsigned char *hmac = generateHMAC_PKEY(secondPubKey, secondPubKeyLen, &hmacLen, firstKey);

    unsigned char *mesgBuffer = malloc(secondPubKeyLen + hmacLen);
    memcpy(mesgBuffer, secondPubKey, secondPubKeyLen);
    memcpy(mesgBuffer + secondPubKeyLen, hmac, hmacLen);

    bool rtn =  verifyHMAC_PKEY(mesgBuffer, secondPubKeyLen, mesgBuffer + secondPubKeyLen, hmacLen, firstKey);

    free(mesgBuffer);
    OPENSSL_free(hmac);
    OPENSSL_free(secondPubKey);

    EVP_PKEY_free(firstKey);
    EVP_PKEY_free(secondKey);

    return rtn;
}

void *threadRoutine(void *arg) {
    for (int i = 0; i < TASK_COUNT; ++i) {
        testEncryptDecrypt();
        testHMAC();
        testECDH();
        testGetSetKey();
        testKeyHMAC();
        testEncryptDecrypt_AAD();
    }
    return arg;
}

bool testEncryptDecrypt_AAD(void) {
    unsigned char testKey[SYMMETRIC_KEY_SIZE];
    unsigned char testIV[IV_SIZE];
    unsigned char testaad[IV_SIZE];

    fillRandom(testKey, SYMMETRIC_KEY_SIZE);
    fillRandom(testIV, IV_SIZE);
    fillRandom(testaad, IV_SIZE);

    unsigned char ciphertxt[testStringLen];
    unsigned char tag[BLOCK_SIZE];

    size_t cipherLen = encrypt_aead(testString, testStringLen, testaad, IV_SIZE, testKey, testIV, ciphertxt, tag);

    unsigned char plaintext[testStringLen + 1];

    ssize_t plainLen = decrypt_aead(ciphertxt, cipherLen, testaad, IV_SIZE, testKey, testIV, tag, plaintext);

    plaintext[testStringLen] = '\0';

    bool rtn = (strcmp((char *) plaintext, (char *) testString) == 0);

    //Modification
    testaad[0] ^= 1;
    testaad[1] &= 1;
    testaad[2] += 1;

    plainLen = decrypt_aead(ciphertxt, cipherLen, testaad, IV_SIZE, testKey, testIV, tag, plaintext);
    if (plainLen == -1) {
        return rtn;
    } else {
        return false;
    }
}
