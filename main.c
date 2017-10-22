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
#include <stdlib.h>
#include <string.h>
#include "crypto.h"

int main(void) {
    initCrypto();

    unsigned char *hmac = NULL;
    size_t hmaclen = 0;

    const unsigned char *testString = (unsigned char *) "This is a test";
    const size_t testStringLen = strlen((const char *) testString);

    unsigned char testKey[32];
    unsigned char testIV[16];

    fillRandom(testKey, 32);
    fillRandom(testIV, 16);

    unsigned char ciphertxt[128];

    size_t cipherLen = encrypt(testString, testStringLen, testKey, testIV, ciphertxt);

    unsigned char plaintext[128];

    size_t plainLen = decrypt(ciphertxt, cipherLen, testKey, testIV, plaintext);

    plaintext[plainLen] = '\0';

    printf("Cipher length: %zu\nPlain length: %zu\nPlainText: %s\n", cipherLen, plainLen, plaintext);

    EVP_PKEY *signKey = generateSigningKey();
    generateHMAC(testString, testStringLen, &hmac, &hmaclen, signKey);
    if (verifyHMAC(testString, testStringLen, hmac, hmaclen, signKey)) {
        puts("HMAC validated successfully");
    } else {
        puts("HMAC failed validation");
    }
    OPENSSL_free(hmac);

    EVP_PKEY_free(signKey);

    unsigned char buffer[4096];
    fillRandom(buffer, 4096);

    cleanupCrypto();
    return EXIT_SUCCESS;
}
