#include <stdlib.h>
#include <string.h>
#include "crypto.h"

int main(void) {
    initCrypto();

    EVP_PKEY *key = generateSigningKey();

    unsigned char *hmac = NULL;
    size_t hmaclen = 0;

    const char *testString = "This is a test";
    const size_t testStringLen = strlen(testString);

    unsigned char testStringBuffer[20];
    strcpy((char *) testStringBuffer, testString);

    generateHMAC(testStringBuffer, testStringLen, &hmac, &hmaclen, key);

    if (verifyHMAC(testStringBuffer, testStringLen, hmac, hmaclen, key)) {
        puts("HMAC validated successfully");
    } else {
        puts("HMAC failed validation");
    }
    OPENSSL_free(hmac);

    EVP_PKEY_free(key);

    unsigned char buffer[4096];
    fillRandom(buffer, 4096);

    cleanupCrypto();
    return EXIT_SUCCESS;
}
