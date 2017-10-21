#include <stdlib.h>
#include "crypto.h"

int main(void) {
    initCrypto();

    EVP_PKEY *key = generateSigningKey();

    EVP_PKEY_free(key);

    //unsigned char buffer[4096];
    //fillRandom(buffer, 4096);

    cleanupCrypto();
    return EXIT_SUCCESS;
}
