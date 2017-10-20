#include <stdlib.h>
#include "crypto.h"

int main(void) {
    initCrypto();

    unsigned char buffer[4096];
    fillRandom(buffer, 4096);

    cleanupCrypto();
    return EXIT_SUCCESS;
}
