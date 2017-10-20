#include <stdlib.h>
#include "crypto.h"

int main(void) {
    initCrypto();
    cleanupCrypto();
    return EXIT_SUCCESS;
}
