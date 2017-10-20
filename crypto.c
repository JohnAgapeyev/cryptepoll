#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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
