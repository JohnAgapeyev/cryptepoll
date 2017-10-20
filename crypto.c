#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
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
    int urandom;
    if ((urandom = open("/dev/urandom", O_RDONLY)) == -1) {
        fatal_error("Open urandom");
    }
    ssize_t r;
    if ((r = read(urandom, buf, n)) == -1) {
        fatal_error("read urandom");
    }
    if ((size_t) r != n) {
        fprintf(stderr, "Failed to read %zu bytes from /dev/urandom", n);
        exit(EXIT_FAILURE);
    }
}

