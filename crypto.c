#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
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
    checkCryptoAPICall(RAND_bytes(buf, n));
}

EVP_PKEY *generateSigningKey(void) {
    EVP_PKEY_CTX *pctx;

    checkCryptoAPICall((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)));

    checkCryptoAPICall(EVP_PKEY_paramgen_init(pctx));

    int curveNID;
    if ((curveNID = OBJ_sn2nid(SN_secp521r1)) == NID_undef) {
        libcrypto_error();
    }

    checkCryptoAPICall(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curveNID));

    EVP_PKEY *params = EVP_PKEY_new();

    checkCryptoAPICall(EVP_PKEY_paramgen(pctx, &params));

    EVP_PKEY_CTX *kctx;

    checkCryptoAPICall((kctx = EVP_PKEY_CTX_new(params, NULL)));

    checkCryptoAPICall(EVP_PKEY_keygen_init(kctx) );

    EVP_PKEY *key = EVP_PKEY_new();

    checkCryptoAPICall(EVP_PKEY_keygen(kctx, &key));

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);

    return key;
}

void SecureFree(void *addr, size_t n) {
    OPENSSL_clear_free(addr, n);
}

