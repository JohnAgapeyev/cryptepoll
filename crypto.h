#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

#define libcrypto_error() \
    do {\
    fprintf(stderr, "Libcrypto error code %lu at %s, line %d in function %s\n", ERR_get_error(), __FILE__, __LINE__, __func__); \
    exit(EXIT_FAILURE);\
    } while(0)

void initCrypto(void);
void cleanupCrypto(void);
void fillRandom(unsigned char *buf, size_t n);
EVP_PKEY *generateSigningKey(void);
void SecureFree(void *addr, size_t n);

#endif
