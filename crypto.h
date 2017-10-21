#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <stdbool.h>

#define libcrypto_error() \
    do {\
        fprintf(stderr, "Libcrypto error code %lu at %s, line %d in function %s\n", ERR_get_error(), __FILE__, __LINE__, __func__); \
        exit(EXIT_FAILURE);\
    } while(0)

#define checkCryptoAPICall(pred) \
    do {\
        if ((pred) != 1) {\
            libcrypto_error();\
        }\
    } while(0)

void initCrypto(void);
void cleanupCrypto(void);
void fillRandom(unsigned char *buf, size_t n);
EVP_PKEY *generateSigningKey(void);
void generateHMAC(const unsigned char *mesg, size_t mlen, unsigned char **hmac, size_t *hmaclen, EVP_PKEY *key);
bool verifyHMAC(const unsigned char *mesg, size_t mlen, const unsigned char *hmac, size_t hmaclen, EVP_PKEY *key);
void SecureFree(void *addr, size_t n);

#endif
