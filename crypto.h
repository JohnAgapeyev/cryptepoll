#ifndef CRYPTO_H
#define CRYPTO_H

#define libcrypto_error() \
    fprintf(stderr, "Libcrypto error code %lu at %s, line %d in function %s\n", ERR_get_error(), __FILE__, __LINE__, __func__); \
    exit(EXIT_FAILURE);

void initCrypto(void);
void cleanupCrypto(void);
void fillRandom(unsigned char *buf, size_t n);

#endif
