#ifndef CRYPTO_H
#define CRYPTO_H

void initCrypto(void);
void cleanupCrypto(void);
void fillRandom(unsigned char *buf, size_t n);

#endif
