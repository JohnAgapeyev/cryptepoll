/*
 *Copyright (C) 2017 John Agapeyev
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation, either version 3 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License
 *along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *cryptepoll is licensed under the GNU General Public License version 3
 *with the addition of the following special exception:
 *
 ***
 In addition, as a special exception, the copyright holders give
 permission to link the code of portions of this program with the
 OpenSSL library under certain conditions as described in each
 individual source file, and distribute linked combinations
 including the two.
 You must obey the GNU General Public License in all respects
 for all of the code used other than OpenSSL.  If you modify
 file(s) with this exception, you may extend this exception to your
 version of the file(s), but you are not obligated to do so.  If you
 do not wish to do so, delete this exception statement from your
 version.  If you delete this exception statement from all source
 files in the program, then also delete it here.
 ***
 *
 */
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include "network.h"
#include "socket.h"
#include "crypto.h"
#include "macro.h"

EVP_PKEY *LongTermSigningKey = NULL;
EVP_PKEY *PeerSigningKey = NULL;
bool isServer;

void network_init(void) {
    initCrypto();
    LongTermSigningKey = generateECKey();
}

void network_cleanup(void) {
    if (LongTermSigningKey) {
        EVP_PKEY_free(LongTermSigningKey);
    }
    if (PeerSigningKey) {
        EVP_PKEY_free(PeerSigningKey);
    }
    cleanupCrypto();
}

/*
 * Does nothing intentionally.
 * This is to be replaced by the application's desired behaviour
 */
void process_packet(const char * const buffer, const size_t bufsize) {
    (void)(buffer);
    (void)(bufsize);
#ifndef NDEBUG
    fprintf(stderr, "Processing packet\n");
#endif
}

/*
 * Server signing key
 * Server public key + hmac
 * Client signing key
 * Client public key + hmac
 */
unsigned char *exchangeKeys(const int sock) {
    size_t pubKeyLen;
    unsigned char *signPubKey = getPublicKey(LongTermSigningKey, &pubKeyLen);

    EVP_PKEY *ephemeralKey = generateECKey();
    size_t ephemeralPubKeyLen;
    unsigned char *ephemeralPubKey = getPublicKey(ephemeralKey, &ephemeralPubKeyLen);

    unsigned char *hmac;
    size_t hmaclen;
    generateHMAC(ephemeralPubKey, ephemeralPubKeyLen, &hmac, &hmaclen, LongTermSigningKey);

    unsigned char *sharedSecret = NULL;

    if (isServer) {
        sendKey(sock, signPubKey, pubKeyLen);

        unsigned char *mesgBuffer = malloc(ephemeralPubKeyLen + hmaclen);
        if (mesgBuffer == NULL) {
            fatal_error("malloc");
        }
        memcpy(mesgBuffer, ephemeralKey, ephemeralPubKeyLen);
        memcpy(mesgBuffer + ephemeralPubKeyLen, hmac, hmaclen);
        sendKey(sock, mesgBuffer, ephemeralPubKeyLen + hmaclen);

        mesgBuffer = realloc(mesgBuffer, pubKeyLen);
        if (mesgBuffer == NULL) {
            fatal_error("realloc");
        }
        size_t n = readNBytes(sock, mesgBuffer, pubKeyLen);

        PeerSigningKey = setPublicKey(mesgBuffer, n);

        if (!receiveAndVerifyKey(sock, mesgBuffer, ephemeralPubKeyLen + hmaclen, ephemeralPubKeyLen, hmaclen)) {
            fatal_error("HMAC verification");
        }

        EVP_PKEY *clientPubKey = setPublicKey(mesgBuffer, ephemeralPubKeyLen);

        sharedSecret = getSharedSecret(ephemeralKey, clientPubKey);

        EVP_PKEY_free(clientPubKey);
        free(mesgBuffer);
    } else {
        unsigned char *mesgBuffer = malloc(pubKeyLen);
        if (mesgBuffer == NULL) {
            fatal_error("malloc");
        }
        size_t n = readNBytes(sock, mesgBuffer, pubKeyLen);

        PeerSigningKey = setPublicKey(mesgBuffer, n);

        mesgBuffer = realloc(mesgBuffer, ephemeralPubKeyLen + hmaclen);
        if (mesgBuffer == NULL) {
            fatal_error("realloc");
        }

        if (!receiveAndVerifyKey(sock, mesgBuffer, ephemeralPubKeyLen + hmaclen, ephemeralPubKeyLen, hmaclen)) {
            fatal_error("HMAC verification");
        }

        EVP_PKEY *serverPubKey = setPublicKey(mesgBuffer, ephemeralPubKeyLen);

        sendKey(sock, signPubKey, pubKeyLen);

        memcpy(mesgBuffer, ephemeralKey, ephemeralPubKeyLen);
        memcpy(mesgBuffer + ephemeralPubKeyLen, hmac, hmaclen);
        sendKey(sock, mesgBuffer, ephemeralPubKeyLen + hmaclen);

        sharedSecret = getSharedSecret(ephemeralKey, serverPubKey);

        free(mesgBuffer);
        EVP_PKEY_free(serverPubKey);
    }

    OPENSSL_free(signPubKey);
    OPENSSL_free(ephemeralPubKey);
    OPENSSL_free(hmac);
    EVP_PKEY_free(ephemeralKey);

    return sharedSecret;
}

void sendKey(const int sock, const unsigned char *buffer, const size_t bufSize) {
sendKey:
    if (send(sock, buffer, bufSize, 0) == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            //Non-blocking send would block, try again
            goto sendKey;
        } else {
            fatal_error("Key send");
        }
    }
}

bool receiveAndVerifyKey(const int sock, unsigned char *buffer, const size_t bufSize, const size_t keyLen, const size_t hmacLen) {
    assert(bufSize >= keyLen + hmacLen);
    readNBytes(sock, buffer, bufSize);

    EVP_PKEY *serverPubKey = setPublicKey(buffer, keyLen);

    bool rtn = verifyHMAC(buffer, keyLen, buffer + keyLen, hmacLen, PeerSigningKey);

    EVP_PKEY_free(serverPubKey);
    return rtn;
}

