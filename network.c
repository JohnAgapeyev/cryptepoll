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
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "network.h"
#include "epoll.h"
#include "socket.h"
#include "crypto.h"
#include "macro.h"
#include "main.h"

EVP_PKEY *LongTermSigningKey = NULL;
bool isServer;
struct client *clientList;
size_t clientCount;
unsigned short port;
int listenSock;
pthread_mutex_t clientLock;

void network_init(void) {
    initCrypto();
    LongTermSigningKey = generateECKey();
    clientList = calloc(10, sizeof(struct client));
    clientCount = 1;
    pthread_mutex_init(&clientLock, NULL);
}

void network_cleanup(void) {
    if (LongTermSigningKey) {
        EVP_PKEY_free(LongTermSigningKey);
    }
    for (size_t i = 0; i< clientCount; ++i) {
        OPENSSL_clear_free(clientList[i].sharedKey, SYMMETRIC_KEY_SIZE);
        EVP_PKEY_free(clientList[i].signingKey);
    }
    pthread_mutex_destroy(&clientLock);
    free(clientList);
    cleanupCrypto();
}

/*
 * Does nothing intentionally.
 * This is to be replaced by the application's desired behaviour
 */
void process_packet(const unsigned char * const buffer, const size_t bufsize) {
    (void)(buffer);
    (void)(bufsize);
#ifndef NDEBUG
    fprintf(stderr, "Processing packet\n");
    fprintf(stderr, "Processing packet of size %zu with contents %s\n", bufsize, buffer);
#endif
}

/*
 * Server signing key
 * Server public key + hmac
 * Client signing key
 * Client public key + hmac
 */
unsigned char *exchangeKeys(const int * const sock) {
    size_t pubKeyLen;
    unsigned char *signPubKey = getPublicKey(LongTermSigningKey, &pubKeyLen);

    EVP_PKEY *ephemeralKey = generateECKey();
    size_t ephemeralPubKeyLen;
    unsigned char *ephemeralPubKey = getPublicKey(ephemeralKey, &ephemeralPubKeyLen);

    unsigned char *hmac = NULL;
    size_t hmaclen;
    generateHMAC(ephemeralPubKey, ephemeralPubKeyLen, &hmac, &hmaclen, LongTermSigningKey);

    unsigned char *sharedSecret = NULL;

    struct client *clientEntry = container_entry(sock, struct client, socket);

    if (isServer) {
        sendKey(*sock, signPubKey, pubKeyLen);

        unsigned char *mesgBuffer = malloc(ephemeralPubKeyLen + hmaclen);
        if (mesgBuffer == NULL) {
            fatal_error("malloc");
        }
        memcpy(mesgBuffer, ephemeralKey, ephemeralPubKeyLen);
        memcpy(mesgBuffer + ephemeralPubKeyLen, hmac, hmaclen);
        sendKey(*sock, mesgBuffer, ephemeralPubKeyLen + hmaclen);

        mesgBuffer = realloc(mesgBuffer, pubKeyLen);
        if (mesgBuffer == NULL) {
            fatal_error("realloc");
        }
        size_t n = readNBytes(*sock, mesgBuffer, pubKeyLen);

        clientEntry->signingKey = setPublicKey(mesgBuffer, n);

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
        size_t n = readNBytes(*sock, mesgBuffer, pubKeyLen);

        clientEntry->signingKey = setPublicKey(mesgBuffer, n);

        mesgBuffer = realloc(mesgBuffer, ephemeralPubKeyLen + hmaclen);
        if (mesgBuffer == NULL) {
            fatal_error("realloc");
        }

        if (!receiveAndVerifyKey(sock, mesgBuffer, ephemeralPubKeyLen + hmaclen, ephemeralPubKeyLen, hmaclen)) {
            fatal_error("HMAC verification");
        }

        EVP_PKEY *serverPubKey = setPublicKey(mesgBuffer, ephemeralPubKeyLen);

        sendKey(*sock, signPubKey, pubKeyLen);

        memcpy(mesgBuffer, ephemeralKey, ephemeralPubKeyLen);
        memcpy(mesgBuffer + ephemeralPubKeyLen, hmac, hmaclen);
        sendKey(*sock, mesgBuffer, ephemeralPubKeyLen + hmaclen);

        sharedSecret = getSharedSecret(ephemeralKey, serverPubKey);

        free(mesgBuffer);
        EVP_PKEY_free(serverPubKey);
    }

    OPENSSL_free(signPubKey);
    OPENSSL_free(ephemeralPubKey);
    OPENSSL_free(hmac);
    EVP_PKEY_free(ephemeralKey);

    clientEntry->sharedKey = sharedSecret;

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

bool receiveAndVerifyKey(const int * const sock, unsigned char *buffer, const size_t bufSize, const size_t keyLen, const size_t hmacLen) {
    assert(bufSize >= keyLen + hmacLen);
    readNBytes(*sock, buffer, bufSize);

    EVP_PKEY *serverPubKey = setPublicKey(buffer, keyLen);

    struct client *entry = container_entry(sock, struct client, socket);

    bool rtn = verifyHMAC(buffer, keyLen, buffer + keyLen, hmacLen, entry->signingKey);

    EVP_PKEY_free(serverPubKey);
    return rtn;
}

void startClient(void) {
    network_init();
    char *address = getUserInput("Enter the server's address: ");
    char *portString = calloc(10, sizeof(char));
    sprintf(portString, "%d", (unsigned short) (port));

    int serverSock = establishConnection(address, portString);
    if (serverSock == -1) {
        fprintf(stderr, "Unable to connect to server\n");
        goto clientCleanup;
    }

    setNonBlocking(serverSock);

    size_t clientNum = addClient(serverSock);

    struct client *serverEntry = &clientList[clientNum];

    //unsigned char *secretKey = exchangeKeys(&serverEntry->socket);

    int epollfd = createEpollFd();

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
    ev.data.ptr = serverEntry;

    addEpollSocket(epollfd, serverSock, &ev);

    pthread_t readThread;
    pthread_create(&readThread, NULL, eventLoop, &epollfd);

    //eventLoop(&epollfd);

    while(true) {
        char *result = getUserInput("Enter your message: ");
        send(serverSock, result, strlen(result), 0);
        free(result);
    }

clientCleanup:
    free(address);
    free(portString);
    network_cleanup();
}

void startServer(void) {
    network_init();

    int epollfd = createEpollFd();

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
    ev.data.ptr = NULL;

    setNonBlocking(listenSock);

    addEpollSocket(epollfd, listenSock, &ev);

    //TODO: Create threads here instead of calling eventloop directly
    eventLoop(&epollfd);

    network_cleanup();
}

void *eventLoop(void *epollfd) {
    int efd = *((int *)epollfd);

    struct epoll_event *eventList = calloc(MAX_EPOLL_EVENTS, sizeof(struct epoll_event));
    if (eventList == NULL) {
        fatal_error("calloc");
    }

    //TODO: Change infinite loop to use condition that changes on user exit
    while (true) {
        int n = waitForEpollEvent(efd, eventList);
        if (n == -1) {
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < n; ++i) {
            if (eventList[i].events & EPOLLERR) {
                if (eventList[i].data.ptr) {
                    int sock = ((struct client *) eventList[i].data.ptr)->socket;
                    fprintf(stderr, "Socket error on socket %d\n", sock);
                    close(sock);
                } else {
                    fprintf(stderr, "Socket error on socket %d\n", listenSock);
                    close(listenSock);
                }
            } else if (eventList[i].events & EPOLLHUP) {
                if (eventList[i].data.ptr) {
                    int sock = ((struct client *) eventList[i].data.ptr)->socket;
                    fprintf(stderr, "Socket %d closed\n", sock);
                    close(sock);
                } else {
                    fprintf(stderr, "Socket %d closed\n", listenSock);
                    close(listenSock);
                }
            } else if (eventList[i].events & EPOLLIN) {
                if (eventList[i].data.ptr) {
                    //Regular read connection
                    int sock = ((struct client *) eventList[i].data.ptr)->socket;

                    int sizeToRead;
                    if (ioctl(sock, FIONREAD, &sizeToRead) == -1) {
                        fatal_error("ioctl");
                    }
                    //Ensure base-level buffer size
                    if (sizeToRead < 1024) {
                        sizeToRead = 1024;
                    }

                    //Double the given size to hopefully catch all the data at once
                    unsigned char *buffer = malloc(2 * sizeToRead);

                    int numRead;
                    while ((numRead = readNBytes(sock, buffer, 2 * sizeToRead)) > 0) {
                        process_packet(buffer, numRead);
                        if (isServer) {
                            send(sock, buffer, numRead, 0);
                        }
                    }
                } else {
                    //Null data pointer means listen socket has incoming connection
                    for(;;) {
                        int sock = accept(listenSock, NULL, NULL);
                        if (sock == -1) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                //No incoming connections, ignore the error
                                break;
                            } else {
                                fatal_error("accept");
                            }
                        }

                        setNonBlocking(sock);

                        size_t newClientIndex = addClient(sock);

                        //unsigned char *secretKey = exchangeKeys(&clientList[newClientIndex].socket);

                        //Add keys to client struct here

                        struct epoll_event ev;
                        ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
                        ev.data.ptr = &clientList[newClientIndex];

                        addEpollSocket(efd, sock, &ev);
                    }
                }
            }
        }
    }
    return NULL;
}

size_t addClient(int sock) {
    pthread_mutex_lock(&clientLock);
    bool foundEntry = false;
    for (size_t i = 0; i < clientCount; ++i) {
        if (clientList[i].enabled == false) {
            initClientStruct(clientList + i, sock);
            ++clientCount;
            foundEntry = true;
            break;
        }
    }
    if (!foundEntry) {
        clientList = realloc(clientList, sizeof(struct client) * clientCount * 2);
        if (clientList == NULL) {
            fatal_error("realloc");
        }
        memset(clientList + clientCount, 0, sizeof(struct client) * clientCount);
        initClientStruct(clientList + clientCount, sock);
        ++clientCount;
    }
    pthread_mutex_unlock(&clientLock);
    //Subtract 2: 1 for incremented client count, 1 for dummy value
    return clientCount - 2;
}

void initClientStruct(struct client *newClient, int sock) {
    newClient->socket = sock;
    newClient->sharedKey = NULL;
    newClient->signingKey = NULL;
    newClient->enabled = true;
}
