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
#ifndef NETWORK_H
#define NETWORK_H

#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>

struct client {
    int socket;
    unsigned char *sharedKey;
    EVP_PKEY *signingKey;
    bool enabled;
};

/*
 * Length is 2 bytes
 * Ciphertext can be max 4096
 * IV is 16
 * Tag size is 16
 */
#define MAX_PACKET_SIZE 4096 + IV_SIZE + TAG_SIZE + sizeof(uint16_t)

extern bool isServer;
extern EVP_PKEY *LongTermSigningKey;
extern struct client **clientList;
extern size_t clientCount;
extern unsigned short port;
extern int listenSock;

void network_init(void);
void network_cleanup(void);
void process_packet(const unsigned char * const buffer, const size_t bufsize, struct client *src);
unsigned char *exchangeKeys(struct client *clientEntry);
bool receiveAndVerifyKey(const int * const sock, unsigned char *buffer, const size_t bufSize, const size_t keyLen, const size_t hmacLen);
void startClient(const char *ip, const char *portString, int inputFD);
void startServer(const int inputFD);
size_t addClient(int sock);
void initClientStruct(struct client *newClient, int sock);
void *eventLoop(void *epollfd);
void sendEncryptedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *dest);
void decryptReceivedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *src);
void sendReliablePacket(const unsigned char *mesg, const size_t mesgLen, struct client *dest);
void handleIncomingConnection(const int efd);
void handleSocketError(const int epollfd, struct client *entry);
void handleIncomingPacket(struct client *src);
uint16_t readPacketLength(const int sock);
void sendSigningKey(const int sock, const unsigned char *key, const size_t keyLen);
void sendEphemeralKey(const int sock, const unsigned char *key, const size_t keyLen, const unsigned char *hmac, const size_t hmacLen);
void readSigningKey(const int sock, struct client *clientEntry, const size_t keyLen);

#endif
