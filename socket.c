#include <sys/socket.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "socket.h"
#include "macro.h"

int createSocket(int domain, int type, int protocol) {
    int sock;
    if ((sock = socket(domain, type, protocol)) == -1) {
        fatal_error("socket");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1) {
        fatal_error("SO_REUSEADDR");
    }
    return sock;
}

void setNonBlocking(const int sock) {
    int flags;
    if ((flags = fcntl(sock, F_GETFL, 0)) == -1){
        fatal_error("fcntl get");
    }
    flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) == -1) {
        fatal_error("fcntl set");
    }
}

void bindSocket(const int sock, const unsigned short port) {
    struct sockaddr_in myAddr;
    memset(&myAddr, 0, sizeof(struct sockaddr_in));
    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(port);
    myAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *) &myAddr, sizeof(struct sockaddr_in)) == -1) {
        fatal_error("bind");
    }
}

int establishConnection(const char *address, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;     // Return IPv4 and IPv6 choices
    hints.ai_socktype = SOCK_STREAM; // We want a TCP socket
    hints.ai_flags = (AI_ADDRCONFIG | AI_V4MAPPED);

    struct addrinfo *result;
    int e;
    if ((e = getaddrinfo(address, port, &hints, &result)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(e));
        exit(EXIT_FAILURE);
    }

    struct addrinfo *rp;
    int sock;
    for (rp = result; rp; rp = rp->ai_next) {
        if ((sock = createSocket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) {
            continue;
        }
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(sock);
    }

    if (!rp) {
        fprintf(stderr, "Unable to connect\n");
        return -1;
    }

    freeaddrinfo(result);
    return sock;
}

