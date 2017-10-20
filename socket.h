#ifndef SOCKET_H
#define SOCKET_H

int createSocket(int domain, int type, int protocol);
void setNonBlocking(const int sock);
void bindSocket(const int sock, const unsigned short port);
int establishConnection(const char *address, const char *port);

#endif
