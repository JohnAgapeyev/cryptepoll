#ifndef EPOLL_H
#define EPOLL_H

#include <sys/epoll.h>

#define MAX_EPOLL_EVENTS 100

int createEpollFd(void);
void addEpollSocket(const int epollfd, const int sock, struct epoll_event *ev);
int waitForEpollEvent(const int epollfd, struct epoll_event *events);

#endif

