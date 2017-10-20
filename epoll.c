#include <sys/epoll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "epoll.h"
#include "macro.h"

int createEpollFd(void) {
    int efd;
    if ((efd = epoll_create1(0)) == -1) {
        fatal_error("epoll_create1");
    }
    return efd;
}

void addEpollSocket(const int epollfd, const int sock, struct epoll_event *ev) {
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, ev) == -1) {
        fatal_error("epoll_ctl");
    }
}

int waitForEpollEvent(const int epollfd, struct epoll_event *events) {
    int nevents;
    if ((nevents = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1)) == -1) {
        fatal_error("epoll_wait");
    }
    return nevents;
}

