/*
 * SOURCE FILE: epoll.c - Implementation of functions declared in epoll.h
 *
 * PROGRAM: 7005-asn4
 *
 * DATE: Dec. 2, 2017
 *
 * FUNCTIONS:
 * int createEpollFd(void);
 * void addEpollSocket(const int epollfd, const int sock, struct epoll_event *ev);
 * int waitForEpollEvent(const int epollfd, struct epoll_event *events);
 * size_t singleEpollReadInstance(const int sock, unsigned char *buffer, const size_t bufSize);
 *
 * DESIGNER: John Agapeyev
 *
 * PROGRAMMER: John Agapeyev
 */
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
#include <sys/epoll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "epoll.h"
#include "main.h"
#include "macro.h"
#include "socket.h"

/*
 * FUNCTION: createEpollFd
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * int createEpollFd(void);
 *
 * RETURNS:
 * int - The created epoll file descriptor
 */
int createEpollFd(void) {
    int efd;
    if ((efd = epoll_create1(0)) == -1) {
        fatal_error("epoll_create1");
    }
    return efd;
}

/*
 * FUNCTION: addEpollSocket
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * void addEpollSocket(const int epollfd, const int sock, struct epoll_event *ev);
 *
 * PARAMETERS:
 * const int epollfd - The epoll descriptor to add the socket to
 * const int sock - The socket to add to epoll
 * struct epoll_event *ev - The epoll_event struct saying how epoll should handle the socket
 *
 * RETURNS:
 * void
 */
void addEpollSocket(const int epollfd, const int sock, struct epoll_event *ev) {
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, ev) == -1) {
        fatal_error("epoll_ctl");
    }
}

/*
 * FUNCTION: waitForEpollEvent
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * int waitForEpollEvent(const int epollfd, struct epoll_event *events);
 *
 * PARAMETERS:
 * const int epollfd - The epoll descriptor to wait on
 * struct epoll_event *events - The event list that epoll write too
 *
 * RETURNS:
 * int - The number of events on the epoll descriptor
 */
int waitForEpollEvent(const int epollfd, struct epoll_event *events) {
    int nevents;
    if ((nevents = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1)) == -1) {
        if (errno == EINTR) {
            //Interrupted by signal, ignore it
            return 0;
        }
        fatal_error("epoll_wait");
    }
    return nevents;
}

/*
 * FUNCTION: singleEpollReadInstance
 *
 * DATE:
 * Dec. 2, 2017
 *
 * DESIGNER:
 * John Agapeyev
 *
 * PROGRAMMER:
 * John Agapeyev
 *
 * INTERFACE:
 * size_t singleEpollReadInstance(const int sock, unsigned char *buffer, const size_t bufSize);
 *
 * PARAMETERS:
 * const int sock - The socket to read on
 * unsigned char *buffer - The buffer to write the packet to
 * const size_t bufSize - The size of the buffer that was passed in
 *
 * RETURNS:
 * size_t - The number of bytes read from the socket
 *
 * NOTES:
 * Sometimes the application requires a one-off read on a socket, such as during the initial handshake.
 * This function sets up a short and sweet epoll instance to do a single read on a socket, then clean
 * up after itself.
 */
size_t singleEpollReadInstance(const int sock, unsigned char *buffer, const size_t bufSize) {
    int epollfd = createEpollFd();

    struct epoll_event ev;
    ev.data.fd = sock;
    ev.events = EPOLLIN | EPOLLET;

    addEpollSocket(epollfd, sock, &ev);

    struct epoll_event *eventList = checked_malloc(sizeof(struct epoll_event) * MAX_EPOLL_EVENTS);

    int nevents = waitForEpollEvent(epollfd, eventList);
    size_t n = 0;
    for (int i = 0; i < nevents; ++i) {
        if (eventList[i].events & EPOLLERR) {
            fatal_error("One off epoll error");
        } else if (eventList[i].events & EPOLLHUP) {
            fatal_error("One off epoll socket closed");
        } else if (eventList[i].events & EPOLLIN) {
            n = readNBytes(sock, buffer, bufSize);
        } else {
            fatal_error("Unknown epoll error");
        }
    }

    free(eventList);
    close(epollfd);

    return n;
}
