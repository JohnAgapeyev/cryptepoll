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
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "main.h"
#include "test.h"
#include "socket.h"
#include "network.h"

int main(int argc, char **argv) {
#ifndef NDEBUG
    //performTests();
    //return EXIT_SUCCESS;
#else
    //Do nothing at the moment
#endif

    int option;
    bool isClient = false; //Temp bool used to check if both client and server is chosen
    isServer = false;

    const char *portString = NULL;

    while ((option = getopt(argc, argv, "csp:")) != -1) {
        switch (option) {
            case 'c':
                isClient = true;
                isServer = false;
                break;
            case 's':
                isServer = true;
                break;
            case 'p':
                portString = optarg;
                break;
        }
    }
    if (isClient == isServer) {
        puts("This program must be run with either the -c or -s flag, but not both.");
        puts("Please re-run this program with one of the above flags.");
        puts("-c represents client mode, -s represents server mode");
        return EXIT_SUCCESS;
    }

    if (portString == NULL) {
        puts("No port set, reverting to port 1337");
        portString = "1337";
    }

    //port = htons(strtoul(portString, NULL, 0));
    port = (strtoul(portString, NULL, 0));
    if (errno == EINVAL || errno == ERANGE) {
        perror("strtoul");
        return EXIT_FAILURE;
    }

    if (isServer) {
        listenSock = createSocket(AF_INET, SOCK_STREAM, 0);
        bindSocket(listenSock, port);
        listen(listenSock, 5);
        startServer();
        close(listenSock);
    } else {
        startClient();
    }

    return EXIT_SUCCESS;
}

#define MAX_USER_BUFFER 1024

char *getUserInput(const char *prompt) {
    char *buffer = calloc(MAX_USER_BUFFER, sizeof(char));
    if (buffer == NULL) {
        perror("Allocation failure");
        abort();
    }
    printf("%s", prompt);
    int c;
    for (;;) {
        c = getchar();
        if (c == EOF) {
            break;
        }
        if (!isspace(c)) {
            ungetc(c, stdin);
            break;
        }
    }
    size_t n = 0;
    for (;;) {
        c = getchar();
        if (c == EOF || (isspace(c) && c != ' ')) {
            buffer[n] = '\0';
            break;
        }
        buffer[n] = c;
        if (n == MAX_USER_BUFFER - 1) {
            printf("Message too big\n");
            memset(buffer, 0, MAX_USER_BUFFER);
            while ((c = getchar()) != '\n' && c != EOF) {}
            n = 0;
            continue;
        }
        ++n;
    }
    return buffer;
}
