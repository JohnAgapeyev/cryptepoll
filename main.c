/*
 * SOURCE FILE: main.c - Implementation of functions declared in main.h
 *
 * PROGRAM: 7005-asn4
 *
 * DATE: Dec. 2, 2017
 *
 * FUNCTIONS:
 * static void sighandler(int signo);
 * char *getUserInput(const char *prompt);
 * void debug_print_buffer(const char *prompt, const unsigned char *buffer, const size_t size);
 * void *checked_malloc(const size_t size);
 * void *checked_calloc(const size_t nmemb, const size_t size);
 * void *checked_realloc(void *ptr, const size_t size);
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
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <getopt.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include "main.h"
#include "macro.h"
#include "test.h"
#include "socket.h"
#include "network.h"

int outputFD = -1;

static void sighandler(int signo);

static struct option long_options[] = {
    {"port",    required_argument, 0, 'p'},
    {"help",    no_argument,       0, 'h'},
    {"client",  no_argument,       0, 'c'},
    {"server",  no_argument,       0, 's'},
    {"ip",      required_argument, 0, 'i'},
    {"file",    required_argument, 0, 'f'},
    {0,         0,                 0, 0}
};

#define print_help() \
    do { \
    printf("usage options:\n"\
            "\t [p]ort <1-65535>        - the port to use, default 1337\n"\
            "\t [c]lient                - run as client, exclusive with server\n"\
            "\t [s]erver                - run as server, exclusive with client\n"\
            "\t [i]p <url || ip>        - address to connect to\n"\
            "\t [f]ile <path/to/file>   - the file to send\n"\
            "\t [h]elp                  - this message\n"\
            );\
    } while(0)

/*
 * FUNCTION: main
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
 * int main(int argc, char **argv)
 *
 * PARAMETERS:
 * int argc - The number of command arguments
 * char **argv - A list of the command arguments as strings
 *
 * RETURNS:
 * int - The application return code
 *
 * NOTES:
 * Validates command arguments and starts client/server from here
 */
int main(int argc, char **argv) {
    isRunning = ATOMIC_VAR_INIT(1);

    struct sigaction sigHandleList = {.sa_handler=sighandler};
    sigaction(SIGINT,&sigHandleList,0);
    sigaction(SIGHUP,&sigHandleList,0);
    sigaction(SIGQUIT,&sigHandleList,0);
    sigaction(SIGTERM,&sigHandleList,0);

    bool isClient = false; //Temp bool used to check if both client and server is chosen
    isServer = false;

    const char *portString = NULL;
    const char *ipAddr = NULL;
    const char *filename = NULL;

    int inputFD = -1;

    int c;
    for (;;) {
        int option_index = 0;
        if ((c = getopt_long(argc, argv, "csp:i:f:h", long_options, &option_index)) == -1) {
            break;
        }
        switch (c) {
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
            case 'i':
                ipAddr = optarg;
                break;
            case 'f':
                filename = optarg;
                break;
            case 'h':
                //Intentional fallthrough
            case '?':
                //Intentional fallthrough
            default:
                print_help();
                return EXIT_SUCCESS;
        }
    }
    if (isClient == isServer) {
        print_help();
        return EXIT_SUCCESS;
    }
    if (portString == NULL) {
        puts("No port set, reverting to port 1337");
        portString = "1337";
    }
    if (ipAddr == NULL) {
        if (!isServer) {
            puts("No IP provided, will prompt for IP");
        }
    }
    if (filename == NULL) {
        puts("No filename provided, defaulting to stdin");
        inputFD = STDIN_FILENO;
    } else {
        FILE *fp = fopen(filename, "rb");
        if (fp == NULL) {
            printf("Filename invalid\n");
            print_help();
            return EXIT_FAILURE;
        }
        inputFD = fileno(fp);
        assert(inputFD != -1);
    }
    port = strtoul(portString, NULL, 0);
    if (errno == EINVAL || errno == ERANGE) {
        perror("strtoul");
        return EXIT_FAILURE;
    }
    struct rlimit limit;
    /* Get max number of files. */
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
        printf("getrlimit() failed with errno=%d\n", errno);
        exit(0);
    }

    limit.rlim_max = USHRT_MAX;
    limit.rlim_cur = limit.rlim_max;

    printf("Setting soft limit: %d\n", limit.rlim_cur);

    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
        printf("setrlimit() failed with errno=%d\n", errno);
        exit(0);
    }


    if (isServer) {
        listenSock = createSocket(AF_INET, SOCK_STREAM, 0);
        bindSocket(listenSock, port);
        listen(listenSock, 5);
        startServer(inputFD);
        close(listenSock);
    } else {
        startClient(ipAddr, portString, inputFD);
    }

    return EXIT_SUCCESS;
}

/*
 * FUNCTION: getUserInput
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
 * char *getUserInput(const char *prompt);
 *
 * PARAMETERS:
 * const char *prompt - The prompt string to print to the user
 *
 * RETURNS:
 * char * - A buffer pointer to the string the user entered
 *
 * NOTES:
 * Gets user input and stores it in a buffer.
 * Limits user input to MAX_USER_BUFFER to prevent overflows.
 * Guarantees null termination on the returned string.
 */
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

/*
 * FUNCTION: sighandler
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
 * void sighandler(int signo)
 *
 * PARAMETERS:
 * int signo - The signal number received
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Sets isRunning to 0 to terminate program gracefully in the event of SIGINT or other
 * user sent signals.
 */
void sighandler(int signo) {
    (void)(signo);
    isRunning = 0;
}

/*
 * FUNCTION: debug_print_buffer
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
 * void debug_print_buffer(const char *prompt, const unsigned char *buffer, const size_t size);
 *
 * PARAMETERS:
 * const char *prompt - The prompt to show for debug purposes
 * const unsigned char *buffer - The buffer to print out
 * const size_t size - The size of the buffer
 *
 * RETURNS:
 * void
 *
 * NOTES:
 * Method is nop in release mode.
 * For debug it is useful to see the raw hex contents of a buffer for checks such as HMAC verification.
 */
void debug_print_buffer(const char *prompt, const unsigned char *buffer, const size_t size) {
#ifndef NDEBUG
    printf(prompt);
    for (size_t i = 0; i < size; ++i) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
#else
    (void)(prompt);
    (void)(buffer);
    (void)(size);
#endif
}

/*
 * FUNCTION: checked_malloc
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
 * void *checked_malloc(const size_t size);
 *
 * PARAMETERS:
 * const size_t - The size to allocate
 *
 * RETURNS:
 * void * - The allocated buffer
 *
 * NOTES:
 * Simple wrapper to check for out of memory.
 */
void *checked_malloc(const size_t size) {
    void *rtn = malloc(size);
    if (rtn == NULL) {
        fatal_error("malloc");
    }
    return rtn;
}

/*
 * FUNCTION: checked_calloc
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
 * void *checked_calloc(const size_t nmemb, const size_t size);
 *
 * PARAMETERS:
 * const size_t nmemb - The number of items to allocate
 * const size_t - The size of each member
 *
 * RETURNS:
 * void * - The allocated buffer
 *
 * NOTES:
 * Simple wrapper to check for out of memory.
 */
void *checked_calloc(const size_t nmemb, const size_t size) {
    void *rtn = calloc(nmemb, size);
    if (rtn == NULL) {
        fatal_error("calloc");
    }
    return rtn;
}

/*
 * FUNCTION: checked_realloc
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
 * void *checked_realloc(void *ptr, const size_t size);
 *
 * PARAMETERS:
 * void *ptr - The old pointer
 * const size_t - The size to allocate
 *
 * RETURNS:
 * void * - The reallocated buffer
 *
 * NOTES:
 * Simple wrapper to check for out of memory.
 */
void *checked_realloc(void *ptr, const size_t size) {
    void *rtn = realloc(ptr, size);
    if (rtn == NULL) {
        fatal_error("realloc");
    }
    return rtn;
}
