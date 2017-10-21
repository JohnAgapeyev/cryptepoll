#ifndef MACRO_H
#define MACRO_H

#define fatal_error(mesg) \
    do {\
    perror(mesg);\
    exit(EXIT_FAILURE);\
    } while(0);

#endif
