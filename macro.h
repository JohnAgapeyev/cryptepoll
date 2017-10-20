#ifndef MACRO_H
#define MACRO_H

#define fatal_error(mesg) \
    perror(mesg);\
    exit(EXIT_FAILURE);

#endif
