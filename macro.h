/*
 * HEADER FILE: macro.h - Useful macros
 *
 * PROGRAM: 7005-asn4
 *
 * DATE: Dec. 2, 2017
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
#ifndef MACRO_H
#define MACRO_H

#include <stddef.h>

#define fatal_error(mesg) \
    do {\
        perror(mesg);\
        fprintf(stderr, "%s, line %d in function %s\n", __FILE__, __LINE__, __func__); \
        exit(EXIT_FAILURE);\
    } while(0)

#define container_entry(ptr, type, member)\
    ((type *)((char *)(1 ? (ptr) : &((type *)0)->member) - offsetof(type, member)))

#ifndef NDEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#define debug_print(...) \
    do { \
        if (DEBUG) {\
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while(0)

#endif
