/*
 * HEADER FILE: socket.h - Socket calls and their wrappers
 *
 * PROGRAM: 7005-asn4
 *
 * DATE: Dec. 2, 2017
 *
 * FUNCTIONS:
 * int createSocket(int domain, int type, int protocol);
 * void setNonBlocking(const int sock);
 * void bindSocket(const int sock, const unsigned short port);
 * int establishConnection(const char *address, const char *port);
 * size_t readNBytes(const int sock, unsigned char *buf, size_t bufsize);
 * void rawSend(const int sock, const unsigned char *buffer, size_t bufSize);
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
#ifndef SOCKET_H
#define SOCKET_H

int createSocket(int domain, int type, int protocol);
void setNonBlocking(const int sock);
void bindSocket(const int sock, const unsigned short port);
int establishConnection(const char *address, const char *port);
size_t readNBytes(const int sock, unsigned char *buf, size_t bufsize);
void rawSend(const int sock, const unsigned char *buffer, size_t bufSize);

#endif
