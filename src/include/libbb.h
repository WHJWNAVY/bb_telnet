/* vi: set sw=4 ts=4: */
/*
 * Busybox main internal header file
 *
 * Based in part on code from sash, Copyright (c) 1999 by David I. Bell
 * Permission has been granted to redistribute this code under GPL.
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#ifndef LIBBB_H
#define LIBBB_H 1

// #include "platform.h"
#include "autoconf.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h> /* dirname,basename */
#include <netdb.h>
#include <paths.h>
#include <setjmp.h>
#include <signal.h>

#include <termios.h>
#include <time.h>
// #include <pwd.h>
// #include <grp.h>

#include <poll.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#define FIX_ALIASING
#define FAST_FUNC
#define UNUSED_PARAM __attribute__((__unused__))
#define NORETURN __attribute__((__noreturn__))

#define safe_strncpy strncpy
#define bb_error_msg printf

typedef struct len_and_sockaddr {
    socklen_t len;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
        struct sockaddr_in6 sin6;
#endif
    } u;
} len_and_sockaddr;

enum {
    LSA_LEN_SIZE = offsetof(len_and_sockaddr, u),
    LSA_SIZEOF_SA = sizeof(union {
        struct sockaddr sa;
        struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
        struct sockaddr_in6 sin6;
#endif
    })
};

void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
void *xzalloc(size_t size);

void xmove_fd(int from, int to);

ssize_t safe_read(int fd, void *buf, size_t count);
ssize_t full_read(int fd, void *buf, size_t len);
ssize_t read_close(int fd, void *buf, size_t size);
ssize_t open_read_close(const char *filename, void *buf, size_t size);

ssize_t safe_write(int fd, const void *buf, size_t count);
ssize_t full_write(int fd, const void *buf, size_t len);
ssize_t full_write1_str(const char *str);

int xsocket(int domain, int type, int protocol);
void xconnect(int s, const struct sockaddr *s_addr, socklen_t addrlen);

void setsockopt_reuseaddr(int fd);
int setsockopt_broadcast(int fd);
int setsockopt_keepalive(int fd);

#define bb_lookup_std_port(portstr, protocol, portnum) (portnum)
unsigned bb_lookup_port(const char *port, const char *protocol, unsigned default_port);

int create_and_connect_stream_or_die(const char *peer, int port);

#endif
