/* vi: set sw=4 ts=4: */
/*
 * Utility routines.
 *
 * Copyright (C) 2008 Bernhard Reutner-Fischer
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
#include "libbb.h"

// Die if we can't allocate size bytes of memory.
void *xmalloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL && size != 0) {
        bb_error_msg("out of memory!");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Die if we can't resize previously allocated memory.  (This returns a pointer
// to the new memory, which may or may not be the same as the old memory.
// It'll copy the contents to a new chunk and free the old one if necessary.)
void *xrealloc(void *ptr, size_t size) {
    ptr = realloc(ptr, size);
    if (ptr == NULL && size != 0) {
        bb_error_msg("out of memory!");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Die if we can't allocate and zero size bytes of memory.
void *xzalloc(size_t size) {
    void *ptr = xmalloc(size);
    memset(ptr, 0, size);
    return ptr;
}

static void xdup2(int from, int to) {
    if (dup2(from, to) != to) {
        bb_error_msg("can't duplicate file descriptor");
        exit(EXIT_FAILURE);
    }
}

// "Renumber" opened fd
void xmove_fd(int from, int to) {
    if (from == to) {
        return;
    }
    xdup2(from, to);
    close(from);
}

ssize_t safe_read(int fd, void *buf, size_t count) {
    ssize_t n = 0;

    do {
        n = read(fd, buf, count);
    } while (n < 0 && errno == EINTR);

    return n;
}

/*
 * Read all of the supplied buffer from a file.
 * This does multiple reads as necessary.
 * Returns the amount read, or -1 on an error.
 * A short read is returned on an end of file.
 */
ssize_t full_read(int fd, void *buf, size_t len) {
    ssize_t cc = 0;
    ssize_t total = 0;

    total = 0;

    while (len) {
        cc = safe_read(fd, buf, len);

        if (cc < 0) {
            if (total) {
                /* we already have some! */
                /* user can do another read to know the error code */
                return total;
            }
            return cc; /* read() returns -1 on failure. */
        }
        if (cc == 0) {
            break;
        }
        buf = ((char *)buf) + cc;
        total += cc;
        len -= cc;
    }

    return total;
}

ssize_t read_close(int fd, void *buf, size_t size) {
    /*int e;*/
    size = full_read(fd, buf, size);
    /*e = errno;*/
    close(fd);
    /*errno = e;*/
    return size;
}

ssize_t open_read_close(const char *filename, void *buf, size_t size) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        return fd;
    return read_close(fd, buf, size);
}

ssize_t safe_write(int fd, const void *buf, size_t count) {
    ssize_t n = 0;

    for (;;) {
        n = write(fd, buf, count);
        if (n >= 0 || errno != EINTR)
            break;
        /* Some callers set errno=0, are upset when they see EINTR.
     * Returning EINTR is wrong since we retry write(),
     * the "error" was transient.
     */
        errno = 0;
        /* repeat the write() */
    }

    return n;
}

/*
 * Write all of the supplied buffer out to a file.
 * This does multiple writes as necessary.
 * Returns the amount written, or -1 on an error.
 */
ssize_t full_write(int fd, const void *buf, size_t len) {
    ssize_t cc = 0;
    ssize_t total = 0;

    total = 0;

    while (len) {
        cc = safe_write(fd, buf, len);

        if (cc < 0) {
            if (total) {
                /* we already wrote some! */
                /* user can do another write to know the error code */
                return total;
            }
            return cc; /* write() returns -1 on failure. */
        }

        total += cc;
        buf = ((const char *)buf) + cc;
        len -= cc;
    }

    return total;
}

ssize_t full_write1_str(const char *str) {
    return full_write(STDOUT_FILENO, str, strlen(str));
}

// Die with an error message if we can't open a new socket.
int xsocket(int domain, int type, int protocol) {
    int r = socket(domain, type, protocol);

    if (r < 0) {
        const char *s = "INET";
        if (domain == AF_PACKET)
            s = "PACKET";
        if (domain == AF_NETLINK)
            s = "NETLINK";
        IF_FEATURE_IPV6(if (domain == AF_INET6) s = "INET6";)
        bb_error_msg("socket(AF_%s,%d,%d)", s, type, protocol);
        exit(EXIT_FAILURE);
    }

    return r;
}

void xconnect(int s, const struct sockaddr *s_addr, socklen_t addrlen) {
    if (connect(s, s_addr, addrlen) < 0) {
        close(s);
        if (s_addr->sa_family == AF_INET) {
            bb_error_msg("%s (%s)", "can't connect to remote host",
                         inet_ntoa(((struct sockaddr_in *)s_addr)->sin_addr));
        } else {
            bb_error_msg("can't connect to remote host");
        }
        exit(EXIT_FAILURE);
    }
}

static int setsockopt_int(int fd, int level, int optname, int optval) {
    return setsockopt(fd, level, optname, &optval, sizeof(int));
}

static int setsockopt_1(int fd, int level, int optname) {
    return setsockopt_int(fd, level, optname, 1);
}

static int setsockopt_SOL_SOCKET_int(int fd, int optname, int optval) {
    return setsockopt_int(fd, SOL_SOCKET, optname, optval);
}

static int setsockopt_SOL_SOCKET_1(int fd, int optname) {
    return setsockopt_SOL_SOCKET_int(fd, optname, 1);
}

void setsockopt_reuseaddr(int fd) {
    setsockopt_SOL_SOCKET_1(fd, SO_REUSEADDR);
}

int setsockopt_broadcast(int fd) {
    return setsockopt_SOL_SOCKET_1(fd, SO_BROADCAST);
}

int setsockopt_keepalive(int fd) {
    return setsockopt_SOL_SOCKET_1(fd, SO_KEEPALIVE);
}

/* Return port number for a service.
 * If "port" is a number use it as the port.
 * If "port" is a name it is looked up in /etc/services,
 * if it isnt found return default_port
 */
unsigned bb_lookup_port(const char *port, const char *protocol, unsigned default_port) {
    unsigned port_nr = default_port;
    if (port) {
        int old_errno = 0;

        /* Since this is a lib function, we're not allowed to reset errno to 0.
     * Doing so could break an app that is deferring checking of errno. */
        old_errno = errno;
        port_nr = strtoul(port, NULL, 10);
        if (errno || port_nr > 65535) {
            struct servent *tserv = getservbyname(port, protocol);
            port_nr = default_port;
            if (tserv)
                port_nr = ntohs(tserv->s_port);
        }
        errno = old_errno;
    }
    return (uint16_t)port_nr;
}

static void set_nport(struct sockaddr *sa, unsigned port) {
#if ENABLE_FEATURE_IPV6
    if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (void *)sa;
        sin6->sin6_port = port;
        return;
    }
#endif
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (void *)sa;
        sin->sin_port = port;
        return;
    }
    /* What? UNIX socket? IPX?? :) */
}

/*
 * Return NULL if string is not prefixed with key. Return pointer to the
 * first character in string after the prefix key. If key is an empty string,
 * return pointer to the beginning of string.
 */
static char *is_prefixed_with(const char *string, const char *key) {
#if 0 /* Two passes over key - probably slower */
	int len = strlen(key);
	if (strncmp(string, key, len) == 0)
		return string + len;
	return NULL;
#else /* Open-coded */
    while (*key != '\0') {
        if (*key != *string)
            return NULL;
        key++;
        string++;
    }
    return (char *)string;
#endif
}

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will remove this bit anyway */
#define DIE_ON_ERROR AI_CANONNAME

/* host: "1.2.3.4[:port]", "www.google.com[:port]"
 * port: if neither of above specifies port # */
static len_and_sockaddr *str2sockaddr(const char *host, int port, IF_FEATURE_IPV6(sa_family_t af, ) int ai_flags) {
    IF_NOT_FEATURE_IPV6(sa_family_t af = AF_INET;)
    int rc = 0;
    len_and_sockaddr *r = NULL;
    struct addrinfo *result = NULL;
    struct addrinfo *used_res = NULL;
    const char *org_host = host; /* only for error msg */
    const char *cp = NULL;
    struct addrinfo hint = {0};

    if (ENABLE_FEATURE_UNIX_LOCAL && is_prefixed_with(host, "local:")) {
        struct sockaddr_un *sun = NULL;

        r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_un));
        r->len = sizeof(struct sockaddr_un);
        r->u.sa.sa_family = AF_UNIX;
        sun = (struct sockaddr_un *)&r->u.sa;
        safe_strncpy(sun->sun_path, host + 6, sizeof(sun->sun_path));
        return r;
    }

    r = NULL;

    /* Ugly parsing of host:addr */
    if (ENABLE_FEATURE_IPV6 && host[0] == '[') {
        /* Even uglier parsing of [xx]:nn */
        host++;
        cp = strchr(host, ']');
        if (!cp || (cp[1] != ':' && cp[1] != '\0')) {
            /* Malformed: must be [xx]:nn or [xx] */
            bb_error_msg("bad address '%s'", org_host);
            if (ai_flags & DIE_ON_ERROR) {
                exit(EXIT_FAILURE);
            }
            return NULL;
        }
    } else {
        cp = strrchr(host, ':');
        if (ENABLE_FEATURE_IPV6 && cp && strchr(host, ':') != cp) {
            /* There is more than one ':' (e.g. "::1") */
            cp = NULL; /* it's not a port spec */
        }
    }
    if (cp) { /* points to ":" or "]:" */
        int sz = cp - host + 1;

        host = safe_strncpy(alloca(sz), host, sz);
        if (ENABLE_FEATURE_IPV6 && *cp != ':') {
            cp++;            /* skip ']' */
            if (*cp == '\0') /* [xx] without port */
                goto skip;
        }
        cp++; /* skip ':' */
        port = strtoul(cp, NULL, 10);
        if (errno || (unsigned)port > 0xffff) {
            bb_error_msg("bad port spec '%s'", org_host);
            if (ai_flags & DIE_ON_ERROR) {
                exit(EXIT_FAILURE);
            }
            return NULL;
        }
    skip:;
    }

    /* Next two if blocks allow to skip getaddrinfo()
   * in case host name is a numeric IP(v6) address.
   * getaddrinfo() initializes DNS resolution machinery,
   * scans network config and such - tens of syscalls.
   */
    /* If we were not asked specifically for IPv6,
   * check whether this is a numeric IPv4 */
    IF_FEATURE_IPV6(if (af != AF_INET6)) {
        struct in_addr in4;
        if (inet_aton(host, &in4) != 0) {
            r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_in));
            r->len = sizeof(struct sockaddr_in);
            r->u.sa.sa_family = AF_INET;
            r->u.sin.sin_addr = in4;
            goto set_port;
        }
    }
#if ENABLE_FEATURE_IPV6
    /* If we were not asked specifically for IPv4,
   * check whether this is a numeric IPv6 */
    if (af != AF_INET) {
        struct in6_addr in6;
        if (inet_pton(AF_INET6, host, &in6) > 0) {
            r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_in6));
            r->len = sizeof(struct sockaddr_in6);
            r->u.sa.sa_family = AF_INET6;
            r->u.sin6.sin6_addr = in6;
            goto set_port;
        }
    }
#endif

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = af;
    /* Need SOCK_STREAM, or else we get each address thrice (or more)
   * for each possible socket type (tcp,udp,raw...): */
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = ai_flags & ~DIE_ON_ERROR;
    rc = getaddrinfo(host, NULL, &hint, &result);
    if (rc || !result) {
        bb_error_msg("bad address '%s'", org_host);
        if (ai_flags & DIE_ON_ERROR) {
            exit(EXIT_FAILURE);
        }
        goto ret;
    }
    used_res = result;
#if ENABLE_FEATURE_PREFER_IPV4_ADDRESS
    while (1) {
        if (used_res->ai_family == AF_INET)
            break;
        used_res = used_res->ai_next;
        if (!used_res) {
            used_res = result;
            break;
        }
    }
#endif
    r = xmalloc(LSA_LEN_SIZE + used_res->ai_addrlen);
    r->len = used_res->ai_addrlen;
    memcpy(&r->u.sa, used_res->ai_addr, used_res->ai_addrlen);

set_port:
    set_nport(&r->u.sa, htons(port));
ret:
    if (result)
        freeaddrinfo(result);
    return r;
}

#if !ENABLE_FEATURE_IPV6
#define str2sockaddr(host, port, af, ai_flags) str2sockaddr(host, port, ai_flags)
#endif

static len_and_sockaddr *xhost2sockaddr(const char *host, int port) {
    return str2sockaddr(host, port, AF_UNSPEC, DIE_ON_ERROR);
}

int create_and_connect_stream_or_die(const char *peer, int port) {
    int fd = 0;
    len_and_sockaddr *lsa = NULL;

    lsa = xhost2sockaddr(peer, port);
    fd = xsocket(lsa->u.sa.sa_family, SOCK_STREAM, 0);
    setsockopt_reuseaddr(fd);
    xconnect(fd, &lsa->u.sa, lsa->len);
    free(lsa);
    return fd;
}