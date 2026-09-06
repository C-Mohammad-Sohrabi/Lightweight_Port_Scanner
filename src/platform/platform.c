/* platform.c  -  abstraction layer between scan engine and OS
 *
 * This file is intentionally tiny and swappable. On a desktop Linux box it
 * uses standard POSIX sockets. On a CRAS platform you replace the bodies in
 * platform_cras.c (or platform_freertos.c) and link that instead of this
 * file. The header platform.h defines the contract.
 *
 * The key idea is that libscan_core.c never calls socket()/connect() directly;
 * it only calls platform_scan_port(). That keeps the engine portable and lets
 * you drop in a tiny platform layer for an IoT or CRAS target without touching
 * the scanner logic.
 */

/* Expose the POSIX declarations used below when a strict C standard is
 * selected (notably CLOCK_MONOTONIC on glibc-based systems). */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>

#include "platform.h"

#ifndef EOPNOTSUPP
#ifdef ENOTSUP
#define EOPNOTSUPP ENOTSUP
#else
#define EOPNOTSUPP 95
#endif
#endif

/* -------------------------------------------------------------------------- */
/*  Lightweight, strict IPv4 parser                                          */
/* -------------------------------------------------------------------------- */

/*
 * Parse exactly four decimal octets.  We deliberately do not use inet_aton:
 * its historical shorthand/octal forms accept strings that are surprising
 * in a scanner (for example, "127.1" or "010.0.0.1").
 */
int platform_parse_ipv4_checked(const char *str, uint32_t *out)
{
    uint32_t octets[4];
    const char *p = str;

    if (str == NULL || out == NULL || *str == '\0') {
        return -EINVAL;
    }

    for (int i = 0; i < 4; i++) {
        unsigned value = 0;
        unsigned digits = 0;

        /* Every component must contain at least one digit. */
        while (*p >= '0' && *p <= '9') {
            if (digits >= 3) {
                return -EINVAL; /* avoid accepting oversized components */
            }
            value = value * 10U + (unsigned)(*p - '0');
            digits++;
            p++;
        }

        if (digits == 0 || value > 255U) {
            return -EINVAL;
        }
        octets[i] = value;

        if (i < 3) {
            if (*p != '.') {
                return -EINVAL;
            }
            p++;
            if (*p == '\0') {
                return -EINVAL; /* trailing dot */
            }
        } else if (*p != '\0') {
            return -EINVAL; /* extra component or other trailing text */
        }
    }

    /* Build in host order, then explicitly convert to network byte order. */
    uint32_t host_order = (octets[0] << 24) |
                          (octets[1] << 16) |
                          (octets[2] << 8)  |
                          octets[3];
    *out = htonl(host_order);
    return 0;
}

int platform_parse_ipv4_ex(const char *str, uint32_t *out)
{
    return platform_parse_ipv4_checked(str, out);
}

uint32_t platform_parse_ipv4(const char *str)
{
    uint32_t ip = 0;
    if (platform_parse_ipv4_checked(str, &ip) != 0) {
        return 0;
    }
    return ip;
}

/* -------------------------------------------------------------------------- */
/*  Generic TCP connect-scan implementation                                   */
/* -------------------------------------------------------------------------- */

int platform_scan_port(uint32_t ip, uint16_t port, scan_mode_t mode)
{
    if (port == 0) {
        return -EINVAL;
    }
    if (mode == SCAN_MODE_CONNECT) {
        return platform_scan_tcp_connect(ip, port);
    }

    /* This host implementation intentionally makes no false claims: raw SYN,
     * UDP/ICMP probing are not implemented by this portable socket layer. */
    if (mode == SCAN_MODE_SYN) {
        return platform_scan_syn(ip, port);
    }
    if (mode == SCAN_MODE_UDP) {
        return platform_scan_udp(ip, port);
    }
    if (mode == SCAN_MODE_ICMP_PING) {
        return -EOPNOTSUPP;
    }
    return -EINVAL;
}

static int classify_connect_error(int error_code)
{
    switch (error_code) {
    case 0:
        return 1;             /* connected: port is open */
    case ECONNREFUSED:
        return 0;             /* a live host actively rejected the port */
    case ETIMEDOUT:
        return -ETIMEDOUT;
    default:
        return -error_code;
    }
}

static int64_t monotonic_millis(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        /* Some older libc implementations lack CLOCK_MONOTONIC.  Wall-clock
         * time is a less ideal fallback, but still gives EINTR handling a
         * bounded deadline rather than retrying forever. */
        struct timeval tv;
        if (gettimeofday(&tv, NULL) != 0) {
            return -1;
        }
        return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    }
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int platform_scan_tcp_connect(uint32_t ip, uint16_t port)
{
    if (port == 0) {
        return -EINVAL;
    }
    /* IPv4 TCP connect scan - universal, no special privileges needed */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = ip;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        int saved_errno = errno;
        close(fd);
        return -saved_errno;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        int saved_errno = errno;
        close(fd);
        return -saved_errno;
    }

    /* Keep a one-second total deadline, including EINTR retries. */
    const int timeout_ms = 1000;
    const int64_t start_ms = monotonic_millis();
    const bool have_clock = (start_ms >= 0);

    for (;;) {
        int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret == 0) {
            (void)close(fd);
            return 1; /* open */
        }

        int connect_errno = errno;
        if (connect_errno == EISCONN) {
            (void)close(fd);
            return 1;
        }
        if (connect_errno == EINTR) {
            if (have_clock) {
                int64_t now_ms = monotonic_millis();
                if (now_ms < 0 || now_ms - start_ms >= timeout_ms) {
                    (void)close(fd);
                    return -ETIMEDOUT;
                }
            }
            continue;
        }
        if (connect_errno != EINPROGRESS && connect_errno != EALREADY) {
            int status = classify_connect_error(connect_errno);
            (void)close(fd);
            return status;
        }
        break;
    }

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT | POLLERR | POLLHUP;

    for (;;) {
        int wait_ms = timeout_ms;
        if (have_clock) {
            int64_t now_ms = monotonic_millis();
            if (now_ms < 0) {
                /* Clock failure should not turn a closed port into "open". */
                (void)close(fd);
                return -EIO;
            }
            int64_t remaining = (int64_t)timeout_ms - (now_ms - start_ms);
            if (remaining <= 0) {
                (void)close(fd);
                return -ETIMEDOUT;
            }
            wait_ms = (remaining > INT32_MAX) ? INT32_MAX : (int)remaining;
        }

        int ret = poll(&pfd, 1, wait_ms);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        if (ret == 0) {
            (void)close(fd);
            return -ETIMEDOUT;
        }
        if (ret < 0) {
            int saved_errno = errno;
            (void)close(fd);
            return -saved_errno;
        }

        if (pfd.revents & POLLNVAL) {
            (void)close(fd);
            return -EBADF;
        }

        /* SO_ERROR must be read while the descriptor is still open. */
        int socket_error = 0;
        socklen_t error_len = sizeof(socket_error);
        for (;;) {
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                           &socket_error, &error_len) == 0) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            int saved_errno = errno;
            (void)close(fd);
            return -saved_errno;
        }

        int status = classify_connect_error(socket_error);
        (void)close(fd);
        return status;
    }
}

/* SYN scanning needs raw packet support (and usually CAP_NET_RAW), which is
 * intentionally outside this portable socket layer. */
int platform_scan_syn(uint32_t ip, uint16_t port)
{
    (void)ip;
    (void)port;
    return -EOPNOTSUPP;
}

/* UDP probing requires protocol-specific response/ICMP handling and is not
 * implemented by this layer. */
int platform_scan_udp(uint32_t ip, uint16_t port)
{
    (void)ip;
    (void)port;
    return -EOPNOTSUPP;
}

void platform_init(void)
{
    /* Nothing to initialise on POSIX hosts.  Embedded ports can hook setup
     * here (e.g. enable network interface, clear ring buffers, etc). */
}

/* -------------------------------------------------------------------------- */
/*  platform.c                                                               */
/* -------------------------------------------------------------------------- */
