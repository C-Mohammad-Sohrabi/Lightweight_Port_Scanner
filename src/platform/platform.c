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

#include "platform.h"

/* -------------------------------------------------------------------------- */
/*  Lightweight IPv4 parser (no libcinet dependence)                         */
/* -------------------------------------------------------------------------- */

uint32_t platform_parse_ipv4(const char *str)
{
    uint32_t ip = 0;
    int      shift = 24;
    const char *p = str;
    int octet = 0;

    while (*p) {
        if (*p == '.') {
            ip |= (uint32_t)octet << shift;
            octet = 0;
            shift -= 8;
        } else if (*p >= '0' && *p <= '9') {
            octet = octet * 10 + (*p - '0');
            if (octet > 255) return 0;
        } else {
            return 0;
        }
        p++;
    }
    ip |= (uint32_t)octet; /* last octet */
    return ip;
}

/* -------------------------------------------------------------------------- */
/*  Generic TCP connect-scan implementation                                   */
/* -------------------------------------------------------------------------- */

int platform_scan_port(uint32_t ip, uint16_t port, scan_mode_t mode)
{
    (void)ip;
    if (mode == SCAN_MODE_CONNECT) {
        return platform_scan_tcp_connect(ip, port);
    }
    if (mode == SCAN_MODE_SYN) {
        return platform_scan_syn(ip, port);
    }
    if (mode == SCAN_MODE_UDP) {
        return platform_scan_udp(ip, port);
    }
    return -1;
}

int platform_scan_tcp_connect(uint32_t ip, uint16_t port)
{
    /* IPv4 TCP connect scan - universal, no special privileges needed */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = ip;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        close(fd);
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == 0) {
        close(fd);
        return 1; /* open */
    }

    if (errno != EINPROGRESS) {
        close(fd);
        return -1; /* error */
    }

    /* Wait with a short timeout */
    fd_set wfds;
    struct timeval tv;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    tv.tv_sec  = 1;
    tv.tv_usec = 0;

    ret = select(fd + 1, NULL, &wfds, NULL, &tv);
    close(fd);

    if (ret > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        int chk = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        (void)chk;
        if (err == 0) return 1; /* open */
    }

    return 0; /* closed / filtered */
}

/* SYN scan stub - on Linux you can wire this to a raw socket, but that
 * usually needs CAP_NET_RAW. Keep it as a stub so whatever platform drops
 * in can implement it later without changing the core. */
int platform_scan_syn(uint32_t ip, uint16_t port)
{
    /* Stub: fall back to connect for now.
     * On a CRAS / embedded box you would replace this with your own
     * packet crafting or use a lightweight TCP stack.
     */
    return platform_scan_tcp_connect(ip, port);
}

/* UDP probe stub - send a zero-byte UDP datagram and check for ICMP
 * Port Unreachable.  Keep it intentionally simple. */
int platform_scan_udp(uint32_t ip, uint16_t port)
{
    /* Very lightweight UDP probe.
     * A full implementation would parse ICMP errors; here we just note
     * that the port was probed.  Replace with your own logic per platform.
     */
    (void)ip;
    (void)port;
    return 0; /* unknown / filtered */
}

void platform_init(void)
{
    /* Nothing to initialise on POSIX hosts.  Embedded ports can hook setup
     * here (e.g. enable network interface, clear ring buffers, etc). */
}

/* -------------------------------------------------------------------------- */
/*  platform.c                                                               */
/* -------------------------------------------------------------------------- */
