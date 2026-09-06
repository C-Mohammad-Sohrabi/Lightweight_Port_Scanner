/* platform_freertos.c  -  FreeRTOS + lwIP port layer (explicit stub)
 *
 * Drop in place of platform.c when building with FreeRTOS.
 * Implement the bodies using FreeRTOS+TCP or lwIP sockets.
 */

#include <stdint.h>
#include <errno.h>

#include "platform.h"

#ifndef EOPNOTSUPP
#ifdef ENOTSUP
#define EOPNOTSUPP ENOTSUP
#else
#define EOPNOTSUPP 95
#endif
#endif

/* This file deliberately has no FreeRTOS header dependency.  It is a
 * linkable placeholder until a product supplies its lwIP/FreeRTOS socket
 * implementation.  In particular, do not use an unqualified `portTickType`
 * declaration here: that type is port-specific and made the old stub fail to
 * compile on a clean host or on newer FreeRTOS ports. */

static uint32_t freertos_htonl(uint32_t value)
{
    const uint16_t marker = 1;
    const unsigned char *bytes = (const unsigned char *)&marker;
    if (bytes[0] == 1) {
        return ((value & UINT32_C(0x000000ff)) << 24) |
               ((value & UINT32_C(0x0000ff00)) << 8)  |
               ((value & UINT32_C(0x00ff0000)) >> 8)  |
               ((value & UINT32_C(0xff000000)) >> 24);
    }
    return value;
}

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

        while (*p >= '0' && *p <= '9') {
            if (digits >= 3) {
                return -EINVAL;
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
                return -EINVAL;
            }
        } else if (*p != '\0') {
            return -EINVAL;
        }
    }

    uint32_t host_order = (octets[0] << 24) |
                          (octets[1] << 16) |
                          (octets[2] << 8)  |
                          octets[3];
    *out = freertos_htonl(host_order);
    return 0;
}

int platform_parse_ipv4_ex(const char *str, uint32_t *out)
{
    return platform_parse_ipv4_checked(str, out);
}

uint32_t platform_parse_ipv4(const char *str)
{
    uint32_t ip = 0;
    return platform_parse_ipv4_checked(str, &ip) == 0 ? ip : 0;
}

int platform_scan_port(uint32_t ip, uint16_t port, scan_mode_t mode)
{
    if (mode == SCAN_MODE_CONNECT) {
        return platform_scan_tcp_connect(ip, port);
    }
    if (mode == SCAN_MODE_SYN) {
        return platform_scan_syn(ip, port);
    }
    if (mode == SCAN_MODE_UDP) {
        return platform_scan_udp(ip, port);
    }
    if (mode == SCAN_MODE_ICMP_PING) {
        return -EOPNOTSUPP;
    }
    (void)ip;
    (void)port;
    return -EINVAL;
}

int platform_scan_tcp_connect(uint32_t ip, uint16_t port)
{
    (void)ip;
    (void)port;
    return -EOPNOTSUPP;
}

int platform_scan_syn(uint32_t ip, uint16_t port)
{
    (void)ip;
    (void)port;
    return -EOPNOTSUPP;
}

int platform_scan_udp(uint32_t ip, uint16_t port)
{
    (void)ip;
    (void)port;
    return -EOPNOTSUPP;
}

void platform_init(void) {}

/* platform_freertos.c */
