/* platform_cras.c  -  CRAS platform port layer (stub)
 *
 * This file is the drop-in replacement for platform.c when building for the
 * CRAS platform.  The monitor and tool-chain on the host link this instead of
 * platform.c so the same libscan_core.c can run on the device.
 *
 * On a real CRAS board you would implement these using the board's TCP stack,
 * DMA helpers, or whatever minimal network driver is available.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "platform.h"

uint32_t platform_parse_ipv4(const char *str)
{
    /* Reuse the same lightweight parser from platform.c */
    uint32_t ip = 0;
    int shift = 24;
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
    ip |= (uint32_t)octet;
    return ip;
}

int platform_scan_port(uint32_t ip, uint16_t port, scan_mode_t mode)
{
    (void)ip; (void)port; (void)mode;
    /* Placeholder: CRAS hardware will implement real probing here.
     * For now report "unknown" so builds that ship this file still link. */
    return 0;
}

int platform_scan_tcp_connect(uint32_t ip, uint16_t port) { (void)ip; (void)port; return 0; }
int platform_scan_syn(uint32_t ip, uint16_t port)        { (void)ip; (void)port; return 0; }
int platform_scan_udp(uint32_t ip, uint16_t port)        { (void)ip; (void)port; return 0; }
void platform_init(void) {}

/* platform_cras.c */
