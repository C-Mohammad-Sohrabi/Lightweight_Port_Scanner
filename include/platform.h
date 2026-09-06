/* platform.h  -  platform abstraction for libscan
 *
 * On production targets you will ship one platform_*.c per supported OS:
 *   - platform_linux.c     : POSIX sockets (default for host testing)
 *   - platform_cras.c      : CRAS platform – tiny TCP/UDP stack, no malloc
 *   - platform_freertos.c  : FreeRTOS + lwIP based port
 *   - platform_esp32.c     : ESP-IDF socket wrapper
 *
 * The scanner core only ever includes platform.h and calls these functions.
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>
#include <stdbool.h>

#include "libscan.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Parse a dotted-quad IPv4 string.
 *
 * The checked form returns 0 on success and a negative errno-style value on
 * failure.  It writes the address in network byte order to `out`; therefore
 * 0.0.0.0 is a valid address and is distinguishable from malformed input.
 */
int      platform_parse_ipv4_checked(const char *str, uint32_t *out);
/* Alias kept for ports that use the `_ex` spelling. */
int      platform_parse_ipv4_ex(const char *str, uint32_t *out);

/* Legacy form.  It returns a network-byte-order address, or 0 on failure.
 * Because 0.0.0.0 also encodes as zero, new callers should use one of the
 * checked forms above.
 */
uint32_t platform_parse_ipv4(const char *str);

/* Scan a single port on a single target.
 * `mode` selects the technique.  Return >0 for open, 0 for closed/filtered,
 * <0 for error/timeout.
 */
int platform_scan_port(uint32_t ip, uint16_t port, scan_mode_t mode);

/* Concrete implementations – platform.c or a drop-in replacement must define
 * at least one of these.  The default platform.c provides connect-scan. */
int platform_scan_tcp_connect(uint32_t ip, uint16_t port);
int platform_scan_syn(uint32_t ip, uint16_t port);
int platform_scan_udp(uint32_t ip, uint16_t port);

/* Optional platform initialisation – called by libscan_init() */
void platform_init(void);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_H */
