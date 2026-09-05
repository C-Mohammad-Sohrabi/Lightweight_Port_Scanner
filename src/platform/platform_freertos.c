/* platform_freertos.c  -  FreeRTOS + lwIP port layer (stub)
 *
 * Drop in place of platform.c when building with FreeRTOS.
 * Implement the bodies using FreeRTOS+TCP or lwIP sockets.
 */

#include <stdint.h>
#include <stdbool.h>

#include "platform.h"

/* FreeRTOS tick-based millisecond delay helper (platform hook) */
extern void vTaskDelayMs(portTickType ms); /* defined by your FreeRTOS port */

uint32_t platform_parse_ipv4(const char *str) { return 0; }
int      platform_scan_port(uint32_t ip, uint16_t port, scan_mode_t mode)
{
    (void)ip; (void)port; (void)mode;
    return 0;
}
int platform_scan_tcp_connect(uint32_t ip, uint16_t port) { (void)ip; (void)port; return 0; }
int platform_scan_syn(uint32_t ip, uint16_t port)        { (void)ip; (void)port; return 0; }
int platform_scan_udp(uint32_t ip, uint16_t port)        { (void)ip; (void)port; return 0; }
void platform_init(void) {}

/* platform_freertos.c */
