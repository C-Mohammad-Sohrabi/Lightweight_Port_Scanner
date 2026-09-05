/* example.c  -  minimal library usage example (no CLI dependency)
 *
 * Build this alongside libscan and you get a tiny embedded binary that can
 * scan a single host's common ports without any shell logic.
 */

#include <stdio.h>
#include <stdint.h>
#include "libscan.h"

int main(void)
{
    const char *targets[] = { "192.168.1.1" };
    uint16_t ports[] = { 22, 80, 443, 8080 };

    libscan_init();
    libscan_set_targets(targets, 1);
    libscan_set_ports(ports, 4);
    libscan_set_mode(SCAN_MODE_CONNECT);

    libscan_run();

    scan_result_t res[64];
    int n = libscan_results(res, 64);
    for (int i = 0; i < n; i++) {
        printf("%d/tcp %s\n",
               res[i].port,
               res[i].open ? "open" : "closed");
    }

    return 0;
}
