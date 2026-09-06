/* example.c  -  minimal library usage example (no CLI dependency)
 *
 * Build this alongside libscan and you get a tiny embedded binary that can
 * scan a single host's common ports without any shell logic.
 */

#include <stdio.h>
#include <stdint.h>
#include "libscan.h"

static const char *protocol_name(scan_mode_t mode)
{
    switch (mode) {
    case SCAN_MODE_UDP:
        return "udp";
    case SCAN_MODE_ICMP_PING:
        return "icmp";
    case SCAN_MODE_CONNECT:
    case SCAN_MODE_SYN:
    default:
        return "tcp";
    }
}

int main(void)
{
    const char *targets[] = { "192.168.1.1" };
    uint16_t ports[] = { 22, 80, 443, 8080 };

    if (libscan_init() != LIBSCAN_OK ||
        libscan_set_targets(targets, 1) != LIBSCAN_OK ||
        libscan_set_ports(ports, 4) != LIBSCAN_OK ||
        libscan_set_mode(SCAN_MODE_CONNECT) != LIBSCAN_OK) {
        fprintf(stderr, "failed to configure scanner\n");
        return 1;
    }

    int run_status = libscan_run();
    if (run_status != LIBSCAN_OK) {
        fprintf(stderr, "scan failed (status %d)\n", run_status);
        return 1;
    }

    bool saw_error = false;
    /* libscan_results() is a drain API; loop until the queue is empty. */
    for (;;) {
        scan_result_t res[64];
        int n = libscan_results(res, (int)(sizeof(res) / sizeof(res[0])));
        if (n < 0) {
            fprintf(stderr, "failed to retrieve scan results (status %d)\n", n);
            return 1;
        }
        if (n == 0) {
            break;
        }
        for (int i = 0; i < n; i++) {
            saw_error = saw_error || res[i].result < 0;
            const char *state = res[i].result < 0
                                    ? "error"
                                    : (res[i].open ? "open" : "closed/filtered");
            printf("%s\t%u/%s\t%s\tresult=%d\n",
                   res[i].target,
                   (unsigned)res[i].port,
                   protocol_name(res[i].mode),
                   state,
                   res[i].result);
        }
    }

    return saw_error ? 1 : 0;
}
