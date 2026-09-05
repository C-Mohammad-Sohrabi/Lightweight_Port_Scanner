/* cli.c  -  minimal command-line frontend for libscan
 *
 * This is a deliberate throwaway layer - the library never includes it.
 * On an embedded device you would replace this with whatever interface you
 * have: UART console, WEB UI, MQTT commands, gRPC service, etc.
 *
 * For now it demonstrates the typical flow:
 *   libscan          <targets> <ports...>
 *   libscan --mode   syn  192.168.1.1 22 80 443
 *
 * Because the core library has no dependencies on stdout, shell, or heap,
 * this CLI can be compiled out entirely on a headless device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "libscan.h"

static void usage(void)
{
    fprintf(stderr, "libscan - minimal port scanner (LiScan)\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  libscan <target> <port1> [port2 ...]\n");
    fprintf(stderr, "  libscan --mode syn <target> <ports...>\n");
    fprintf(stderr, "  libscan --help\n");
    fprintf(stderr, "Modes: connect (default), syn, udp, icmp\n");
}

static int parse_port(const char *s)
{
    if (s == NULL) return -1;
    long v = strtol(s, NULL, 10);
    if (v < 1 || v > 65535) return -1;
    return (int)v;
}

static void print_result(const scan_result_t *r)
{
    if (r->open)
        printf("open\t%d/tcp\n", r->port);
    else
        printf("closed\t%d/tcp\n", r->port);
}

static void progress_callback(int completed, int total, void *ctx)
{
    (void)ctx;
    if (total > 0 && (completed % 50 == 0 || completed == total)) {
        fprintf(stderr, "\rscanning %d/%d", completed, total);
    }
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage();
        return 1;
    }

    int i = 1;

    /* Parse optional flags */
    scan_mode_t mode = SCAN_MODE_CONNECT;
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "--mode") == 0) {
            i++;
            if (i >= argc) { usage(); return 1; }
            if (strcmp(argv[i], "syn") == 0)      mode = SCAN_MODE_SYN;
            else if (strcmp(argv[i], "udp") == 0) mode = SCAN_MODE_UDP;
            else if (strcmp(argv[i], "icmp") == 0) mode = SCAN_MODE_ICMP_PING;
            else { fprintf(stderr, "Unknown mode: %s\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else if (strcmp(argv[i], "--tof") == 0) {
            /* table-of-figures mode */
            mode = SCAN_MODE_CONNECT;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage();
            return 1;
        }
        i++;
    }

    if (i >= argc) {
        usage();
        return 1;
    }

    /* First positional arg = target(s) separated by comma */
    const char *target_str = argv[i];
    i++;

    /* Split comma-separated targets */
    int n_targets = 1;
    for (const char *p = target_str; *p; p++) {
        if (*p == ',') n_targets++;
    }

    const char **targets = calloc(n_targets, sizeof(const char *));
    if (targets == NULL) {
        fprintf(stderr, "Out of memory\n");
        return 1;
    }

    int idx = 0;
    char *copy = strdup(target_str);
    char *tok  = strtok(copy, ",");
    while (tok && idx < n_targets) {
        targets[idx++] = tok;
        tok = strtok(NULL, ",");
    }
    free(copy);

    /* Remaining args are ports */
    int n_ports = argc - i;
    uint16_t *ports = calloc(n_ports, sizeof(uint16_t));
    if (ports == NULL) {
        fprintf(stderr, "Out of memory\n");
        free(targets);
        return 1;
    }

    for (int j = 0; j < n_ports; j++) {
        int p = parse_port(argv[i + j]);
        if (p < 0) {
            fprintf(stderr, "Bad port: %s\n", argv[i + j]);
            free(targets);
            free(ports);
            return 1;
        }
        ports[j] = (uint16_t)p;
    }

    /* Setup and run */
    libscan_init();
    libscan_set_targets(targets, n_targets);
    libscan_set_ports(ports, n_ports);
    libscan_set_mode(mode);

    /* Simple progress callback for nicer UX on a host */
    libscan_set_progress_callback(progress_callback, NULL);

    fprintf(stderr, "\n");
    int rc = libscan_run();

    /* Print results */
    scan_result_t buf[256];
    int n = libscan_results(buf, 256);
    for (int k = 0; k < n; k++) {
        print_result(&buf[k]);
    }

    free(targets);
    free(ports);

    return rc == 0 ? 0 : 1;
}
