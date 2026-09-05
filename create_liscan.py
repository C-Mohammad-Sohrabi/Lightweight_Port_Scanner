#!/usr/bin/env python3
"""Minimal embed-friendly Libscan builder (CRAS platform compat layer)."""

import os
import shutil
import sys
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent
    build = root / "build"
    embed = root / "embed"

    # Clean
    shutil.rmtree(build, ignore_errors=True)
    shutil.rmtree(embed, ignore_errors=True)

    # Create directory layout for an embedded-friendly build.
    for rel in [
        "src/core",
        "src/platform",
        "src/protocol",
        "src/cli",
        "include",
        "third_party",
        "examples",
        "tests",
        "docs",
        "tools",
    ]:
        (root / rel).mkdir(parents=True, exist_ok=True)

    # Stub a port scanner core in C.
    core_src = """\
/* libscan_core.c  -  minimal TCP SYN/connect scan engine
 *
 * Design notes:
 *   - Single-threaded scan loop with optional raw-socket fallback.
 *   - All syscalls are abstracted behind a small platform layer so the same
 *     code can run on Linux, FreeRTOS, or bare-metal CRAS without changes.
 *   - No heap allocations in the hot path; a fixed-size ring buffer is used
 *     for results so the binary stays small and deterministic.
 *
 * Public API (see include/libscan.h):
 *   libscan_init()
 *   libscan_set_targets()
 *   libscan_set_ports()
 *   libscan_set_mode()
 *   libscan_run()
 *   libscan_results()
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "libscan.h"
#include "platform.h"

/* -------------------------------------------------------------------------- */
/*  Internal scan state                                                       */
/* -------------------------------------------------------------------------- */

#define LIBSCAN_MAX_TARGETS   64
#define LIBSCAN_MAX_PORTS     1024
#define LIBSCAN_RESULT_CAP    2048

typedef struct {
    /* target IPv4 address in network byte order */
    uint32_t target_ip;
    char     target_str[16];
    bool     active;
} target_entry_t;

typedef struct {
    uint16_t port;      /* network order port number */
    bool     open;
    int      result;    /* protocol-specific status */
} scan_result_t;

typedef struct {
    target_entry_t   targets[LIBSCAN_MAX_TARGETS];
    uint16_t        ports[LIBSCAN_MAX_PORTS];
    int             n_targets;
    int             n_ports;
    scan_mode_t      mode;

    /* result ring buffer */
    scan_result_t   results[LIBSCAN_RESULT_CAP];
    int             result_head;
    int             result_tail;
    int             result_count;

    /* user-provided progress callback (can be NULL) */
    void           *user_ctx;
    libscan_progress_fn progress_cb;
} libscan_t;

/* Singleton scan context – embedded-friendly, no malloc in normal path */
static libscan_t scan_ctx;

/* -------------------------------------------------------------------------- */
/*  Internal helpers                                                          */
/* -------------------------------------------------------------------------- */

static int ring_push_result(scan_result_t entry)
{
    if (scan_ctx.result_count >= LIBSCAN_RESULT_CAP) {
        return -1; /* ring full */
    }

    scan_ctx.results[scan_ctx.result_tail] = entry;
    scan_ctx.result_tail = (scan_ctx.result_tail + 1) % LIBSCAN_RESULT_CAP;
    scan_ctx.result_count++;
    return 0;
}

static bool is_port_in_range(uint16_t port, uint16_t low, uint16_t high)
{
    return (port >= low && port <= high);
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                */
/* -------------------------------------------------------------------------- */

int libscan_init(void)
{
    scan_ctx.n_targets   = 0;
    scan_ctx.n_ports     = 0;
    scan_ctx.mode        = SCAN_MODE_CONNECT;
    scan_ctx.result_head = 0;
    scan_ctx.result_tail = 0;
    scan_ctx.result_count = 0;
    scan_ctx.user_ctx    = NULL;
    scan_ctx.progress_cb = NULL;

    platform_init();
    return 0;
}

int libscan_set_targets(const char **ips, int count)
{
    if (count > LIBSCAN_MAX_TARGETS) {
        return -1;
    }

    scan_ctx.n_targets = count;
    for (int i = 0; i < count; i++) {
        scan_ctx.targets[i].active = false;
        if (ips[i] == NULL) {
            continue;
        }
        /* Very lightweight parsing: assume dotted-quad IPv4 */
        uint32_t ip = platform_parse_ipv4(ips[i]);
        if (ip == 0) {
            continue;
        }
        scan_ctx.targets[i].target_ip  = ip;
        snprintf(scan_ctx.targets[i].target_str, sizeof(scan_ctx.targets[i].target_str), "%s", ips[i]);
        scan_ctx.targets[i].active     = true;
    }
    return 0;
}

int libscan_set_ports(const uint16_t *ports, int count)
{
    if (count > LIBSCAN_MAX_PORTS) {
        return -1;
    }
    scan_ctx.n_ports = count;
    for (int i = 0; i < count; i++) {
        scan_ctx.ports[i] = ports[i];
    }
    return 0;
}

int libscan_set_mode(scan_mode_t mode)
{
    scan_ctx.mode = mode;
    return 0;
}

void libscan_set_progress_callback(libscan_progress_fn cb, void *ctx)
{
    scan_ctx.progress_cb = cb;
    scan_ctx.user_ctx    = ctx;
}

int libscan_run(void)
{
    if (scan_ctx.n_targets == 0 || scan_ctx.n_ports == 0) {
        return -1;
    }

    int total_ops = scan_ctx.n_targets * scan_ctx.n_ports;
    int completed = 0;

    for (int t = 0; t < scan_ctx.n_targets; t++) {
        if (!scan_ctx.targets[t].active) {
            continue;
        }

        for (int p = 0; p < scan_ctx.n_ports; p++) {
            scan_result_t res = { 0 };
            res.port    = scan_ctx.ports[p];
            res.open    = false;
            res.result  = 0;

            int status = platform_scan_port(scan_ctx.targets[t].target_ip,
                                             scan_ctx.ports[p],
                                             scan_ctx.mode);
            if (status > 0) {
                res.open   = true;
                res.result = status;
            } else if (status == 0) {
                res.open   = false;
                res.result = 0;
            } else {
                /* negative status: error / filtered / timeout */
                res.open   = false;
                res.result = status;
            }

            ring_push_result(res);

            completed++;
            if (scan_ctx.progress_cb) {
                scan_ctx.progress_cb(completed, total_ops, scan_ctx.user_ctx);
            }
        }
    }
    return 0;
}

int libscan_results(scan_result_t *out, int max_out)
{
    if (out == NULL || max_out <= 0) {
        return -1;
    }

    int copied = 0;
    int idx    = scan_ctx.result_head;

    while (copied < max_out && scan_ctx.result_count > 0) {
        out[copied++] = scan_ctx.results[idx];
        idx = (idx + 1) % LIBSCAN_RESULT_CAP;
        /* keep result in buffer until user drains it */
    }

    return copied;
}

void libscan_reset_results(void)
{
    scan_ctx.result_head    = scan_ctx.result_tail;
    scan_ctx.result_count   = 0;
}

/* Lightweight target iterator for embedded UI / web front-end */
int libscan_target_count(void)
{
    return scan_ctx.n_targets;
}

const char *libscan_target_str(int idx)
{
    if (idx < 0 || idx >= scan_ctx.n_targets) {
        return NULL;
    }
    return scan_ctx.targets[idx].target_str;
}

/* -------------------------------------------------------------------------- */
/*  End of libscan_core.c                                                    */
/* -------------------------------------------------------------------------- */
"""

    (root / "src" / "core" / "libscan_core.c").write_text(core_src)

    header_src = """\
/* libscan.h  -  minimal port scanner library (embed-friendly)
 *
 * Usage:
 *   1. Call libscan_init() once at startup.
 *   2. Provide targets with libscan_set_targets().
 *   3. Provide ports with libscan_set_ports().
 *   4. Optionally select scan mode with libscan_set_mode().
 *   5. Call libscan_run() – it blocks until the scan completes.
 *   6. Retrieve results with libscan_results().
 *
 * Typical embedded flow:
 *   - Discovery stage: scan a small range like 1-1024 to find live hosts.
 *   - Audit stage: scan well-known service ports against discovered hosts.
 *   - The same binary can run on Linux for testing, on a gateway for CRAS,
 *     or on an ESP32-class device with a minimal port layer.
 */

#ifndef LIBSCAN_H
#define LIBSCAN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scan modes – pick the lightest that works on the target platform */
typedef enum {
    SCAN_MODE_CONNECT = 0,   /* plain TCP connect() – universal, no root */
    SCAN_MODE_SYN,           /* half-open SYN scan – needs raw socket / cap */
    SCAN_MODE_UDP,           /* UDP probe – noisy, best for selected ports */
    SCAN_MODE_ICMP_PING,     /* host discovery only */
} scan_mode_t;

/* Callback signature for progress reporting */
typedef void (*libscan_progress_fn)(int completed, int total, void *ctx);

/* One-shot initialisation – must be called before anything else */
int  libscan_init(void);

/* Provide target list – ips is an array of dotted-quad strings */
int  libscan_set_targets(const char **ips, int count);

/* Provide port list – explicit ports in host byte order */
int  libscan_set_ports(const uint16_t *ports, int count);

/* Set scan mode */
int  libscan_set_mode(scan_mode_t mode);

/* Optional progress callback */
void libscan_set_progress_callback(libscan_progress_fn cb, void *ctx);

/* Run the scan (blocking). Returns 0 on success. */
int libscan_run(void);

/* Drain results. Returns number of results written to `out`. */
int  libscan_results(scan_result_t *out, int max_out);

/* Clear result buffer after draining */
void libscan_reset_results(void);

/* Lightweight info helpers */
int  libscan_target_count(void);
const char *libscan_target_str(int idx);

/* Result record */
typedef struct {
    uint16_t port;   /* port in host byte order */
    bool     open;
    int      result; /* extra status: protocol response code or error */
} scan_result_t;

#ifdef __cplusplus
}
#endif

#endif /* LIBSCAN_H */
"""

    (root / "include" / "libscan.h").write_text(header_src)

    platform_stub = """\
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
    /* IPv4 TCP connect scan – universal, no special privileges needed */
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

/* SYN scan stub – on Linux you can wire this to a raw socket, but that
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

/* UDP probe stub – send a zero-byte UDP datagram and check for ICMP
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

/* -------------------------------------------------------------------------- */
/*  platform.c                                                               */
/* -------------------------------------------------------------------------- */
"""

    (root / "src" / "platform" / "platform.c").write_text(platform_stub)

    platform_hdr = """\
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
 * Returns 0 on failure, network-byte-order IP on success.
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
"""

    (root / "include" / "platform.h").write_text(platform_hdr)

    cli_src = """\
/* cli.c  -  minimal command-line frontend for libscan
 *
 * This is a deliberate throwaway layer – the library never includes it.
 * On an embedded device you would replace this with whatever interface you
 * have: UART console, WEB UI, MQTT commands, gRPC service, etc.
 *
 * For now it demonstrates the typical flow:
 *   libscan          <targets> <ports...>
 *   libscan --mode   syn  192.168.1.1 22 80 443
 *   libscan --tof    <targets> <ports...>   (table of figures output)
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
            /* table-of-figures mode – same as default but print as tabulated
             * rows for easy post-processing */
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
    libscan_set_progress_callback(
        [](int completed, int total, void *ctx) {
            (void)ctx;
            if (total > 0 && (completed % 50 == 0 || completed == total)) {
                fprintf(stderr, "\rscanning %d/%d", completed, total);
            }
        },
        NULL
    );

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
"""

    (root / "src" / "cli" / "cli.c").write_text(cli_src)

    # CRAS / freertos placeholder platform layer (stubs only)
    cras_platform = """\
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
"""

    (root / "src" / "platform" / "platform_cras.c").write_text(cras_platform)

    freertos_platform = """\
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
"""

    (root / "src" / "platform" / "platform_freertos.c").write_text(freertos_platform)

    # A small example of using the library as a library (no CLI)
    example_src = """\
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
"""

    (root / "examples" / "example.c").write_text(example_src)

    # Minimal CMakeLists.txt for host testing
    cmake = """\
cmake_minimum_required(VERSION 3.10)
project(libscan C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Library
add_library(libscan
    src/core/libscan_core.c
    src/platform/platform.c
)

target_include_directories(libscan PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# CLI binary (compile out on embedded targets)
add_executable(libscan_cli src/cli/cli.c)
target_link_libraries(libscan_cli PRIVATE libscan)

# Example
add_executable(example examples/example.c)
target_link_libraries(example PRIVATE libscan)
"""

    (root / "CMakeLists.txt").write_text(cmake)

    # Minimal Makefile in case the user does not use CMake
    makefile = """\
# Makefile – minimal portable build for host testing
# On embedded targets you normally replace this with your own toolchain make.

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -std=c11
LDFLAGS ?=

PREFIX  ?= ./build
OBJDIR  := $(PREFIX)/obj
BINDIR  := $(PREFIX)/bin

SRCS_LIB := src/core/libscan_core.c src/platform/platform.c
OBJS_LIB := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS_LIB))

CLI_SRC  := src/cli/cli.c
CLI_OBJ  := $(OBJDIR)/cli.o

EXAMPLE_SRC := examples/example.c
EXAMPLE_OBJ := $(OBJDIR)/example.o

INC      := -I include

.PHONY: all clean cli example

all: $(PREFIX)/lib/libscan.a $(BINDIR)/libscan_cli

$(OBJDIR)/%.o: %.c | $(OBJDIR)
\t$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(PREFIX)/lib/libscan.a: $(OBJS_LIB) | $(PREFIX)/lib
\tar rcs $@ $(OBJS_LIB)

$(BINDIR)/libscan_cli: $(CLI_OBJ) $(PREFIX)/lib/libscan.a | $(BINDIR)
\t$(CC) $(CFLAGS) $(CLI_OBJ) -L $(PREFIX)/lib -lscan -o $@ $(LDFLAGS)

$(BINDIR)/example: $(EXAMPLE_OBJ) $(PREFIX)/lib/libscan.a | $(BINDIR)
\t$(CC) $(CFLAGS) $(EXAMPLE_OBJ) -L $(PREFIX)/lib -lscan -o $@ $(LDFLAGS)

$(OBJDIR) $(PREFIX)/lib $(BINDIR):
\tmkdir -p $@

cli: $(BINDIR)/libscan_cli

example: $(BINDIR)/example

clean:
\trm -rf $(PREFIX)
"""

    (root / "Makefile").write_text(makefile)

    readme_md = """\
# LiScan – lightweight, embeddable port scanner

LiScan is a small, single-library port scanner written in C. It is designed to
be easy to drop into IoT firmware, CRAS platform binaries, or desktop tools,
without pulling in heavy dependencies.

## What it does

- Scans a list of IPv4 targets against a list of TCP/UDP ports.
- Supports connect-scan (universal, no root), SYN-scan (stub), and UDP-probe
  (stub) scan modes via a pluggable platform layer.
- Uses a fixed-size result ring buffer – no heap allocations in the scan loop.
- Reports progress through a callback so a UI, web front-end, or serial console
  can show live progress.

## Why it exists

- A small embedded device often needs to discover which ports are open on a
  gateway or neighbouring device, but cannot afford a full Nmap-like tool.
- The CRAS platform needs a tiny scanner that runs in a constrained environment
  without malloc-heavy code.
- The same source can be compiled on a developer's Linux machine for testing
  and then swapped to a CRAS/FreeRTOS/ESP32 platform layer for deployment.

## Architecture

    include/
      libscan.h        – public API (scan setup, run, results)
      platform.h       – platform abstraction contract

    src/core/
      libscan_core.c   – scan engine: state, loops, result ring buffer

    src/platform/
      platform.c                  – POSIX (Linux/macOS) reference implementation
      platform_cras.c             – CRAS platform drop-in
      platform_freertos.c         – FreeRTOS/lwIP drop-in

    src/cli/
      cli.c              – optional command-line front-end (can be omitted on
                            headless devices)

    examples/
      example.c          – minimal library usage without CLI

    tools/              – scripts for packaging / test generation (future)

    tests/              – unit tests (future)

## Building (host)

Using CMake:

    cmake -B build -S .
    cmake --build build
    ./build/bin/libscan_cli 192.168.1.1 22 80 443

Using Make:

    make
    ./build/bin/libscan_cli 192.168.1.1 22 80 443

On an embedded target you would not build the CLI; you would link
libscan_core.c + your platform_*.c into your firmware and call the library
API directly.

## Using the library from firmware

```c
#include "libscan.h"

const char *targets[] = { "192.168.1.1" };
uint16_t ports[] = { 22, 80, 443 };

libscan_init();
libscan_set_targets(targets, 1);
libscan_set_ports(ports, 3);
libscan_set_mode(SCAN_MODE_CONNECT);

libscan_run();

scan_result_t res[64];
int n = libscan_results(res, 64);
for (int i = 0; i < n; i++) {
    if (res[i].open) {
        // found an open port
    }
}
```

## Adding a new platform

1. Copy `src/platform/platform.c` to `src/platform/platform_mything.c`.
2. Implement `platform_scan_tcp_connect`, `platform_scan_syn`, and
   `platform_scan_udp` using your platform's networking API.
3. In your build, compile `platform_mything.c` instead of `platform.c`.
4. Keep `libscan_core.c` untouched – it only sees the `platform.h` contract.

## CRAS platform notes

- The CRAS port is started from `src/platform/platform_cras.c` – currently a
  stub so the project still builds; implement the bodies using the CRAS network
  stack when the board is available.
- Because the core engine never calls socket() or select() directly, you can
  swap the platform layer without touching the scanner logic.

## Port list formats

- You can pass an explicit list of ports via `libscan_set_ports()`.
- For range scans you can expand the range into an array yourself before
  calling the API (e.g. 1..1024).
- The engine never allocates; the caller controls memory.

## Limitations / future work

- IPv6 is not yet supported (IPv4 only today).
- SYN and UDP scan modes are stubs in the reference platform – implement them
  per platform when needed.
- No service fingerprinting or OS detection – the goal is small and fast.
- No async/distributor mode yet; for large scans you can call libscan_run()
  from a dedicated task/worker thread.

## License

This project is a small internal tool; adapt the license headers to your own
project policy before shipping.
"""

    (root / "README.md").write_text(readme_md)

    gitignore = """\
# Build artifacts
build/
embed/
*.o
*.a
*.elf
*.bin

# IDE
.vscode/
.idea/
*.swp
*~

# OS
.DS_Store
Thumbs.db

# Debug
core
*.core
"""

    (root / ".gitignore").write_text(gitignore)

    print(f"LiScan scaffold created under {root}")
    print("Files:")
    for path in sorted(root.rglob("*")):
        if path.is_file():
            print("  ", path.relative_to(root))

if __name__ == "__main__":
    main()
