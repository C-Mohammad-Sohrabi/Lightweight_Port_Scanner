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

/* Result record – defined first so it can be used by the API prototypes */
typedef struct {
    uint16_t port;   /* port in host byte order */
    bool     open;
    int      result; /* extra status: protocol response code or error */
} scan_result_t;

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

#ifdef __cplusplus
}
#endif

#endif /* LIBSCAN_H */
