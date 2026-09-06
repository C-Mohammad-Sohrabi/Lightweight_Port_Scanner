/* libscan_core.c - small, deterministic scan engine
 *
 * The core owns configuration and result bookkeeping. Address parsing and
 * actual network operations stay in the platform layer so this file can be
 * used unchanged on POSIX, CRAS, or an embedded network stack.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "libscan.h"
#include "platform.h"

/* -------------------------------------------------------------------------- */
/* Internal scan state                                                        */
/* -------------------------------------------------------------------------- */

#define LIBSCAN_RESULT_CAP LIBSCAN_RESULT_CAPACITY

typedef struct {
    /* Target IPv4 address in network byte order. */
    uint32_t target_ip;
    char     target_str[16];
    bool     active;
} target_entry_t;

typedef struct {
    target_entry_t      targets[LIBSCAN_MAX_TARGETS];
    uint16_t            ports[LIBSCAN_MAX_PORTS];
    int                 n_targets;
    int                 n_ports;
    scan_mode_t         mode;

    /* Fixed-size FIFO. Records are never overwritten on overflow. */
    scan_result_t       results[LIBSCAN_RESULT_CAP];
    int                 result_head;
    int                 result_tail;
    int                 result_count;
    bool                result_overflowed;

    bool                initialized;

    /* User-provided progress callback (can be NULL). */
    void               *user_ctx;
    libscan_progress_fn  progress_cb;
} libscan_t;

/* Singleton context: no heap allocation in the normal scan path. */
static libscan_t scan_ctx;

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* -------------------------------------------------------------------------- */

static int ring_push_result(const scan_result_t *entry)
{
    if (entry == NULL) {
        return LIBSCAN_ERR_INVALID_ARGUMENT;
    }
    if (scan_ctx.result_count >= LIBSCAN_RESULT_CAP) {
        /* Keep records already collected, but make loss explicit through
         * libscan_run()'s return value. */
        scan_ctx.result_overflowed = true;
        return LIBSCAN_ERR_RESULT_OVERFLOW;
    }

    scan_ctx.results[scan_ctx.result_tail] = *entry;
    scan_ctx.result_tail = (scan_ctx.result_tail + 1) % LIBSCAN_RESULT_CAP;
    scan_ctx.result_count++;
    return LIBSCAN_OK;
}

static int active_target_count(void)
{
    int active = 0;
    for (int i = 0; i < scan_ctx.n_targets; i++) {
        if (scan_ctx.targets[i].active) {
            active++;
        }
    }
    return active;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                 */
/* -------------------------------------------------------------------------- */

int libscan_init(void)
{
    memset(&scan_ctx, 0, sizeof(scan_ctx));
    scan_ctx.mode = SCAN_MODE_CONNECT;
    scan_ctx.initialized = true;

    platform_init();
    return LIBSCAN_OK;
}

int libscan_set_targets(const char **ips, int count)
{
    if (!scan_ctx.initialized) {
        return LIBSCAN_ERR_NOT_INITIALIZED;
    }
    if (count < 0 || count > LIBSCAN_MAX_TARGETS) {
        return LIBSCAN_ERR_INVALID_ARGUMENT;
    }
    if (count > 0 && ips == NULL) {
        return LIBSCAN_ERR_INVALID_ARGUMENT;
    }

    /* Validate/parse the complete input before changing active config. This
     * prevents a failed call from leaving a partially replaced list. */
    target_entry_t parsed[LIBSCAN_MAX_TARGETS];
    memset(parsed, 0, sizeof(parsed));
    for (int i = 0; i < count; i++) {
        if (ips[i] == NULL) {
            return LIBSCAN_ERR_INVALID_ARGUMENT;
        }
        if (strlen(ips[i]) >= sizeof(parsed[i].target_str)) {
            return LIBSCAN_ERR_INVALID_ARGUMENT;
        }

        uint32_t ip = 0;
        if (platform_parse_ipv4_ex(ips[i], &ip) != 0) {
            return LIBSCAN_ERR_INVALID_ARGUMENT;
        }

        parsed[i].target_ip = ip;
        (void)snprintf(parsed[i].target_str, sizeof(parsed[i].target_str),
                       "%s", ips[i]);
        parsed[i].active = true;
    }

    memset(scan_ctx.targets, 0, sizeof(scan_ctx.targets));
    if (count > 0) {
        memcpy(scan_ctx.targets, parsed,
               (size_t)count * sizeof(scan_ctx.targets[0]));
    }
    scan_ctx.n_targets = count;
    return LIBSCAN_OK;
}

int libscan_set_ports(const uint16_t *ports, int count)
{
    if (!scan_ctx.initialized) {
        return LIBSCAN_ERR_NOT_INITIALIZED;
    }
    if (count < 0 || count > LIBSCAN_MAX_PORTS) {
        return LIBSCAN_ERR_INVALID_ARGUMENT;
    }
    if (count > 0 && ports == NULL) {
        return LIBSCAN_ERR_INVALID_ARGUMENT;
    }

    /* Port zero is not a valid TCP/UDP service port. */
    for (int i = 0; i < count; i++) {
        if (ports[i] == 0) {
            return LIBSCAN_ERR_INVALID_ARGUMENT;
        }
    }

    memset(scan_ctx.ports, 0, sizeof(scan_ctx.ports));
    if (count > 0) {
        memcpy(scan_ctx.ports, ports,
               (size_t)count * sizeof(scan_ctx.ports[0]));
    }
    scan_ctx.n_ports = count;
    return LIBSCAN_OK;
}

int libscan_set_mode(scan_mode_t mode)
{
    if (!scan_ctx.initialized) {
        return LIBSCAN_ERR_NOT_INITIALIZED;
    }
    if (mode < SCAN_MODE_CONNECT || mode > SCAN_MODE_ICMP_PING) {
        return LIBSCAN_ERR_INVALID_ARGUMENT;
    }
    scan_ctx.mode = mode;
    return LIBSCAN_OK;
}

void libscan_set_progress_callback(libscan_progress_fn cb, void *ctx)
{
    scan_ctx.progress_cb = cb;
    scan_ctx.user_ctx = ctx;
}

int libscan_run(void)
{
    if (!scan_ctx.initialized) {
        return LIBSCAN_ERR_NOT_INITIALIZED;
    }
    if (scan_ctx.n_targets == 0 || scan_ctx.n_ports == 0) {
        return LIBSCAN_ERR_NOT_CONFIGURED;
    }

    /* A run is a new batch. Require callers to consume or explicitly discard
     * records from the previous batch so results from separate runs cannot be
     * confused.  No state is changed when this check fails. */
    if (scan_ctx.result_count != 0) {
        return LIBSCAN_ERR_PENDING_RESULTS;
    }

    int n_active = active_target_count();
    if (n_active == 0) {
        return LIBSCAN_ERR_NOT_CONFIGURED;
    }

    /* Limits above make this multiplication safe in an int (64 * 1024). */
    const int total_ops = n_active * scan_ctx.n_ports;
    if (total_ops > LIBSCAN_RESULT_CAP) {
        /* Refuse the batch before touching the network.  This is preferable to
         * returning a seemingly successful partial result set. */
        return LIBSCAN_ERR_RESULT_OVERFLOW;
    }

    /* An earlier overflow is acknowledged by draining/resetting the queue;
     * start the new batch with a clean status flag. */
    scan_ctx.result_overflowed = false;
    int completed = 0;

    for (int t = 0; t < scan_ctx.n_targets; t++) {
        if (!scan_ctx.targets[t].active) {
            continue;
        }

        for (int p = 0; p < scan_ctx.n_ports; p++) {
            scan_result_t res;
            memset(&res, 0, sizeof(res));
            res.port = scan_ctx.ports[p];
            res.target_ip = scan_ctx.targets[t].target_ip;
            (void)snprintf(res.target, sizeof(res.target), "%s",
                           scan_ctx.targets[t].target_str);
            res.mode = scan_ctx.mode;

            int status = platform_scan_port(scan_ctx.targets[t].target_ip,
                                            scan_ctx.ports[p], scan_ctx.mode);
            if (status > 0) {
                res.open = true;
                res.result = status;
            } else {
                /* Zero means closed/filtered; negative values preserve the
                 * platform's error/timeout code in the result record. */
                res.open = false;
                res.result = status;
            }

            (void)ring_push_result(&res);

            completed++;
            if (scan_ctx.progress_cb != NULL) {
                scan_ctx.progress_cb(completed, total_ops, scan_ctx.user_ctx);
            }
        }
    }

    return scan_ctx.result_overflowed ? LIBSCAN_ERR_RESULT_OVERFLOW
                                      : LIBSCAN_OK;
}

int libscan_results(scan_result_t *out, int max_out)
{
    if (!scan_ctx.initialized) {
        return LIBSCAN_ERR_NOT_INITIALIZED;
    }
    if (out == NULL || max_out <= 0) {
        return LIBSCAN_ERR_INVALID_ARGUMENT;
    }

    int copied = 0;
    while (copied < max_out && scan_ctx.result_count > 0) {
        out[copied] = scan_ctx.results[scan_ctx.result_head];
        scan_ctx.result_head =
            (scan_ctx.result_head + 1) % LIBSCAN_RESULT_CAP;
        scan_ctx.result_count--;
        copied++;
    }
    return copied;
}

void libscan_reset_results(void)
{
    scan_ctx.result_head = scan_ctx.result_tail;
    scan_ctx.result_count = 0;
    scan_ctx.result_overflowed = false;
}

/* Lightweight target iterator for embedded UI/web front-ends. */
int libscan_target_count(void)
{
    if (!scan_ctx.initialized) {
        return 0;
    }
    return active_target_count();
}

const char *libscan_target_str(int idx)
{
    if (!scan_ctx.initialized || idx < 0 || idx >= scan_ctx.n_targets ||
        !scan_ctx.targets[idx].active) {
        return NULL;
    }
    return scan_ctx.targets[idx].target_str;
}

/* -------------------------------------------------------------------------- */
/* End of libscan_core.c                                                      */
/* -------------------------------------------------------------------------- */
