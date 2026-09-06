/* cli.c - command-line frontend for libscan.
 *
 * The CLI intentionally owns all temporary argument storage until the scan
 * and result-drain operations have completed.  The library copies target
 * strings today, but keeping the storage alive here also makes the ownership
 * contract safe for platform implementations that retain the pointers.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libscan.h"

/* Use the limits exported by the default core.  The setter functions remain
 * the final authority for alternate platform/core implementations. */
#define CLI_MAX_TARGETS LIBSCAN_MAX_TARGETS
#define CLI_MAX_PORTS LIBSCAN_MAX_PORTS

static void usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage: %s [--mode MODE] <target[,target...]> <port[,port...]> ...\n"
            "\n"
            "Scan one or more IPv4 targets. Ports may be numbers or inclusive\n"
            "ranges (for example 22,80-82).\n"
            "\n"
            "Options:\n"
            "  -m, --mode MODE  connect (default), syn, udp, or icmp\n"
            "  -h, --help       show this help and exit\n"
            "  --               end options\n"
            "\n"
            "Modes:\n"
            "  connect  TCP connect scan\n"
            "  syn      SYN scan when the platform supports it; otherwise the\n"
            "           platform reports unsupported\n"
            "  udp      UDP probe; an unconfirmed response is reported as\n"
            "           unknown/filtered, not closed\n"
            "  icmp     ICMP host probe. The generic API still requires at least\n"
            "           one port argument; the platform may ignore its value.\n",
            program);
}

static char *duplicate_string(const char *src)
{
    size_t length;
    char *copy;

    if (src == NULL) {
        return NULL;
    }
    length = strlen(src);
    copy = malloc(length + 1U);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, src, length + 1U);
    return copy;
}

static char *trim_ascii_space(char *text)
{
    char *end;

    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
        text++;
    }
    end = text + strlen(text);
    while (end > text &&
           (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
            end[-1] == '\n')) {
        *--end = '\0';
    }
    return text;
}

static bool parse_mode(const char *text, scan_mode_t *mode)
{
    if (text == NULL || mode == NULL) {
        return false;
    }
    if (strcmp(text, "connect") == 0) {
        *mode = SCAN_MODE_CONNECT;
    } else if (strcmp(text, "syn") == 0) {
        *mode = SCAN_MODE_SYN;
    } else if (strcmp(text, "udp") == 0) {
        *mode = SCAN_MODE_UDP;
    } else if (strcmp(text, "icmp") == 0 || strcmp(text, "icmp-ping") == 0) {
        *mode = SCAN_MODE_ICMP_PING;
    } else {
        return false;
    }
    return true;
}

static const char *mode_name(scan_mode_t mode)
{
    switch (mode) {
    case SCAN_MODE_CONNECT:
        return "connect";
    case SCAN_MODE_SYN:
        return "syn";
    case SCAN_MODE_UDP:
        return "udp";
    case SCAN_MODE_ICMP_PING:
        return "icmp";
    default:
        return "unknown";
    }
}

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

static bool parse_port_number(const char *text, unsigned long *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || *text == '\0' || value == NULL) {
        return false;
    }
    /* Reject signs and whitespace; command-line ports should be digits only. */
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0' || parsed < 1UL ||
        parsed > 65535UL) {
        return false;
    }
    *value = parsed;
    return true;
}

static bool append_port(uint16_t **ports, size_t *count, size_t *capacity,
                        unsigned long value)
{
    uint16_t *grown;

    if (*count >= CLI_MAX_PORTS) {
        return false;
    }
    if (*count == *capacity) {
        size_t next = (*capacity == 0U) ? 16U : (*capacity * 2U);
        if (next > CLI_MAX_PORTS) {
            next = CLI_MAX_PORTS;
        }
        grown = realloc(*ports, next * sizeof(**ports));
        if (grown == NULL) {
            return false;
        }
        *ports = grown;
        *capacity = next;
    }
    (*ports)[(*count)++] = (uint16_t)value;
    return true;
}

static bool parse_port_argument(const char *argument, uint16_t **ports,
                                size_t *count, size_t *capacity)
{
    char *copy;
    char *cursor;

    if (argument == NULL || *argument == '\0') {
        return false;
    }
    copy = duplicate_string(argument);
    if (copy == NULL) {
        return false;
    }

    cursor = copy;
    while (cursor != NULL) {
        char *item = cursor;
        char *comma = strchr(cursor, ',');
        char *dash;
        unsigned long first;
        unsigned long last;

        if (comma != NULL) {
            *comma = '\0';
            cursor = comma + 1;
        } else {
            cursor = NULL;
        }
        item = trim_ascii_space(item);
        if (*item == '\0') {
            free(copy);
            return false;
        }

        dash = strchr(item, '-');
        if (dash != NULL) {
            if (strchr(dash + 1, '-') != NULL) {
                free(copy);
                return false;
            }
            *dash = '\0';
            if (!parse_port_number(trim_ascii_space(item), &first) ||
                !parse_port_number(trim_ascii_space(dash + 1), &last) ||
                first > last) {
                free(copy);
                return false;
            }
            for (unsigned long port = first; port <= last; port++) {
                if (!append_port(ports, count, capacity, port)) {
                    free(copy);
                    return false;
                }
            }
        } else {
            if (!parse_port_number(item, &first) ||
                !append_port(ports, count, capacity, first)) {
                free(copy);
                return false;
            }
        }
    }

    free(copy);
    return true;
}

static bool parse_targets(char *storage, const char **targets, size_t *count)
{
    char *cursor = storage;

    while (cursor != NULL) {
        char *item = cursor;
        char *comma = strchr(cursor, ',');
        struct in_addr address;

        if (comma != NULL) {
            *comma = '\0';
            cursor = comma + 1;
        } else {
            cursor = NULL;
        }
        item = trim_ascii_space(item);
        if (*item == '\0' || strlen(item) >= INET_ADDRSTRLEN ||
            inet_pton(AF_INET, item, &address) != 1 || *count >= CLI_MAX_TARGETS) {
            return false;
        }
        targets[(*count)++] = item;
    }
    return *count > 0U;
}

static const char *result_target(const scan_result_t *result, char *fallback)
{
    if (result->target[0] != '\0') {
        return result->target;
    }
    if (fallback == NULL ||
        inet_ntop(AF_INET, &result->target_ip, fallback, INET_ADDRSTRLEN) == NULL) {
        return "?";
    }
    return fallback;
}

static const char *result_state(const scan_result_t *result)
{
    if (result->mode == SCAN_MODE_ICMP_PING) {
        if (result->open) {
            return "alive";
        }
        return result->result < 0 ? "error" : "unreachable";
    }
    if (result->open) {
        return "open";
    }
    if (result->result < 0) {
        return "error";
    }
    if (result->mode == SCAN_MODE_UDP) {
        return "unknown/filtered";
    }
    return "closed/filtered";
}

static bool result_is_unsupported(const scan_result_t *result)
{
    if (result == NULL) {
        return false;
    }
#ifdef EOPNOTSUPP
    if (result->result == -EOPNOTSUPP) {
        return true;
    }
#endif
#if defined(ENOTSUP) && (!defined(EOPNOTSUPP) || ENOTSUP != EOPNOTSUPP)
    if (result->result == -ENOTSUP) {
        return true;
    }
#endif
    return false;
}

static void print_result(const scan_result_t *result)
{
    char fallback[INET_ADDRSTRLEN];
    const char *target = result_target(result, fallback);
    const char *protocol = protocol_name(result->mode);

    if (result->mode == SCAN_MODE_ICMP_PING) {
        printf("%s\ticmp\t%s\tresult=%d\tmode=%s\n", target,
               result_state(result), result->result, mode_name(result->mode));
    } else {
        printf("%s\t%u/%s\t%s\tresult=%d\tmode=%s\n", target,
               (unsigned)result->port, protocol, result_state(result),
               result->result, mode_name(result->mode));
    }
}

static void progress_callback(int completed, int total, void *ctx)
{
    (void)ctx;
    if (total > 0 && (completed == total || completed % 50 == 0)) {
        fprintf(stderr, "\rscanning %d/%d", completed, total);
        fflush(stderr);
    }
}

int main(int argc, char **argv)
{
    scan_mode_t mode = SCAN_MODE_CONNECT;
    char *target_storage = NULL;
    const char *targets[CLI_MAX_TARGETS];
    size_t target_count = 0U;
    uint16_t *ports = NULL;
    size_t port_count = 0U;
    size_t port_capacity = 0U;
    int positional;
    int rc = 1;
    bool saw_unsupported = false;
    bool saw_result_error = false;

    if (argc < 2) {
        usage(stderr, argv[0]);
        return 2;
    }

    positional = 1;
    while (positional < argc) {
        const char *arg = argv[positional];
        const char *mode_value = NULL;

        if (strcmp(arg, "--") == 0) {
            positional++;
            break;
        }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            usage(stdout, argv[0]);
            return 0;
        }
        if (strcmp(arg, "--mode") == 0 || strcmp(arg, "-m") == 0) {
            if (++positional >= argc) {
                fprintf(stderr, "error: %s requires connect, syn, udp, or icmp\n",
                        arg);
                usage(stderr, argv[0]);
                return 2;
            }
            mode_value = argv[positional];
        } else if (strncmp(arg, "--mode=", 7) == 0) {
            mode_value = arg + 7;
        } else if (arg[0] == '-') {
            fprintf(stderr, "error: unknown option: %s\n", arg);
            usage(stderr, argv[0]);
            return 2;
        } else {
            break;
        }

        if (!parse_mode(mode_value, &mode)) {
            fprintf(stderr, "error: unknown mode: %s\n", mode_value);
            usage(stderr, argv[0]);
            return 2;
        }
        positional++;
    }

    if (positional >= argc) {
        fprintf(stderr, "error: a target and at least one port are required\n");
        usage(stderr, argv[0]);
        return 2;
    }

    target_storage = duplicate_string(argv[positional++]);
    if (target_storage == NULL) {
        fprintf(stderr, "error: out of memory while parsing targets\n");
        goto cleanup;
    }
    if (!parse_targets(target_storage, targets, &target_count)) {
        fprintf(stderr, "error: invalid target list (IPv4 addresses expected)\n");
        goto cleanup;
    }
    if (positional >= argc) {
        fprintf(stderr, "error: at least one port is required\n");
        usage(stderr, argv[0]);
        goto cleanup;
    }
    for (; positional < argc; positional++) {
        if (!parse_port_argument(argv[positional], &ports, &port_count,
                                 &port_capacity)) {
            fprintf(stderr, "error: invalid port list: %s\n", argv[positional]);
            goto cleanup;
        }
    }
    if (port_count == 0U) {
        fprintf(stderr, "error: at least one port is required\n");
        goto cleanup;
    }
    if (target_count > (size_t)INT_MAX || port_count > (size_t)INT_MAX) {
        fprintf(stderr, "error: target or port list is too large\n");
        goto cleanup;
    }

    if (libscan_init() != 0 ||
        libscan_set_targets(targets, (int)target_count) != 0 ||
        libscan_set_ports(ports, (int)port_count) != 0 ||
        libscan_set_mode(mode) != 0) {
        fprintf(stderr, "error: failed to configure scanner\n");
        goto cleanup;
    }
    libscan_set_progress_callback(progress_callback, NULL);

    if (libscan_run() != 0) {
        fprintf(stderr, "\nerror: scan failed\n");
        goto print_results;
    }

    fprintf(stderr, "\n");
    rc = 0;

print_results:
    for (;;) {
        scan_result_t results[128];
        int result_count = libscan_results(results, (int)(sizeof(results) /
                                                           sizeof(results[0])));
        if (result_count < 0) {
            fprintf(stderr, "error: failed to retrieve scan results\n");
            rc = 1;
            break;
        }
        if (result_count == 0) {
            break;
        }
        for (int i = 0; i < result_count; i++) {
            saw_unsupported = saw_unsupported || result_is_unsupported(&results[i]);
            saw_result_error = saw_result_error || results[i].result < 0;
            print_result(&results[i]);
        }
    }

    if (saw_unsupported) {
        fprintf(stderr,
                "error: requested scan mode is unsupported by the selected platform\n");
        rc = 1;
    }
    if (saw_result_error) {
        fprintf(stderr, "error: one or more probes failed or timed out\n");
        rc = 1;
    }

cleanup:
    free(ports);
    free(target_storage);
    return rc;
}
