/* Core API behavior test.
 *
 * This test supplies a deterministic fake platform, so it does not need
 * network access or elevated privileges.  Build it with:
 *   cc -std=c11 -Wall -Wextra -Werror -Iinclude \
 *      src/core/libscan_core.c tests/core_api_test.c -o core_api_test
 */

#ifdef NDEBUG
#undef NDEBUG /* Keep this regression test active in Release builds. */
#endif
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "libscan.h"
#include "platform.h"

static int scan_calls;
static int last_completed;
static int last_total;

int platform_parse_ipv4_checked(const char *text, uint32_t *out)
{
    if (text == NULL || out == NULL) {
        return -1;
    }
    if (strcmp(text, "0.0.0.0") == 0) {
        *out = 0;
        return 0;
    }
    if (strcmp(text, "192.0.2.1") == 0) {
        /* The core treats this as an opaque network-order fixture. */
        *out = UINT32_C(0xC0000201);
        return 0;
    }
    return -1;
}

int platform_parse_ipv4_ex(const char *text, uint32_t *out)
{
    return platform_parse_ipv4_checked(text, out);
}

uint32_t platform_parse_ipv4(const char *text)
{
    uint32_t out = 0;
    return platform_parse_ipv4_checked(text, &out) == 0 ? out : 0;
}

void platform_init(void) {}

int platform_scan_port(uint32_t ip, uint16_t port, scan_mode_t mode)
{
    (void)ip;
    (void)mode;
    scan_calls++;
    return port == 80 ? 1 : 0;
}

int platform_scan_tcp_connect(uint32_t ip, uint16_t port)
{
    (void)ip;
    (void)port;
    return 0;
}

int platform_scan_syn(uint32_t ip, uint16_t port)
{
    (void)ip;
    (void)port;
    return 0;
}

int platform_scan_udp(uint32_t ip, uint16_t port)
{
    (void)ip;
    (void)port;
    return 0;
}

static void progress_callback(int completed, int total, void *ctx)
{
    (void)ctx;
    last_completed = completed;
    last_total = total;
}

int main(void)
{
    const char *targets[] = { "0.0.0.0", "192.0.2.1" };
    uint16_t ports[] = { 80, 81 };
    scan_result_t results[4];

    assert(libscan_set_targets(targets, 2) == LIBSCAN_ERR_NOT_INITIALIZED);
    assert(libscan_init() == LIBSCAN_OK);
    assert(libscan_set_targets(NULL, 1) == LIBSCAN_ERR_INVALID_ARGUMENT);
    assert(libscan_set_targets(targets, 2) == LIBSCAN_OK);
    assert(libscan_target_count() == 2);
    assert(strcmp(libscan_target_str(0), "0.0.0.0") == 0);
    assert(libscan_set_targets((const char *[]){ "bad" }, 1) ==
           LIBSCAN_ERR_INVALID_ARGUMENT);
    assert(libscan_target_count() == 2); /* failed setter is transactional */

    assert(libscan_set_ports((uint16_t[]){ 0 }, 1) ==
           LIBSCAN_ERR_INVALID_ARGUMENT);
    assert(libscan_set_ports(ports, 2) == LIBSCAN_OK);
    assert(libscan_set_mode((scan_mode_t)99) == LIBSCAN_ERR_INVALID_ARGUMENT);
    libscan_set_progress_callback(progress_callback, NULL);

    assert(libscan_run() == LIBSCAN_OK);
    assert(scan_calls == 4);
    assert(last_completed == 4 && last_total == 4);
    assert(libscan_run() == LIBSCAN_ERR_PENDING_RESULTS);

    assert(libscan_results(results, 2) == 2);
    assert(results[0].port == 80 && results[0].open);
    assert(strcmp(results[0].target, "0.0.0.0") == 0);
    assert(results[0].mode == SCAN_MODE_CONNECT);
    assert(libscan_results(results + 2, 2) == 2);
    assert(libscan_results(results, 1) == 0); /* real drain semantics */

    /* A batch over the fixed queue is rejected before a platform call. */
    libscan_init();
    const char *one_target[] = { "192.0.2.1" };
    uint16_t many_ports[LIBSCAN_MAX_PORTS];
    for (int i = 0; i < LIBSCAN_MAX_PORTS; i++) {
        many_ports[i] = (uint16_t)(i + 1);
    }
    assert(libscan_set_targets(one_target, 1) == LIBSCAN_OK);
    assert(libscan_set_ports(many_ports, LIBSCAN_MAX_PORTS) == LIBSCAN_OK);
    int calls_before = scan_calls;
    const char *second_target[] = { "192.0.2.1", "0.0.0.0", "192.0.2.1" };
    assert(libscan_set_targets(second_target, 3) == LIBSCAN_OK);
    assert(libscan_run() == LIBSCAN_ERR_RESULT_OVERFLOW);
    assert(scan_calls == calls_before);

    return 0;
}
