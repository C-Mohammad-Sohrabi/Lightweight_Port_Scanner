/* Deterministic tests for the reference POSIX platform parser and dispatch. */

#include <arpa/inet.h>
#ifdef NDEBUG
#undef NDEBUG /* Keep this regression test active in Release builds. */
#endif
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

static void expect_invalid(const char *text)
{
    uint32_t address = UINT32_C(0xA5A5A5A5);
    assert(platform_parse_ipv4_checked(text, &address) < 0);
    assert(address == UINT32_C(0xA5A5A5A5));
}

int main(void)
{
    uint32_t address = 0;
    uint32_t parsed_network = 0;
    char text[INET_ADDRSTRLEN];
    struct in_addr in;

    assert(platform_parse_ipv4_checked("192.0.2.1", &address) == 0);
    parsed_network = address;
    in.s_addr = address;
    assert(inet_ntop(AF_INET, &in, text, sizeof(text)) != NULL);
    assert(strcmp(text, "192.0.2.1") == 0);

    assert(platform_parse_ipv4_checked("0.0.0.0", &address) == 0);
    assert(address == 0);

    expect_invalid(NULL);
    expect_invalid("");
    expect_invalid("127.1");
    expect_invalid("127.0.0");
    expect_invalid("127.0.0.1.2");
    expect_invalid("127..0.1");
    expect_invalid("256.0.0.1");
    expect_invalid("1.2.3.0000");
    expect_invalid("1.2.3.4 trailing");
    assert(platform_parse_ipv4_checked("1.2.3.4", NULL) < 0);

    assert(platform_parse_ipv4("192.0.2.1") == parsed_network);
    assert(platform_scan_port(address, 0, SCAN_MODE_CONNECT) == -EINVAL);
    assert(platform_scan_port(address, 80, SCAN_MODE_SYN) == -EOPNOTSUPP);
    assert(platform_scan_port(address, 53, SCAN_MODE_UDP) == -EOPNOTSUPP);
    assert(platform_scan_port(address, 1, SCAN_MODE_ICMP_PING) == -EOPNOTSUPP);

    return 0;
}
