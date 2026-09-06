# LiScan – lightweight, embeddable port scanner

LiScan is a small C library and optional command-line client for probing IPv4
targets.  The scan engine owns configuration and result bookkeeping; all
network operations are delegated to a replaceable platform layer.  This keeps
the core suitable for a POSIX host as well as a constrained firmware build.

## Current capabilities

- IPv4 targets only.  The parser accepts exactly four decimal octets (`0`–`255`)
  and rejects shorthand, missing components, overflow, and trailing text.
- TCP connect scanning is implemented by the reference POSIX platform with a
  non-blocking socket and a one-second deadline.  A refused port is reported as
  closed; a timeout is reported as an error/timeout result.
- `SCAN_MODE_SYN`, `SCAN_MODE_UDP`, and `SCAN_MODE_ICMP_PING` are extension
  points.  The reference POSIX platform currently returns `-EOPNOTSUPP` for
  these modes rather than pretending that a probe was performed.  A target
  platform may provide real implementations in its own `platform_*.c` file.
- Results are fixed-size FIFO records.  `libscan_results()` drains records;
  attempting a scan larger than the FIFO is rejected before network I/O, so no
  partial batch is produced.
- Every result includes the target address and scan mode, so multi-target
  output is unambiguous.

## Repository layout

```text
include/libscan.h       Public API and result/mode definitions
include/platform.h      Platform abstraction contract
src/core/libscan_core.c Configuration, scan loop, FIFO, progress callback
src/platform/platform.c POSIX IPv4 parser and TCP connect implementation
src/platform/platform_cras.c / platform_freertos.c  Platform stubs/examples
src/cli/cli.c            Optional host command-line frontend
examples/example.c       Minimal library-only usage example
create_liscan.py         Safe CMake build helper (does not generate sources)
```

## Building on a host

The two supported host build paths produce the same layout: binaries in
`build/bin/` and the static library in `build/lib/libscan.a`.

With CMake:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/bin/libscan_cli --help
```

With Make:

```sh
make
./build/bin/libscan_cli --help
make clean
```

The CMake options `-DLIBSCAN_BUILD_CLI=OFF` and
`-DLIBSCAN_BUILD_EXAMPLE=OFF` omit optional host executables.  Make supports a
custom output directory, for example `make PREFIX=out`.

The compatibility helper is equivalent to the CMake flow and is safe to run
in a working tree:

```sh
./create_liscan.py
./create_liscan.py --clean --build-type Debug
./create_liscan.py --build-dir out --target libscan_cli
```

It never deletes or rewrites source files.  `--clean` removes only the chosen
build directory, and that directory must be inside the repository.

## Command-line usage

```text
libscan_cli [--mode MODE] <target[,target...]> <port[,port...]> ...
```

Examples:

```sh
# One target and three TCP ports
./build/bin/libscan_cli 127.0.0.1 22 80 443

# Two targets and a range (inclusive)
./build/bin/libscan_cli --mode connect 192.168.1.1,192.168.1.2 22,80-82

# Probe mode names are accepted, but the default POSIX layer reports them as
# unsupported until a platform implementation is supplied.
./build/bin/libscan_cli --mode udp 192.168.1.1 53
```

Targets are comma-separated strict IPv4 dotted quads.  Port arguments are
decimal numbers from `1` through `65535`; comma-separated values and inclusive
ranges such as `8000-8003` are accepted.  At least one port is required for
all modes because the generic API models work as target × port operations.  In
ICMP mode the platform may ignore the supplied port value.

Output is tab-separated and includes target, protocol, state, platform status,
and scan mode.  For example:

```text
127.0.0.1  80/tcp  open             result=1   mode=connect
127.0.0.1  81/tcp  closed/filtered  result=0   mode=connect
```

UDP results with no confirmation are labelled `unknown/filtered`; unsupported
or timeout conditions are labelled `error`.  SYN and ICMP are not silently
reported as successful scans by the reference platform.

## Library usage

```c
#include "libscan.h"

const char *targets[] = {"192.168.1.1", "192.168.1.2"};
uint16_t ports[] = {22, 80, 443};

libscan_init();
libscan_set_targets(targets, 2);
libscan_set_ports(ports, 3);
libscan_set_mode(SCAN_MODE_CONNECT);
libscan_run();

scan_result_t result[16];
for (;;) {
    int n = libscan_results(result, 16);
    if (n <= 0) {
        break;
    }
    for (int i = 0; i < n; ++i) {
        /* result[i].target, .port, .open, .result, and .mode are available. */
    }
}
```

All setters validate their arguments and return a negative `LIBSCAN_ERR_*`
code on failure.  Call `libscan_init()` before configuration.  The progress
callback receives completed and total target×port operations.  The core is a
singleton, not thread-safe, and `libscan_run()` is blocking; applications that
need concurrency should run it in their own task/thread.

## Adding a platform implementation

Provide the functions declared in `include/platform.h` and link your platform
source instead of `src/platform/platform.c`:

1. Implement `platform_parse_ipv4_checked()` (and the legacy wrapper if your
   port uses it).
2. Implement `platform_scan_port()` plus the mode-specific functions.
3. Call `platform_init()` to bring up the target network stack if needed.
4. Keep `src/core/libscan_core.c` unchanged; it depends only on the contract.

The checked parser writes addresses in network byte order.  The legacy
`platform_parse_ipv4()` returns zero on failure, so new code should prefer a
checked form when `0.0.0.0` must be distinguished from invalid input.

## Limitations and security notes

- The reference platform does not implement raw SYN, UDP response decoding, or
  ICMP sockets.  Do not interpret `-EOPNOTSUPP` as a closed port.
- Scans are sequential and blocking.  A full 64-target × 1024-port run can be
  slow when many destinations time out.
- The result FIFO holds 2048 records.  Drain results between runs or handle
  `LIBSCAN_ERR_RESULT_OVERFLOW`.
- Only scan systems you own or are authorized to test; network probing may be
  logged or restricted by local policy.

## License

This is a small internal tool.  Adapt the license headers to your project
policy before redistribution.
