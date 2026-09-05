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
