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
