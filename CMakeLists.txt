cmake_minimum_required(VERSION 3.10)
project(libscan C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Keep CMake and Make builds consistent: binaries live in build/bin and the
# static library lives in build/lib by default.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

option(LIBSCAN_BUILD_CLI "Build the command-line scanner" ON)
option(LIBSCAN_BUILD_EXAMPLE "Build the library usage example" ON)

# Library
add_library(libscan STATIC
    src/core/libscan_core.c
    src/platform/platform.c
)

set_target_properties(libscan PROPERTIES OUTPUT_NAME scan)

target_include_directories(libscan PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(libscan PRIVATE /W4)
else()
    target_compile_options(libscan PRIVATE -Wall -Wextra -Wpedantic)
endif()

# CLI binary (can be disabled for embedded targets).
if(LIBSCAN_BUILD_CLI)
    add_executable(libscan_cli src/cli/cli.c)
    target_link_libraries(libscan_cli PRIVATE libscan)

    if(MSVC)
        target_compile_options(libscan_cli PRIVATE /W4)
    else()
        target_compile_options(libscan_cli PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

if(LIBSCAN_BUILD_EXAMPLE)
    add_executable(example examples/example.c)
    target_link_libraries(example PRIVATE libscan)

    if(MSVC)
        target_compile_options(example PRIVATE /W4)
    else()
        target_compile_options(example PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(libscan_core_api_test
        src/core/libscan_core.c
        tests/core_api_test.c
    )
    target_include_directories(libscan_core_api_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    add_executable(libscan_platform_test
        src/platform/platform.c
        tests/platform_test.c
    )
    target_include_directories(libscan_platform_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    if(MSVC)
        target_compile_options(libscan_core_api_test PRIVATE /W4)
        target_compile_options(libscan_platform_test PRIVATE /W4)
    else()
        target_compile_options(libscan_core_api_test PRIVATE -Wall -Wextra -Wpedantic)
        target_compile_options(libscan_platform_test PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME libscan_core_api COMMAND libscan_core_api_test)
    add_test(NAME libscan_platform COMMAND libscan_platform_test)
endif()

if(BUILD_TESTING AND LIBSCAN_BUILD_CLI)
    add_test(NAME libscan_cli_help COMMAND libscan_cli --help)
    set_tests_properties(libscan_cli_help PROPERTIES
        PASS_REGULAR_EXPRESSION "Usage:")
endif()
