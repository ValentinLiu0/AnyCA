# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

cmake_minimum_required(VERSION 4.3)

# Version
# VERSION is the single source of truth for the project version.  CMake turns
# it into the version variables and into the generated anyca/version.h that
# the core, the server and the CLI include;
# scripts/linux-distro/build-deb.sh reads the same file for the package
# version.
set(ANYCA_VERSION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
file(STRINGS "${ANYCA_VERSION_FILE}" ANYCA_VERSION_STRING LIMIT_COUNT 1)
string(STRIP "${ANYCA_VERSION_STRING}" ANYCA_VERSION_STRING)
if(NOT ANYCA_VERSION_STRING MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR
        "VERSION must contain MAJOR.MINOR.PATCH, got '${ANYCA_VERSION_STRING}'")
endif()

project(anyca VERSION ${ANYCA_VERSION_STRING} LANGUAGES C)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${ANYCA_VERSION_FILE}")

set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# cl.exe has no /std:c23, and clang-cl's C frontend stays on C17 as well.
# include/anyca/osal/compat.h maps the C23 spellings used by the sources
# (nullptr, static_assert) to their C17 equivalents for both.
if(MSVC OR CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    set(CMAKE_C_STANDARD 17)
    # GCC/Clang warning flags are not valid for the MSVC frontend.
    add_compile_options(
        /W4 /we4715
        "/FI${CMAKE_CURRENT_SOURCE_DIR}/include/anyca/osal/compat.h")
    if(MSVC)
        # C11 atomics are opt-in in cl.exe.
        add_compile_options(/experimental:c11atomics)
    endif()
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    set(CMAKE_C_STANDARD 23)
    add_compile_options(-fPIC -Wall -Wextra -Wno-switch -Werror=return-type)
endif()

# Global
# The certificate and CRL builders use the ML-DSA object identifiers, which
# OpenSSL added in 3.5.
find_package(OpenSSL 3.5 REQUIRED)
find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(libwebsockets REQUIRED)

# libwebsockets 4.x exports the static library as `websockets` and the shared
# one as `websockets_shared`.  vcpkg's dynamic triplet defines only the shared
# target, while distribution packages define both; link whichever exists.
if(TARGET websockets)
    set(ANYCA_LIBWEBSOCKETS_TARGET websockets)
elseif(TARGET websockets_shared)
    set(ANYCA_LIBWEBSOCKETS_TARGET websockets_shared)
else()
    set(ANYCA_LIBWEBSOCKETS_TARGET websockets)
endif()

# libyaml: the configuration parser.  Distribution packages and vcpkg both
# provide yaml.h and the yaml library; find them directly so pkg-config is
# not required.
find_path(YAML_INCLUDE_DIR NAMES yaml.h)
find_library(YAML_LIBRARY NAMES yaml libyaml)
if(NOT YAML_INCLUDE_DIR OR NOT YAML_LIBRARY)
    message(FATAL_ERROR
        "libyaml not found.  Install the libyaml development package, or set "
        "YAML_INCLUDE_DIR and YAML_LIBRARY.")
endif()

# Version header
# The generated header carries the same version into the CLI, the server and
# the core; core_version() exposes the string at run time.
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE GIT_COMMIT_RESULT
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT GIT_COMMIT_RESULT EQUAL 0 OR "${GIT_COMMIT_HASH}" STREQUAL "")
    set(GIT_COMMIT_HASH "unknown")
endif()

# The project() version variables are the canonical accessors; the configured
# template writes them into the header.
set(ANYCA_VERSION_STRING ${PROJECT_VERSION})
set(ANYCA_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(ANYCA_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(ANYCA_VERSION_PATCH ${PROJECT_VERSION_PATCH})
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/anyca/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include/anyca/version.h"
    @ONLY)

# AnyCA targets
include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}/generated/include
    include/)

# OSAL: Operating System (platform) abstraction (memory, files, timers,
#       signals, time conversions, dynamic library loading, logging)
#
# This library carries process-wide state (the log level and error buffers),
# so it is shared: linking it into both libanyca_core and an executable would
# give each image its own copy of that state.
file(GLOB_RECURSE anyca_osal_srcs CONFIGURE_DEPENDS src/osal/*.c src/osal/*.h)
add_library(anyca_osal SHARED)
set_target_properties(anyca_osal PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS ON
    POSITION_INDEPENDENT_CODE ON)
target_sources(anyca_osal PRIVATE ${anyca_osal_srcs})
target_include_directories(anyca_osal PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(anyca_osal PUBLIC ${CMAKE_DL_LIBS} Threads::Threads)

# OSSL: OpenSSL operation abstraction (DER, ASN.1, X.509, digests, Base64)
file(GLOB_RECURSE anyca_ossl_srcs CONFIGURE_DEPENDS src/ossl/*.c src/ossl/*.h)
add_library(anyca_ossl STATIC)
set_target_properties(anyca_ossl PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_sources(anyca_ossl PRIVATE ${anyca_ossl_srcs})
target_include_directories(anyca_ossl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(anyca_ossl PUBLIC anyca_osal)
target_link_libraries(anyca_ossl PUBLIC ${OPENSSL_LIBRARIES})

# Layering: osal <- ossl <- core submodules (ca, cert, config, hsm, ocsp,
#           store, utils) <- core facade (core.c)
# src/server holds the independent HTTP transport (http_server), the OCSP
# responder (ocsp_responder), and the periodic CRL service (crl_service).
# They are not part of libanyca_core; only the server executable links
# libwebsockets.
file(GLOB_RECURSE anyca_core_srcs CONFIGURE_DEPENDS src/core/*.c src/core/*.h)
add_library(anyca_core SHARED)
set_target_properties(anyca_core PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
target_sources(anyca_core PRIVATE ${anyca_core_srcs})
target_include_directories(anyca_core PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${YAML_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/pkcs11
)
target_link_libraries(anyca_core PRIVATE ${OPENSSL_LIBRARIES})
target_link_libraries(anyca_core PRIVATE Threads::Threads)
target_link_libraries(anyca_core PRIVATE ${YAML_LIBRARY})
target_link_libraries(anyca_core PRIVATE SQLite3::SQLite3)
target_link_libraries(anyca_core PRIVATE anyca_osal)
target_link_libraries(anyca_core PRIVATE anyca_ossl)

file(GLOB_RECURSE anyca_server_srcs CONFIGURE_DEPENDS src/server/*.c src/server/*.h)
add_executable(anyca_server)
target_sources(anyca_server PRIVATE ${anyca_server_srcs})
target_include_directories(anyca_server PRIVATE
    ${LIBWEBSOCKETS_INCLUDE_DIRS}
)
target_link_libraries(anyca_server PRIVATE ${ANYCA_LIBWEBSOCKETS_TARGET})
target_link_libraries(anyca_server PRIVATE anyca_core)
target_link_libraries(anyca_server PRIVATE anyca_osal)

file(GLOB_RECURSE anyca_cli_srcs CONFIGURE_DEPENDS src/cli/*.c src/cli/*.h)
add_executable(anyca_cli)
target_sources(anyca_cli PRIVATE ${anyca_cli_srcs})
target_link_libraries(anyca_cli PRIVATE anyca_core)
target_link_libraries(anyca_cli PRIVATE anyca_ossl)
target_link_libraries(anyca_cli PRIVATE anyca_osal)

# CUnit unit tests
option(ANYCA_BUILD_TESTS "Build the CUnit unit tests" ON)
if(ANYCA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
