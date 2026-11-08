# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

if(WIN32)
    message(STATUS "CUnit unit tests are POSIX-only")
    return()
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(CUNIT QUIET IMPORTED_TARGET cunit)
endif()

if(NOT CUNIT_FOUND)
    message(STATUS "CUnit not found; unit tests are disabled")
    return()
endif()

file(GLOB osal_tests CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/osal/*.c)
add_executable(anyca_test_osal ${osal_tests})
target_link_libraries(anyca_test_osal PRIVATE anyca_osal PkgConfig::CUNIT)
add_test(NAME osal COMMAND anyca_test_osal)

file(GLOB ossl_tests CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ossl/*.c)
add_executable(anyca_test_ossl ${ossl_tests}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_support.c)
target_include_directories(anyca_test_ossl PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(anyca_test_ossl PRIVATE
    anyca_ossl ${OPENSSL_LIBRARIES} PkgConfig::CUNIT)
add_test(NAME ossl COMMAND anyca_test_ossl)

file(GLOB core_tests CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/*.c)
add_executable(anyca_test_core ${core_tests}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_support.c)
target_include_directories(anyca_test_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(anyca_test_core PRIVATE
    anyca_core anyca_ossl ${OPENSSL_LIBRARIES} PkgConfig::CUNIT)
add_test(NAME core COMMAND anyca_test_core)

# Server-side helpers (URI parsing, OCSP error responses and the CRL
# schedule) are static, so the HTTP implementation is compiled into this test
# translation unit; the responder and scheduler are linked normally.
file(GLOB server_tests CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/server/*.c)
add_executable(anyca_test_server ${server_tests}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/server/ocsp_responder.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/server/crl_service.c)
target_include_directories(anyca_test_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/server
    ${LIBWEBSOCKETS_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR})
target_link_libraries(anyca_test_server PRIVATE
    anyca_core anyca_ossl ${OPENSSL_LIBRARIES}
    ${ANYCA_LIBWEBSOCKETS_TARGET} PkgConfig::CUNIT)
add_test(NAME server COMMAND anyca_test_server)
