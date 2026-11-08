# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Cross compile instead of silently building for the host architecture.
# Override the compiler with -DCMAKE_C_COMPILER=... when the cross toolchain
# has a different prefix.
if(NOT DEFINED CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
endif()
if(NOT DEFINED CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
endif()

# The CMake configure step fails when the compiler is missing, so a host
# build can never be mistaken for an aarch64 build.
set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
