#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set -euo pipefail

# Configure and build AnyCA for Linux aarch64 with
# cmake/toolchains/linux-aarch64.cmake.
#
# usage: build-linux-aarch64.sh [-h|--help] [cmake configure arguments...]
#
# environment:
#   BUILD_TYPE  CMAKE_BUILD_TYPE (default: Release)
#   BUILD_DIR   build directory (default: <repo>/build-linux-aarch64)
#   BUILD_JOBS  parallel build jobs (default: nproc)

usage() {
    cat <<'EOF'
usage: build-linux-aarch64.sh [cmake configure arguments...]

Configure and build AnyCA for Linux aarch64 with
cmake/toolchains/linux-aarch64.cmake.

environment:
  BUILD_TYPE  CMAKE_BUILD_TYPE (default: Release)
  BUILD_DIR   build directory (default: <repo>/build-linux-aarch64)
  BUILD_JOBS  parallel build jobs (default: nproc)
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$script_dir/../.." && pwd)
toolchain=$root/cmake/toolchains/linux-aarch64.cmake
build_dir=${BUILD_DIR:-"$root/build-linux-aarch64"}
build_type=${BUILD_TYPE:-Release}
jobs=${BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}

[ -f "$toolchain" ] || {
    echo "toolchain not found: $toolchain" >&2
    exit 1
}

# The toolchain invokes the aarch64 cross compiler and fails configuration
# when it is missing, so the build can never silently target the host.
cross_cc=${AARCH64_CC:-aarch64-linux-gnu-gcc}
command -v "$cross_cc" >/dev/null 2>&1 || {
    echo "error: aarch64 cross compiler not found: $cross_cc" >&2
    echo "install gcc-aarch64-linux-gnu or set AARCH64_CC" >&2
    exit 1
}

echo "building AnyCA for linux-aarch64 in $build_dir"
cmake -S "$root" -B "$build_dir" \
    -DCMAKE_TOOLCHAIN_FILE="$toolchain" \
    -DCMAKE_BUILD_TYPE="$build_type" \
    "$@"
cmake --build "$build_dir" --parallel "$jobs"
