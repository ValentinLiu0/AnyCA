#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set -euo pipefail

# Configure and build AnyCA for Linux x86_64 with
# cmake/toolchains/linux-x86_64.cmake.
#
# usage: build-linux-x86_64.sh [-h|--help] [cmake configure arguments...]
#
# environment:
#   BUILD_TYPE  CMAKE_BUILD_TYPE (default: Release)
#   BUILD_DIR   build directory (default: <repo>/build-linux-x86_64)
#   BUILD_JOBS  parallel build jobs (default: nproc)

usage() {
    cat <<'EOF'
usage: build-linux-x86_64.sh [cmake configure arguments...]

Configure and build AnyCA for Linux x86_64 with
cmake/toolchains/linux-x86_64.cmake.

environment:
  BUILD_TYPE  CMAKE_BUILD_TYPE (default: Release)
  BUILD_DIR   build directory (default: <repo>/build-linux-x86_64)
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
toolchain=$root/cmake/toolchains/linux-x86_64.cmake
build_dir=${BUILD_DIR:-"$root/build-linux-x86_64"}
build_type=${BUILD_TYPE:-Release}
jobs=${BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}

[ -f "$toolchain" ] || {
    echo "toolchain not found: $toolchain" >&2
    exit 1
}

# The toolchain compiles with the host gcc, so on another host architecture
# it silently produces binaries for that architecture instead of x86_64.
host_arch=$(uname -m)
case "$host_arch" in
    x86_64|amd64) ;;
    *)
        echo "warning: host is $host_arch; this toolchain uses the host gcc" \
            "and produces $host_arch binaries, not x86_64" >&2
        ;;
esac

echo "building AnyCA for linux-x86_64 in $build_dir"
cmake -S "$root" -B "$build_dir" \
    -DCMAKE_TOOLCHAIN_FILE="$toolchain" \
    -DCMAKE_BUILD_TYPE="$build_type" \
    "$@"
cmake --build "$build_dir" --parallel "$jobs"
