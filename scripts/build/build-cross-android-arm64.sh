#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set -euo pipefail

# Cross-compile AnyCA for Android arm64 (arm64-v8a, API 35) with the NDK and
# cmake/toolchains/android-arm64.
#
# usage: build-android-arm64.sh [-h|--help] [cmake configure arguments...]
#
# environment:
#   ANDROID_NDK_HOME  path to the Android NDK (required)
#   BUILD_TYPE        CMAKE_BUILD_TYPE (default: Release)
#   BUILD_DIR         build directory (default: <repo>/build-android-arm64)
#   BUILD_JOBS        parallel build jobs (default: nproc)

usage() {
    cat <<'EOF'
usage: build-android-arm64.sh [cmake configure arguments...]

Cross-compile AnyCA for Android arm64 (arm64-v8a) with
cmake/toolchains/android-arm64.

environment:
  ANDROID_NDK_HOME  path to the Android NDK (required)
  BUILD_TYPE        CMAKE_BUILD_TYPE (default: Release)
  BUILD_DIR         build directory (default: <repo>/build-android-arm64)
  BUILD_JOBS        parallel build jobs (default: nproc)
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
# The android toolchain file has no .cmake extension.
toolchain=$root/cmake/toolchains/android-arm64
build_dir=${BUILD_DIR:-"$root/build-android-arm64"}
build_type=${BUILD_TYPE:-Release}
jobs=${BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}

[ -f "$toolchain" ] || {
    echo "toolchain not found: $toolchain" >&2
    exit 1
}

# The toolchain passes "$ENV{ANDROID_NDK_HOME}" to CMake as CMAKE_ANDROID_NDK.
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point at the Android NDK}"
[ -d "$ANDROID_NDK_HOME" ] || {
    echo "ANDROID_NDK_HOME is not a directory: $ANDROID_NDK_HOME" >&2
    exit 1
}

echo "building AnyCA for android-arm64 in $build_dir"
cmake -S "$root" -B "$build_dir" \
    -DCMAKE_TOOLCHAIN_FILE="$toolchain" \
    -DCMAKE_BUILD_TYPE="$build_type" \
    "$@"
cmake --build "$build_dir" --parallel "$jobs"
