#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set -euo pipefail

# Build AnyCA and package it as a Debian .deb.
#
# The build runs through scripts/build/build-native-linux-<arch>.sh.  The
# binaries, shared libraries, default configuration and systemd unit are then
# staged into a temporary root and packed with dpkg-deb.
#
# usage: build-deb.sh [-h|--help] [options]
#
# options:
#   -a, --arch <arch>       target Debian architecture: amd64, arm64
#                           (default: host architecture)
#       --version <version> package version, for example 0.1.0-1
#                           (default: VERSION + git hash)
#       --output-dir <dir>  directory for the .deb (default: <repo>/dist)
#       --no-build          package BUILD_DIR without running the build
#       --keep-staging      keep the staging tree after packaging
#
# environment:
#   BUILD_DIR    build directory (default: <repo>/build-deb-<arch>)
#   BUILD_TYPE   CMAKE_BUILD_TYPE passed to the build script (default: Release)
#   BUILD_JOBS   parallel build jobs (default: nproc in the build script)
#   DEB_ARCH     same as --arch
#   DEB_VERSION  same as --version
#   DEB_DEPENDS  override the dependency list (default: dpkg-shlibdeps)
#   MAINTAINER   Maintainer field (default: git user name and email)
#   OUTPUT_DIR   same as --output-dir
#   STRIP        strip tool (default: strip, or the matching cross strip tool)

usage() {
    cat <<'EOF'
usage: build-deb.sh [-h|--help] [options]

Build AnyCA with scripts/build/build-native-linux-<arch>.sh and pack the
result into a Debian .deb.

options:
  -a, --arch <arch>       target Debian architecture: amd64, arm64
                          (default: host architecture)
      --version <version> package version, for example 0.1.0-1
                          (default: VERSION + git hash)
      --output-dir <dir>  directory for the .deb (default: <repo>/dist)
      --no-build          package BUILD_DIR without running the build
      --keep-staging      keep the staging tree after packaging

environment:
  BUILD_DIR    build directory (default: <repo>/build-deb-<arch>)
  BUILD_TYPE   CMAKE_BUILD_TYPE passed to the build script (default: Release)
  BUILD_JOBS   parallel build jobs (default: nproc in the build script)
  DEB_ARCH     same as --arch
  DEB_VERSION  same as --version
  DEB_DEPENDS  override the dependency list (default: dpkg-shlibdeps)
  MAINTAINER   Maintainer field (default: git user name and email)
  OUTPUT_DIR   same as --output-dir
  STRIP        strip tool (default: strip, or the matching cross strip tool)
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

warn() {
    echo "warning: $*" >&2
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

arch=${DEB_ARCH:-}
version=${DEB_VERSION:-}
output_dir=${OUTPUT_DIR:-}
do_build=1
keep_staging=0

while [ $# -gt 0 ]; do
    case "$1" in
        -a|--arch)
            [ $# -ge 2 ] || die "$1 needs a value"
            arch=$2
            shift 2
            ;;
        --arch=*)
            arch=${1#*=}
            shift
            ;;
        --version)
            [ $# -ge 2 ] || die "$1 needs a value"
            version=$2
            shift 2
            ;;
        --version=*)
            version=${1#*=}
            shift
            ;;
        --output-dir)
            [ $# -ge 2 ] || die "$1 needs a value"
            output_dir=$2
            shift 2
            ;;
        --output-dir=*)
            output_dir=${1#*=}
            shift
            ;;
        --no-build)
            do_build=0
            shift
            ;;
        --keep-staging)
            keep_staging=1
            shift
            ;;
        -*)
            die "unknown option: $1 (try --help)"
            ;;
        *)
            die "unexpected argument: $1 (try --help)"
            ;;
    esac
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$script_dir/../.." && pwd)
host_arch=$(uname -m)

if [ -z "$arch" ]; then
    if command -v dpkg >/dev/null 2>&1; then
        arch=$(dpkg --print-architecture)
    else
        arch=$host_arch
    fi
fi

case "$arch" in
    amd64|x86_64|x64)
        deb_arch=amd64
        build_arch=x86_64
        multiarch=x86_64-linux-gnu
        ;;
    arm64|aarch64)
        deb_arch=arm64
        build_arch=aarch64
        multiarch=aarch64-linux-gnu
        ;;
    *)
        die "unsupported architecture: $arch (expected amd64 or arm64)"
        ;;
esac

build_script=$root/scripts/build/build-native-linux-$build_arch.sh
build_dir=${BUILD_DIR:-"$root/build-deb-$build_arch"}
build_type=${BUILD_TYPE:-Release}
[ -n "$output_dir" ] || output_dir=$root/dist

command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb not found"
[ -f "$build_script" ] || die "build script not found: $build_script"

# Package version: the project version from VERSION plus the git short hash,
# so two builds from different commits never compare equal.
if [ -z "$version" ]; then
    [ -f "$root/VERSION" ] || die "VERSION file not found: $root/VERSION"
    upstream=$(sed -n '1p' "$root/VERSION")
    upstream=${upstream//[[:space:]]/}
    [[ $upstream =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        die "invalid version in $root/VERSION: $upstream"

    commit=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || true)
    [ -n "$commit" ] && upstream=$upstream+git$commit
    version=$upstream-1
fi

case "$version" in
    *[[:space:]/]*)
        die "invalid version: $version"
        ;;
esac

maintainer=${MAINTAINER:-}
if [ -z "$maintainer" ]; then
    name=$(git -C "$root" config user.name 2>/dev/null || true)
    email=$(git -C "$root" config user.email 2>/dev/null || true)
    if [ -n "$name" ] && [ -n "$email" ]; then
        maintainer="$name <$email>"
    else
        maintainer="AnyCA Maintainers <anyca@localhost>"
    fi
fi

if [ "$do_build" -eq 1 ]; then
    echo "==> building anyca for linux-$build_arch in $build_dir"
    # The package installs the shared libraries into the multiarch directory,
    # so the build-tree rpath is not needed and must not leak into the .deb.
    BUILD_DIR=$build_dir BUILD_TYPE=$build_type "$build_script" \
        -DCMAKE_SKIP_RPATH=ON \
        -DANYCA_BUILD_TESTS=OFF
else
    echo "==> packaging existing build in $build_dir"
fi

for artifact in anyca_cli anyca_server libanyca_core.so libanyca_osal.so; do
    [ -f "$build_dir/$artifact" ] ||
        die "missing build artifact: $build_dir/$artifact"
done

work=$(mktemp -d "${TMPDIR:-/tmp}/anyca-deb.XXXXXX")
staging=$work/root
mkdir -p "$staging"

cleanup() {
    if [ "$keep_staging" -eq 1 ]; then
        echo "staging tree kept at $staging" >&2
    else
        rm -rf "$work"
    fi
}
trap cleanup EXIT

echo "==> staging package tree"
libdir=$staging/usr/lib/$multiarch
docdir=$staging/usr/share/doc/anyca

install -d "$staging/usr/bin" "$libdir" "$docdir/example" \
    "$staging/etc/anyca" "$staging/usr/lib/systemd/system"
install -m 0755 "$build_dir/anyca_cli" "$staging/usr/bin/anyca_cli"
install -m 0755 "$build_dir/anyca_server" "$staging/usr/bin/anyca_server"
install -m 0644 "$build_dir/libanyca_core.so" "$libdir/libanyca_core.so"
install -m 0644 "$build_dir/libanyca_osal.so" "$libdir/libanyca_osal.so"

# Strip the build-tree rpath when the build directory was produced without
# -DCMAKE_SKIP_RPATH=ON (for example with --no-build).
remove_rpath() {
    local file=$1
    command -v readelf >/dev/null 2>&1 || return 0
    readelf -d "$file" 2>/dev/null | grep -qE '\((RUNPATH|RPATH)\)' || return 0
    if command -v patchelf >/dev/null 2>&1; then
        patchelf --remove-rpath "$file"
    elif command -v chrpath >/dev/null 2>&1; then
        chrpath -d "$file" >/dev/null 2>&1 || true
    else
        warn "$file keeps a build-tree rpath; install patchelf or chrpath" \
            "to remove it"
    fi
}

for file in "$staging/usr/bin/anyca_cli" "$staging/usr/bin/anyca_server" \
    "$libdir/libanyca_core.so" "$libdir/libanyca_osal.so"; do
    remove_rpath "$file"
done

# Host strip cannot handle foreign ELF files, so a cross build needs the
# matching cross strip tool or no stripping at all.
strip_tool=${STRIP:-}
if [ -z "$strip_tool" ]; then
    if [ "$build_arch" = "$host_arch" ]; then
        strip_tool=strip
    else
        strip_tool=$(command -v "$build_arch-linux-gnu-strip" 2>/dev/null || true)
    fi
fi
if [ -n "$strip_tool" ] && command -v "$strip_tool" >/dev/null 2>&1; then
    echo "==> stripping binaries with $strip_tool"
    "$strip_tool" --strip-unneeded \
        "$staging/usr/bin/anyca_cli" "$staging/usr/bin/anyca_server" \
        "$libdir/libanyca_core.so" "$libdir/libanyca_osal.so" || true
else
    warn "no $build_arch strip tool found; binaries are not stripped"
fi

echo "==> installing configuration and documentation"

# Absolute paths keep the server and anyca_cli on the same state regardless
# of the working directory.
cat > "$staging/etc/anyca/config.yaml" <<'EOF'
# AnyCA configuration installed by the anyca Debian package.
#
# The annotated example is /usr/share/doc/anyca/example/config.yaml and the
# deployment guide is /usr/share/doc/anyca/DEPLOY.md.
#
# Absolute paths make the server and anyca_cli resolve the same store,
# revocation and publication files regardless of the working directory.

store:
  path: "/var/lib/anyca/store.db"

http:
  address: "0.0.0.0"
  port: 8080

crl_publish_path: "/var/lib/anyca/crl"
cacerts_publish_path: "/var/lib/anyca/cacerts"

hsm_providers:
  - name: "softhsm"
    model: "SoftHSM v2"
    library: "/usr/lib/softhsm/libsofthsm2.so"
EOF

cat > "$staging/usr/lib/systemd/system/anyca.service" <<'EOF'
[Unit]
Description=AnyCA OCSP responder
Documentation=file:///usr/share/doc/anyca/DEPLOY.md
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/anyca/config.yaml

[Service]
Type=simple
User=anyca
Group=anyca
WorkingDirectory=/var/lib/anyca
ExecStart=/usr/bin/anyca_server -c /etc/anyca/config.yaml
Restart=on-failure
RestartSec=2
LimitNOFILE=4096
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/anyca
# SoftHSM falls back to /etc/softhsm/softhsm2.conf.  When the tokens use a
# different configuration file, set it here or in a drop-in:
#Environment=SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

[Install]
WantedBy=multi-user.target
EOF

install -m 0644 "$root/README.md" "$docdir/README.md"
install -m 0644 "$root/README.zh-CN.md" "$docdir/README.zh-CN.md"
install -m 0644 "$root/docs/CLI.md" "$docdir/CLI.md"
install -m 0644 "$root/docs/CLI.zh-CN.md" "$docdir/CLI.zh-CN.md"
install -m 0644 "$root/docs/DEPLOY.md" "$docdir/DEPLOY.md"
install -m 0644 "$root/docs/DEPLOY.zh-CN.md" "$docdir/DEPLOY.zh-CN.md"
install -m 0644 "$root/docs/example/config.yaml" "$docdir/example/config.yaml"

commit=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || true)
[ -n "$commit" ] || commit=unknown
cat > "$docdir/changelog.Debian" <<EOF
anyca ($version) unstable; urgency=medium

  * Local package built from commit $commit.

 -- $maintainer  $(LC_ALL=C date -R)
EOF
gzip -9n "$docdir/changelog.Debian"

# The upstream tree has no license file, so only the bundled third-party
# material is recorded here.
cat > "$docdir/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: AnyCA

Comment: The upstream source tree contains no license file and states no
 license for the AnyCA code. This file only records the licenses of the
 bundled third-party material.

Files: third_party/pkcs11/*
Copyright: latchset/pkcs11-headers contributors
License: public-domain
 The PKCS #11 3.2 headers are distributed as public domain by
 https://github.com/latchset/pkcs11-headers.
EOF

echo "==> writing package metadata"
installed_size=$(du -sk "$staging" | cut -f1)

depends=${DEB_DEPENDS:-}
if [ -z "$depends" ] && command -v dpkg-shlibdeps >/dev/null 2>&1; then
    # dpkg-shlibdeps insists on a debian/control; this throws it away again.
    mkdir -p "$staging/debian"
    cat > "$staging/debian/control" <<EOF
Source: anyca
Section: admin
Priority: optional
Maintainer: $maintainer
Standards-Version: 4.6.2

Package: anyca
Architecture: any
Description: dependency helper
 dependency helper
EOF
    if shlibs=$(cd "$staging" && dpkg-shlibdeps -O --ignore-missing-info \
            -l"$libdir" usr/bin/anyca_cli usr/bin/anyca_server \
            "usr/lib/$multiarch/libanyca_core.so" \
            "usr/lib/$multiarch/libanyca_osal.so" 2>"$work/shlibdeps.log"); then
        depends=${shlibs#shlibs:Depends=}
        depends=$(printf '%s\n' "$depends" |
            awk -F, '{ for (i = 1; i <= NF; i++) {
                    d = $i
                    gsub(/^[ \t]+|[ \t]+$/, "", d)
                    if (d != "" && d !~ /^libanyca/) {
                        printf "%s%s", sep, d
                        sep = ", "
                    }
                } }')
    else
        warn "dpkg-shlibdeps failed; using the default dependency list"
        cat "$work/shlibdeps.log" >&2
    fi
    rm -rf "$staging/debian"
fi
if [ -z "$depends" ]; then
    depends="libc6, libssl3t64 | libssl3, libsqlite3-0, libyaml-0-2, libcap2"
fi
depends="$depends, adduser"

mkdir -p "$staging/DEBIAN"
cat > "$staging/DEBIAN/control" <<EOF
Package: anyca
Version: $version
Architecture: $deb_arch
Maintainer: $maintainer
Installed-Size: $installed_size
Depends: $depends
Recommends: softhsm2, openssl
Section: admin
Priority: optional
Description: certificate authority toolkit and OCSP responder
 AnyCA is a certificate authority and OCSP responder written in C. It
 issues X.509 v3 certificates with private keys held in a PKCS #11 HSM,
 stores CA configurations and certificate and revocation records in
 SQLite, and serves OCSP responses over HTTP.
 .
 This package provides anyca_cli for administration and certificate
 generation, anyca_server for the OCSP responder, a systemd unit and a
 default configuration in /etc/anyca/config.yaml.
EOF

printf '%s\n' "/etc/anyca/config.yaml" > "$staging/DEBIAN/conffiles"

# Run ldconfig when the shared libraries in the multiarch directory change.
printf '%s\n' "activate-noawait ldconfig" > "$staging/DEBIAN/triggers"

cat > "$staging/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

case "$1" in
    configure)
        if ! getent group anyca >/dev/null; then
            addgroup --system anyca
        fi
        if ! getent passwd anyca >/dev/null; then
            adduser --system --ingroup anyca --home /var/lib/anyca \
                --no-create-home --gecos "AnyCA OCSP responder" \
                --shell /usr/sbin/nologin anyca
        fi
        install -d -o anyca -g anyca -m 0750 /var/lib/anyca
        install -d -o anyca -g anyca -m 0750 \
            /var/lib/anyca/crl /var/lib/anyca/cacerts
        install -d -o anyca -g anyca -m 0700 \
            /var/lib/anyca/pins /var/lib/anyca/tokens
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload || true
            if systemctl is-active --quiet anyca.service 2>/dev/null; then
                systemctl restart anyca.service || true
            fi
        fi
        echo "Edit /etc/anyca/config.yaml, then run:" \
            "'systemctl enable --now anyca'"
        ;;
esac

exit 0
EOF

cat > "$staging/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    if command -v deb-systemd-invoke >/dev/null 2>&1; then
        deb-systemd-invoke stop anyca.service >/dev/null 2>&1 || true
    elif command -v systemctl >/dev/null 2>&1; then
        systemctl --no-reload stop anyca.service >/dev/null 2>&1 || true
    fi
fi

exit 0
EOF

cat > "$staging/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

case "$1" in
    remove|purge)
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload || true
        fi
        ;;
esac

if [ "$1" = purge ]; then
    if getent passwd anyca >/dev/null; then
        deluser --system anyca >/dev/null 2>&1 || true
    fi
    if getent group anyca >/dev/null; then
        delgroup --system anyca >/dev/null 2>&1 || true
    fi
    # The store, SoftHSM tokens and PIN files are CA material; keep them
    # even on purge unless the administrator removes them explicitly.
    if [ -d /var/lib/anyca ]; then
        echo "Not removing /var/lib/anyca (CA state); remove it manually."
    fi
fi

exit 0
EOF

chmod 0644 "$staging/DEBIAN/control" "$staging/DEBIAN/conffiles" \
    "$staging/DEBIAN/triggers"
chmod 0755 "$staging/DEBIAN/postinst" "$staging/DEBIAN/prerm" \
    "$staging/DEBIAN/postrm"

(
    cd "$staging"
    find . -type f ! -path './DEBIAN/*' -printf '%P\0' |
        LC_ALL=C sort -z |
        xargs -0 -r md5sum
) > "$staging/DEBIAN/md5sums"
chmod 0644 "$staging/DEBIAN/md5sums"

deb_name=anyca_$(printf '%s' "$version" | sed 's/:/%3a/g')_$deb_arch.deb
deb_file=$output_dir/$deb_name
mkdir -p "$output_dir"
rm -f "$deb_file"

echo "==> building $deb_file"
if dpkg-deb --help 2>&1 | grep -q -- '--root-owner-group'; then
    dpkg-deb --build --root-owner-group "$staging" "$deb_file"
elif command -v fakeroot >/dev/null 2>&1; then
    fakeroot dpkg-deb --build "$staging" "$deb_file"
else
    die "dpkg-deb lacks --root-owner-group and fakeroot is not installed"
fi

echo
echo "==> package ready"
dpkg-deb --info "$deb_file" | sed 's/^/    /'
ls -lh "$deb_file" | sed 's/^/    /'
