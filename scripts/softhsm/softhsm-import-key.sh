#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set -euo pipefail

usage() {
    echo "usage: $0 <token-label> <user-pin> <key-label> <private-key-file>" >&2
    echo "       PKCS11_PIN=<user-pin> $0 <token-label> <key-label> <private-key-file>" >&2
    exit 2
}

case "$#" in
    3)
        : "${PKCS11_PIN:?PKCS11_PIN must hold the token PIN}"
        set -- "$1" "$PKCS11_PIN" "$2" "$3"
        ;;
    4) ;;
    *) usage ;;
esac

token=$1
pin=$2
key_label=$3
key_file=$4
module=${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}

[ -f "$key_file" ] || {
    echo "private key file not found: $key_file" >&2
    exit 1
}

pkcs11-tool --module "$module" --token-label "$token" --login --pin "$pin" \
    --write-object "$key_file" --type privkey --label "$key_label" --usage-sign
