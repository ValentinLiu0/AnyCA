#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set -euo pipefail

usage() {
    echo "usage: $0 <token-label> <user-pin> <algorithm> <key-label>" >&2
    echo "       PKCS11_PIN=<user-pin> $0 <token-label> <algorithm> <key-label>" >&2
    echo "algorithms: RSA2048 RSA3072 RSA4096 ECC-P256 ECC-P384 ECC-P521" >&2
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
algorithm=${3^^}
key_label=$4
module=${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}

case "$algorithm" in
    RSA2048) key_type=RSA:2048 ;;
    RSA3072) key_type=RSA:3072 ;;
    RSA4096) key_type=RSA:4096 ;;
    ECC-P256|EC-P256|P256) key_type=EC:prime256v1 ;;
    ECC-P384|EC-P384|P384) key_type=EC:secp384r1 ;;
    ECC-P521|EC-P521|P521) key_type=EC:secp521r1 ;;
    *)
        echo "unsupported algorithm: $3" >&2
        exit 2
        ;;
esac

pkcs11-tool --module "$module" --token-label "$token" --login --pin "$pin" \
    --keypairgen --key-type "$key_type" --label "$key_label" --usage-sign
