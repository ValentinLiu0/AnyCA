#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set -euo pipefail

# softhsm2-util only accepts the PINs as arguments, so they are briefly visible
# in the process list either way.  The environment form keeps them out of shell
# history.
usage() {
    echo "usage: $0 <token-label> <user-pin> <so-pin>" >&2
    echo "       PKCS11_PIN=<user-pin> SOFTHSM_SO_PIN=<so-pin> $0 <token-label>" >&2
    exit 2
}

case "$#" in
    1)
        : "${PKCS11_PIN:?PKCS11_PIN must hold the user PIN}"
        : "${SOFTHSM_SO_PIN:?SOFTHSM_SO_PIN must hold the SO PIN}"
        set -- "$1" "$PKCS11_PIN" "$SOFTHSM_SO_PIN"
        ;;
    3) ;;
    *) usage ;;
esac

softhsm2-util --init-token --free --label "$1" --pin "$2" --so-pin "$3"
