#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set -euo pipefail

if [ "$#" -eq 1 ]; then
    : "${PKCS11_PIN:?PKCS11_PIN must hold the token PIN}"
    set -- "$1" "$PKCS11_PIN"
elif [ "$#" -ne 2 ]; then
    echo "usage: $0 <token-label> <user-pin>" >&2
    echo "       PKCS11_PIN=<user-pin> $0 <token-label>" >&2
    echo "environment: PKCS11_MODULE (default: /usr/lib/softhsm/libsofthsm2.so)" >&2
    exit 2
fi

token=$1
pin=$2
module=${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}

command -v pkcs11-tool >/dev/null 2>&1 || {
    echo "pkcs11-tool not found (install opensc)" >&2
    exit 1
}

# Resolve the token label to its exact slot id.  --token-label accepts
# prefixes, so "AnyCA" would also match "AnyCA-Test".
status=0
slot_id=$(
    pkcs11-tool --module "$module" --list-token-slots |
    TOKEN="$token" awk '
    BEGIN {
        want = ENVIRON["TOKEN"]
        found = 0
    }
    /^Slot / {
        slot_id = $3
        gsub(/[()]/, "", slot_id)
        label = ""
    }
    /^[[:space:]]*token label[[:space:]]*:/ {
        label = $0
        sub(/^[[:space:]]*token label[[:space:]]*:[[:space:]]*/, "", label)
        if (label == want) {
            print slot_id
            found++
        }
    }
    END {
        exit (found == 1 ? 0 : (found == 0 ? 1 : 2))
    }
    '
) || status=$?

case $status in
    0) ;;
    1)
        echo "token not found: $token" >&2
        exit 1
        ;;
    2)
        echo "multiple tokens have label \"$token\"; use a unique label" >&2
        exit 1
        ;;
    *) exit "$status" ;;
esac

if [ -z "$slot_id" ]; then
    echo "cannot determine the slot for token: $token" >&2
    exit 1
fi

# Print one "label<TAB>URI" line per private key.  pkcs11-tool emits the URI
# with the token attributes percent-encoded, ready for anyca_cli.  Drop the
# optional id= attribute, which anyca_cli does not support.
pkcs11-tool --module "$module" --slot "$slot_id" --login --pin "$pin" \
    --list-objects --type privkey |
awk '
/^[[:space:]]*label[[:space:]]*:/ {
    label = $0
    sub(/^[[:space:]]*label[[:space:]]*:[[:space:]]*/, "", label)
    next
}
/^[[:space:]]*uri[[:space:]]*:/ {
    uri = $0
    sub(/^[[:space:]]*uri[[:space:]]*:[[:space:]]*/, "", uri)
    sub(/;id=[^;?]*/, "", uri)
    sub(/^id=[^;?]*;/, "", uri)
    printf "%s\t%s\n", label, uri
    label = ""
}
'
