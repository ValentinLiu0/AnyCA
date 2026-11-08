#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

set -euo pipefail

if [ "$#" -ne 0 ]; then
    echo "usage: $0" >&2
    echo "environment: PKCS11_MODULE (default: /usr/lib/softhsm/libsofthsm2.so)" >&2
    exit 2
fi

module=${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}

command -v pkcs11-tool >/dev/null 2>&1 || {
    echo "pkcs11-tool not found (install opensc)" >&2
    exit 1
}

pkcs11-tool --module "$module" --list-token-slots |
awk '
BEGIN {
    printf "%-24s %-20s %s\n", "LABEL", "SERIAL", "URI"
}
function emit() {
    if (label != "") {
        printf "%-24s %-20s %s\n", label, (serial != "" ? serial : "-"), uri
    }
    label = ""
    serial = ""
    uri = ""
}
/^Slot / {
    emit()
    next
}
/^[[:space:]]*token label[[:space:]]*:/ {
    label = $0
    sub(/^[[:space:]]*token label[[:space:]]*:[[:space:]]*/, "", label)
    next
}
/^[[:space:]]*serial num[[:space:]]*:/ {
    serial = $0
    sub(/^[[:space:]]*serial num[[:space:]]*:[[:space:]]*/, "", serial)
    next
}
/^[[:space:]]*uri[[:space:]]*:/ {
    uri = $0
    sub(/^[[:space:]]*uri[[:space:]]*:[[:space:]]*/, "", uri)
    next
}
END {
    emit()
}
'
