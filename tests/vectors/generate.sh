#!/usr/bin/env bash
# Regenerates the interop vectors with the reference clevis/tang/jose.
# Usage (inside `nix develop`): TANG=/nix/store/...-tang-15 tests/vectors/generate.sh
#
# The tang keys written here are TEST-ONLY and must never be used elsewhere.
set -euo pipefail

: "${TANG:?set TANG to the tang package output path}"
here="$(cd "$(dirname "$0")" && pwd)"
port_a=18731
port_b=18732
plaintext='nbde interop vector: 64 bytes of P would go here, not this text.'

work="$(mktemp -d)"
cleanup() {
    kill "${pids[@]}" 2>/dev/null || true
    rm -rf "$work"
}
pids=()
trap cleanup EXIT

for name in a b; do
    rm -rf "$here/tang-$name"
    mkdir -p "$here/tang-$name"
    "$TANG/libexec/tangd-keygen" "$here/tang-$name"
done

"$TANG/libexec/tangd" -l -p "$port_a" "$here/tang-a" 2>"$work/a.log" &
pids+=($!)
"$TANG/libexec/tangd" -l -p "$port_b" "$here/tang-b" 2>"$work/b.log" &
pids+=($!)
sleep 1

thp() {
    local dir="$1"
    for k in "$dir"/*.jwk; do
        if jose fmt -j- -g key_ops -A -o- <"$k" | grep -q verify; then
            jose jwk thp -i "$k"
            return
        fi
    done
    return 1
}
thp_a="$(thp "$here/tang-a")"
thp_b="$(thp "$here/tang-b")"
url_a="http://127.0.0.1:$port_a"
url_b="http://127.0.0.1:$port_b"

tang_a="{\"url\":\"$url_a\",\"thp\":\"$thp_a\"}"
tang_b="{\"url\":\"$url_b\",\"thp\":\"$thp_b\"}"

printf '%s' "$plaintext" >"$here/plaintext"

printf '%s' "$plaintext" | clevis encrypt tang "$tang_a" >"$here/tang.jwe"

printf '%s' "$plaintext" |
    clevis encrypt sss "{\"t\":2,\"pins\":{\"tang\":[$tang_a,$tang_b]}}" >"$here/sss.jwe"

nested="{\"t\":2,\"pins\":{\"sss\":[{\"t\":1,\"pins\":{\"tang\":[$tang_a]}},{\"t\":1,\"pins\":{\"tang\":[$tang_b]}}]}}"
printf '%s' "$plaintext" | clevis encrypt sss "$nested" >"$here/nested-sss.jwe"

for v in tang sss nested-sss; do
    clevis decrypt <"$here/$v.jwe" | cmp - "$here/plaintext"
    echo "ok: $v"
done
