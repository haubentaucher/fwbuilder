#!/bin/sh
# Validate native nftables transactions in generated Firewall Builder scripts.
# This uses nft --check: it must never apply, install or flush live rules.
set -eu

if [ "$#" -eq 0 ]; then
    echo 'Usage: check-nft-syntax.sh SCRIPT.fw ...' >&2
    exit 2
fi
command -v nft >/dev/null 2>&1 || {
    echo 'nft executable missing; cannot perform native syntax validation' >&2
    exit 2
}

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM

for fw in "$@"; do
    [ -s "$fw" ] || { echo "Missing/empty generated script: $fw" >&2; exit 1; }
    for marker in FWB_NFT_RULESET FWB_NFT_BLOCK FWB_NFT_STOP; do
        rules="$temp_dir/$marker.nft"
        awk -v marker="$marker" '
            {
                if (index($0, "<<\047" marker "\047")) {
                    if (start || seen) bad=1
                    start=1
                    seen++
                    next
                }
                if ($0==marker) {
                    if (!start) bad=1
                    start=0
                    closed++
                    next
                }
                if (start) print
            }
            END { if (seen!=1 || closed!=1 || start || bad) exit 1 }
        ' "$fw" > "$rules" || {
            echo "Missing or malformed $marker in $fw" >&2
            exit 1
        }
        [ -s "$rules" ] || { echo "Empty transaction $marker in $fw" >&2; exit 1; }
        echo "Checking $fw: $marker"
        nft --check --file "$rules"
    done
done

echo 'Native nftables grammar accepted all start/block/stop transactions (check-only).'
