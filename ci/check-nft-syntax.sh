#!/bin/sh
# Validate native nftables transactions in generated Firewall Builder scripts.
# This uses nft --check: it must never apply, install or flush live rules.
#
# The generated script stages three nft -f transactions through heredocs:
#   start: FWB_NFT_START_BASE (base chain declarations) followed by
#          FWB_NFT_RULESET (the rules), committed as one batch;
#   block: FWB_NFT_BLOCK_BASE (base chain declarations) followed by
#          FWB_NFT_BLOCK (emergency management access rules);
#   stop:  FWB_NFT_STOP (comments only; the deletes come from
#          fwb_nft_begin_transaction at run time).
# Markers are matched as whole words so FWB_NFT_BLOCK does not match the
# FWB_NFT_BLOCK_BASE declarations of the same transaction.
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

extract_heredocs() {
    out=$1
    shift
    : > "$out"
    for marker in "$@"; do
        awk -v marker="$marker" '
            function heredoc_open(m) {
                pos = index($0, "<<" m)
                if (pos > 0) {
                    rest = substr($0, pos + 2 + length(m))
                    if (rest == "" || substr(rest, 1, 1) !~ /[A-Za-z0-9_]/)
                        return 1
                }
                if (index($0, "<<\047" m "\047") > 0) return 1
                if (index($0, "<<\"" m "\"") > 0) return 1
                return 0
            }
            {
                if (heredoc_open(marker)) {
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
        ' "$fw" >> "$out" || {
            echo "Missing or malformed $marker in $fw" >&2
            exit 1
        }
    done
}

for fw in "$@"; do
    [ -s "$fw" ] || { echo "Missing/empty generated script: $fw" >&2; exit 1; }
    extract_heredocs "$temp_dir/start.nft" FWB_NFT_START_BASE FWB_NFT_RULESET
    extract_heredocs "$temp_dir/block.nft" FWB_NFT_BLOCK_BASE FWB_NFT_BLOCK
    extract_heredocs "$temp_dir/stop.nft" FWB_NFT_STOP
    for txn in start block stop; do
        rules="$temp_dir/$txn.nft"
        [ -s "$rules" ] || { echo "Empty $txn transaction in $fw" >&2; exit 1; }
        echo "Checking $fw: $txn transaction"
        nft --check --file "$rules"
    done
done

echo 'Native nftables grammar accepted all start/block/stop transactions (check-only).'
