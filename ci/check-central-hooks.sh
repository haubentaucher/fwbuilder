#!/usr/bin/env bash
# Verify central prolog/epilog hooks against a built fwb_ipt or fwb_nft binary.
# Skips cleanly when the compiler is not present so the script can ship
# before a full matrix job is attached.
set -euo pipefail

if (( $# < 2 )); then
    echo "Usage: $0 FWB_COMPILER BASELINE.fwb [OUTPUT_DIR]" >&2
    exit 2
fi

compiler=$1
baseline=$2
outdir=${3:-/tmp/fwb-central-hooks-out}
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd -P)

if [[ ! -x "$compiler" ]]; then
    echo "SKIP: compiler not executable: $compiler"
    exit 0
fi
if [[ ! -s "$baseline" ]]; then
    echo "Missing baseline project: $baseline" >&2
    exit 2
fi

compiler_base=$(basename "$compiler")
case "$compiler_base" in
    fwb_nft) want_platform=nftables ;;
    fwb_ipt) want_platform=iptables ;;
    *)
        echo "SKIP: unsupported compiler binary name: $compiler_base"
        exit 0
        ;;
esac

hooks=$(mktemp -d "$outdir/hooks.XXXXXX")
trap 'rm -rf "$hooks"' EXIT

mkdir -p "$hooks/prolog.d" "$hooks/epilog.d" \
         "$hooks/platforms/$want_platform/prolog.d" \
         "$hooks/profiles/opensuse-leap-15.6/prolog.d"

printf '%s\n' 'echo central-global-prolog' > "$hooks/prolog.d/10-common.sh"
printf '%s\n' 'echo central-platform-prolog' \
    > "$hooks/platforms/$want_platform/prolog.d/20-platform.sh"
printf '%s\n' 'echo central-profile-prolog' \
    > "$hooks/profiles/opensuse-leap-15.6/prolog.d/30-profile.sh"
printf '%s\n' 'echo central-global-epilog' > "$hooks/epilog.d/90-finish.sh"
printf '%s\n' '# comment only' > "$hooks/prolog.d/README.md"

export FWBUILDER_HOOKS_DIR="$hooks"

fw_name=$(python3 - "$baseline" "$want_platform" <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
want = sys.argv[2]
ns = ''
if root.tag.startswith('{'):
    ns = root.tag.split('}')[0] + '}'
for fw in root.iter(ns + 'Firewall'):
    if fw.get('platform') == want and fw.get('inactive', 'False') == 'False':
        print(fw.get('name'))
        break
else:
    sys.exit(3)
PY
) || {
    echo "SKIP: no $want_platform firewall object in baseline"
    exit 0
}

printf '%s\n' "$fw_name opensuse-leap-15.6" > "$hooks/profiles.map"

work="$outdir/compile-$fw_name"
rm -rf "$work"
mkdir -p "$work"

if ! "$compiler" -f "$baseline" -d "$work" "$fw_name" > "$work/compile.log" 2>&1; then
    cat "$work/compile.log" >&2
    echo "FAIL: compiler rejected $fw_name with hooks enabled" >&2
    exit 1
fi

shopt -s nullglob
generated=("$work"/*.fw)
shopt -u nullglob
if (( ${#generated[@]} != 1 )); then
    echo "FAIL: expected one generated script" >&2
    exit 1
fi
script=${generated[0]}

for needle in \
    'echo central-global-prolog' \
    'echo central-platform-prolog' \
    'echo central-profile-prolog' \
    'echo central-global-epilog' \
    'begin fwbuilder central hook: prolog.d/10-common.sh' \
    "begin fwbuilder central hook: platforms/$want_platform/prolog.d/20-platform.sh"
do
    grep -Fq "$needle" "$script" || {
        echo "FAIL: missing hook output: $needle" >&2
        exit 1
    }
done

# Order: global before platform before profile.
python3 - "$script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
markers = [
    'echo central-global-prolog',
    'echo central-platform-prolog',
    'echo central-profile-prolog',
    'echo central-global-epilog',
]
positions = [text.index(m) for m in markers]
if positions != sorted(positions):
    raise SystemExit('FAIL: hook order is not global, platform, profile, epilog')
print('PASS: hook order')
PY

# Unreadable file must fail the compile. Root can still read mode-000
# files, so skip this check when the runner is uid 0 (typical CI).
if [[ "$(id -u)" != 0 ]]; then
    chmod a-r "$hooks/prolog.d/10-common.sh"
    fail_dir="$outdir/compile-unreadable"
    rm -rf "$fail_dir"
    mkdir -p "$fail_dir"
    if "$compiler" -f "$baseline" -d "$fail_dir" "$fw_name" > "$fail_dir/compile.log" 2>&1; then
        echo "FAIL: unreadable hook file was accepted" >&2
        exit 1
    fi
    grep -Fq 'not readable' "$fail_dir/compile.log" || \
    grep -Fq 'Cannot read central hooks file' "$fail_dir/compile.log" || {
        cat "$fail_dir/compile.log" >&2
        echo "FAIL: unreadable hook did not report a clear error" >&2
        exit 1
    }
    chmod a+r "$hooks/prolog.d/10-common.sh"
else
    echo "SKIP: unreadable-hook check (running as root)"
fi

# Symbolic link to a hook file must fail the compile.
ln -s "$hooks/prolog.d/10-common.sh" "$hooks/prolog.d/15-link.sh"
fail_link="$outdir/compile-symlink"
rm -rf "$fail_link"
mkdir -p "$fail_link"
if "$compiler" -f "$baseline" -d "$fail_link" "$fw_name" > "$fail_link/compile.log" 2>&1; then
    echo "FAIL: symbolic-link hook file was accepted" >&2
    exit 1
fi
grep -Fq 'symbolic link' "$fail_link/compile.log" || {
    cat "$fail_link/compile.log" >&2
    echo "FAIL: symbolic-link hook did not report a clear error" >&2
    exit 1
}
rm -f "$hooks/prolog.d/15-link.sh"

# Broken profiles.map must fail.
printf '%s\n' 'only-one-column' > "$hooks/profiles.map"
fail_map="$outdir/compile-bad-map"
rm -rf "$fail_map"
mkdir -p "$fail_map"
if "$compiler" -f "$baseline" -d "$fail_map" "$fw_name" > "$fail_map/compile.log" 2>&1; then
    echo "FAIL: invalid profiles.map was accepted" >&2
    exit 1
fi
grep -Fq 'profiles.map' "$fail_map/compile.log" || {
    cat "$fail_map/compile.log" >&2
    echo "FAIL: invalid profiles.map did not report a clear error" >&2
    exit 1
}
printf '%s\n' "$fw_name opensuse-leap-15.6" > "$hooks/profiles.map"

# No hooks configured → historical output must not contain central markers.
unset FWBUILDER_HOOKS_DIR
clean="$outdir/compile-clean"
rm -rf "$clean"
mkdir -p "$clean"
"$compiler" -f "$baseline" -d "$clean" "$fw_name" > "$clean/compile.log" 2>&1
clean_script=("$clean"/*.fw)
if grep -Fq 'begin fwbuilder central hook:' "${clean_script[0]}"; then
    echo "FAIL: central hooks appeared without configuration" >&2
    exit 1
fi

echo "PASS: central hooks ($want_platform / $fw_name)"
