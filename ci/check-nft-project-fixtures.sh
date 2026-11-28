#!/usr/bin/env bash
# Check independent native FWB XML fixtures without triggering another build.
# Every scenario is executed even when an earlier one fails; only fully
# verified positive outputs are published for nft --check/kernel testing.
set -euo pipefail

if (( $# != 3 )); then
    echo 'Usage: check-nft-project-fixtures.sh COMPILER BASELINE.fwb OUTPUT_DIR' >&2
    exit 2
fi
compiler=$1
baseline=$2
output=$3
[[ -x "$compiler" && -s "$baseline" ]] || { echo 'Missing compiler or baseline' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 missing' >&2; exit 2; }

mkdir -p "$output"
output="$(cd "$output" && pwd -P)"
work="$(dirname "$output")/nft-project-fixtures"
mkdir -p "$work"
python3 ci/generate-nft-project-fixtures.py "$baseline" "$work/xml"
# The compiler CLI must return an ordinary error, never abort on a missing
# -f argument (QStringList::at() is not defined for an out-of-range index).
if "$compiler" -f > "$work/missing-file-argument.log" 2>&1; then
    echo 'FAIL: fwb_nft accepted -f without a filename' >&2
    exit 1
fi
if ! grep -Fq 'Missing filename after -f' "$work/missing-file-argument.log"; then
    cat "$work/missing-file-argument.log" >&2
    echo 'FAIL: fwb_nft did not diagnose the missing -f argument' >&2
    exit 1
fi

# An explicit -4/-6 is essential.  The default fwb_nft invocation in the
# previous CI run produced only an IPv4 block, silently omitting the IPv6 rule.
# Checking the compiled ruleset (not the XML) prevents a false positive.
check_positive() {
    local name=$1 family=$2 generated expected
    shift 2
    local -a args=()
    case "$family" in
        4) args=(-4) ;;
        6) args=(-6) ;;
        *) echo "Internal error: unsupported test family: $family" >&2; return 1 ;;
    esac
    mkdir -p "$work/$name"
    if ! "$compiler" "${args[@]}" -f "$work/xml/$name.fwb" -d "$work/$name" nft-test \
        > "$work/$name.compile.log" 2>&1; then
        cat "$work/$name.compile.log" >&2
        echo "FAIL: native FWB compiler rejected $name (IPv$family)" >&2
        return 1
    fi

    local -a files=()
    shopt -s nullglob
    files=("$work/$name"/*.fw)
    shopt -u nullglob
    if (( ${#files[@]} != 1 )) || [[ ! -s "${files[0]}" ]]; then
        echo "FAIL: expected exactly one generated script for $name" >&2
        return 1
    fi
    generated="${files[0]}"
    if ! sh ci/check-nft-output.sh "$generated"; then
        echo "FAIL: invalid native script structure for $name" >&2
        return 1
    fi

    # Store the extracted start transaction for reproducible diagnostics.
    # It concatenates the base chain declarations (FWB_NFT_START_BASE)
    # with the rule heredoc (FWB_NFT_RULESET) in staging order; testing
    # the script preamble could accidentally accept unrelated addresses.
    if ! awk '
        /<<FWB_NFT_START_BASE/ { in_decl = 1; next }
        /^FWB_NFT_START_BASE$/ { in_decl = 0; next }
        /<<FWB_NFT_RULESET/ { on = 1; next }
        /^FWB_NFT_RULESET$/ { on = 0; next }
        in_decl || on { print }
    ' "$generated" > "$work/$name.ruleset.nft"; then
        echo "FAIL: could not extract native ruleset for $name" >&2
        return 1
    fi
    local table_family=ip
    [[ "$family" == 6 ]] && table_family=ip6
    if ! grep -Eq "^add table $table_family filter[[:space:]]*\$" "$work/$name.ruleset.nft"; then
        # For IPv4 the family is "ip" and for IPv6 it is "ip6".
        echo "FAIL: $name has no IPv$family filter table" >&2
        return 1
    fi
    for expected in "$@"; do
        if [[ "$expected" == 'add set '* ]]; then
            # Set declarations are independent nft statements, never rule
            # expressions. Require exactly one complete declaration so a
            # missing or accidentally duplicated dynamic set is rejected.
            local declaration_count
            declaration_count=$(grep -Ec "^${expected}$" "$work/$name.ruleset.nft" || true)
            if [[ "$declaration_count" != 1 ]]; then
                echo "FAIL: $name expected exactly one nftables set declaration ($expected); found $declaration_count" >&2
                return 1
            fi
        elif ! grep -Eq "^add rule $table_family (filter|nat|mangle) .*${expected}" "$work/$name.ruleset.nft"; then
            echo "FAIL: $name has no expected nftables rule expression ($expected)" >&2
            return 1
        fi
    done
    cp -- "$generated" "$output/nft-ci-$name.fw"
    echo "PASS: $name (IPv$family) generated and verified native rules"
}

# Validate the *actual* three-rule negation lowering for ordinary FWB
# Srv neg=True. A sequence of nft matches is AND, so prefixing "not" or
# negating just the first expression would change policy semantics.
check_negated_ip_service() {
    local name=$1 match=$2
    if ! check_positive "$name" 4 "$match"; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" "$match" <<'PY_NEGATED_IP_SERVICE'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
expected = re.compile(sys.argv[2])
rules = []
for index, line in enumerate(lines):
    match = re.fullmatch(r'add rule ip filter (\S+) (.+)', line)
    if match:
        rules.append((index, match.group(1), match.group(2)))

matched = [(idx, chain, body) for idx, chain, body in rules
           if expected.search(body) and body.endswith(' return')]
if not matched:
    sys.exit('FAIL: negated IP service has no positive-match return rule')
for idx, chain, body in matched:
    if re.search(r'\bnot\s', body):
        sys.exit('FAIL: native negation emitted an invalid not prefix')
    jumps = [(i, c, b) for i, c, b in rules
             if i < idx and c != chain and re.search(
                 r'\bjump\s+' + re.escape(chain) + r'\s*$', b)]
    tails = [(i, b) for i, c, b in rules
             if i > idx and c == chain and (b == 'accept' or b.endswith(' accept'))]
    if not jumps or not tails:
        sys.exit('FAIL: negated IP service is missing jump/return/accept ordering')
    # The fallback action is reached only when the positive service did not
    # match.  A service match *alone* must not trigger the accept action.
    if any(expected.search(b) for _, b in tails):
        sys.exit('FAIL: negated service is present in terminal accept rule')
print('PASS: negated IP service uses jump / positive match return / accept')
PY_NEGATED_IP_SERVICE
}

# Multi-object rule elements used to be chainified by the iptables-era
# optimize1 pass. The native backend prints set-capable Src and Dst as
# inline nftables address sets, so the same FWB rule must compile into one
# flat terminal rule and must not create a jump chain.
check_multi_address_set() {
    local name=$1
    if ! check_positive "$name" 4 \
        'ip saddr \{ 192\.168\.1\.0/24, 192\.168\.2\.0/24 \}' \
        'ip daddr \{ 192\.168\.1\.0/24, 192\.168\.2\.0/24 \}'; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" <<'PY_MULTI_ADDRESS_SET'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
for line in lines:
    if re.match(r'^add (rule|chain) ip filter C\S*', line):
        sys.exit('FAIL: multi-address rule was chainified: ' + line)
    if re.match(r'^add rule ip \S+ .* \bjump C\S*', line):
        sys.exit('FAIL: multi-address rule jumps into a chain: ' + line)
    if re.match(r'^add rule ip \S+ .* (ip saddr|ip daddr) \{', line) \
            and ' jump ' in line:
        sys.exit('FAIL: inline address set is not terminal: ' + line)
flat = [line for line in lines
        if re.search(r'\bip saddr \{', line)
        and re.search(r'\bip daddr \{', line)
        and line.endswith(' accept')]
if not flat:
    sys.exit('FAIL: no flat accept rule with inline Src and Dst sets')
same_rule = [line for line in flat
             if re.search(r'\bip daddr \{ 192\.168\.1\.0/24, '
                          r'192\.168\.2\.0/24 \}', line)]
if len(same_rule) != 1 or len(flat) != 1:
    sys.exit('FAIL: expected exactly one flat multi-address accept rule')
print('PASS: multi-object Src/Dst stay one flat rule with inline sets')
PY_MULTI_ADDRESS_SET
}

# NAT twin of the flat multi-address check: the iptables-era
# splitMultiSrcAndDst pass used to turn multi-object Src/Dst into a jump
# chain with one row per address. The native backend prints inline
# nftables sets, so the same FWB rule must compile into one flat
# translation row and must not create a jump chain.
check_nat_multi_address_set() {
    local name=$1
    if ! check_positive "$name" 4 \
        'ip saddr \{ 192\.168\.1\.0/24, 192\.168\.2\.0/24 \}' \
        'ip daddr \{ 192\.0\.2\.0/24, 192\.0\.2\.101 \}' \
        'snat to 192\.0\.2\.100'; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" <<'PY_NAT_MULTI_ADDRESS_SET'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
for line in lines:
    if re.match(r'^add (rule|chain) ip nat C\S*', line):
        sys.exit('FAIL: multi-address NAT rule was chainified: ' + line)
    if re.match(r'^add rule ip nat \S+ .* \bjump C\S*', line):
        sys.exit('FAIL: multi-address NAT rule jumps into a chain: ' + line)
flat = [line for line in lines
        if re.search(r'\bip saddr \{', line)
        and re.search(r'\bip daddr \{', line)
        and line.rstrip().endswith('snat to 192.0.2.100')]
if len(flat) != 1:
    sys.exit('FAIL: expected exactly one flat multi-address snat rule')
print('PASS: multi-object NAT Src/Dst stay one flat rule with inline sets')
PY_NAT_MULTI_ADDRESS_SET
}

# The ipt_use_masq rule option must flip the standard SNAT translation
# into exactly one native masquerade statement; no residual snat.
check_nat_masquerade() {
    local name=$1
    if ! check_positive "$name" 4 'masquerade' 'ip saddr 192\.168\.1\.0/24'; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" <<'PY_NAT_MASQUERADE'
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
snat = [line for line in lines if 'snat to' in line]
if snat:
    sys.exit('FAIL: residual snat translation remains: ' + snat[0])
masq = [line for line in lines if 'masquerade' in line]
if not masq:
    sys.exit('FAIL: no native masquerade rule')
for line in masq:
    if not line.startswith('add rule ip nat POSTROUTING'):
        sys.exit('FAIL: masquerade rule is not in POSTROUTING: ' + line)
print('PASS: ipt_use_masq flips SNAT into a native masquerade row')
PY_NAT_MASQUERADE
}

# Tagging rules enrich packets in the mangle table: 'meta mark set' rows,
# the CONNMARK save statement for ipt_mark_connections and the automatic
# restoration rows. No mark expression may leak into filter or nat.
check_mangle_tag() {
    local name=$1
    if ! check_positive "$name" 4 'meta mark set 64'; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" <<'PY_MANGLE_TAG'
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
marks = [line for line in lines if 'meta mark set 64' in line]
saved = [line for line in lines if 'ct mark set meta mark' in line]
restore = [line for line in lines if 'meta mark set ct mark' in line]
if not marks:
    sys.exit('FAIL: the Tag action produced no meta mark set row')
if not saved:
    sys.exit('FAIL: ipt_mark_connections produced no ct mark save row')
if not restore:
    sys.exit('FAIL: no automatic meta mark set ct mark restoration rows')
for line in marks + saved + restore:
    if not line.startswith('add rule ip mangle '):
        sys.exit('FAIL: mark expression outside the mangle table: ' + line)
    if line.rstrip().endswith('drop'):
        sys.exit('FAIL: mark row ends in an unexpected drop: ' + line)
print('PASS: Tag sets meta mark/ct mark inside the mangle table')
PY_MANGLE_TAG
}

# The nft_counter rule option adds the native counter statement exactly
# where it was enabled: the filter verdict, the nat translation and the
# mangle tag row. Every other rule must stay free of counter statements.
# Direction "Both" rules fan out over several chains, so the check does
# not pin the row count; every counter row must belong to one of the
# three enabled rules instead.
check_rule_counter() {
    local name=$1
    if ! check_positive "$name" 4 'counter drop' 'counter snat to' 'counter meta mark set'; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" <<'PY_RULE_COUNTER'
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
counter = [line for line in lines if 'counter' in line]
if not counter:
    sys.exit('FAIL: no counter rows at all')
expected = (
    ('add rule ip filter ', 'counter drop'),
    ('add rule ip nat ', 'counter snat to'),
    ('add rule ip mangle ', 'counter meta mark set'),
)
for line in counter:
    if not any(line.startswith(prefix) and needle in line
               for prefix, needle in expected):
        sys.exit('FAIL: unexpected counter row: ' + line)
print('PASS: nft_counter adds native counter rows to filter, nat and mangle')
PY_RULE_COUNTER
}

# Matching a TagService only reads the mark: flat filter rows, and the
# compiled script must not declare a mangle table at all.
check_mark_match() {
    local name=$1
    if ! check_positive "$name" 4 'meta mark == 42'; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" <<'PY_MARK_MATCH'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
rows = [line for line in lines if 'meta mark == 42' in line]
if not rows:
    sys.exit('FAIL: the TagService match produced no meta mark == 42 row')
for line in rows:
    if not line.startswith('add rule ip filter '):
        sys.exit('FAIL: TagService match outside the filter table: ' + line)
    if not line.rstrip().endswith('accept'):
        sys.exit('FAIL: TagService match does not accept: ' + line)
if any(re.match(r'^add (table|chain|rule|set) ip mangle', line) for line in lines):
    sys.exit('FAIL: a plain mark match must not create a mangle table')
print('PASS: TagService matches meta mark in the filter table')
PY_MARK_MATCH
}

# The iptables CLASSIFY handle 'major:minor' must be translated into the
# numeric nftables skb priority; no raw 'M:N' syntax may reach the script.
check_mangle_classify() {
    local name=$1
    if ! check_positive "$name" 4 'meta priority set 0x0001000a'; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" <<'PY_MANGLE_CLASSIFY'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
priorities = [line for line in lines if 'meta priority set' in line]
if not priorities:
    sys.exit('FAIL: the Classify action produced no meta priority set row')
for line in priorities:
    if not line.startswith('add rule ip mangle '):
        sys.exit('FAIL: priority expression outside the mangle table: ' + line)
    if re.search(r'meta priority set [0-9]+:[0-9]+', line):
        sys.exit('FAIL: untranslated iptables CLASSIFY handle leaked: ' + line)
print('PASS: Classify translates the TC handle into a native priority')
PY_MANGLE_CLASSIFY
}

# Validate the native three-row NAT negation lowering (regression for the
# "Unsupported native nftables SNAT target" / "... NAT rule type" aborts):
# the translation row in a base chain must jump to the temporary chain,
# the positive destination matches must return without translating, and
# only the fall-through rows may carry the actual snat statement.
check_negated_nat() {
    local name=$1 dst_re=$2 translation_re=$3
    if ! check_positive "$name" 4 'ip daddr'; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" "$dst_re" "$translation_re" <<'PY_NEGATED_NAT'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
dst_re = re.compile(sys.argv[2])
translation_re = re.compile(sys.argv[3])
rules = []
for index, line in enumerate(lines):
    match = re.fullmatch(r'add rule ip nat (\S+) (.+)', line)
    if match:
        rules.append((index, match.group(1), match.group(2)))

base = {'PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'}
jump_rows = []
for index, chain, body in rules:
    match = re.search(r'\bjump (\S+)\s*$', body)
    if chain in base and match and match.group(1) not in base:
        jump_rows.append((index, match.group(1), body))
if not jump_rows:
    sys.exit('FAIL: negated NAT has no jump into a temporary chain')
for jump_index, tmp_chain, jump_body in jump_rows:
    if dst_re.search(jump_body) or translation_re.search(jump_body):
        sys.exit('FAIL: negated NAT jump row must not match or translate')
    # The NAT printer pads generated rows with trailing spaces
    # (e.g. "... return  "), so match the keyword with a trailing-space
    # tolerant regex instead of a strict body.endswith().
    returns = [(index, body) for index, chain, body in rules
               if chain == tmp_chain and dst_re.search(body)
               and re.search(r'\breturn\s*$', body)]
    translations = [(index, body) for index, chain, body in rules
                     if chain == tmp_chain and translation_re.search(body)]
    if not returns:
        sys.exit('FAIL: negated NAT temporary chain lacks positive-match return')
    if not translations:
        sys.exit('FAIL: negated NAT temporary chain lacks translation row')
    for _, body in returns:
        if translation_re.search(body):
            sys.exit('FAIL: negated destination match must not translate')
    for _, body in translations:
        if dst_re.search(body):
            sys.exit('FAIL: translation row must not match the negated destination')
    if max(i for i, _ in returns) > min(i for i, _ in translations):
        sys.exit('FAIL: translation must follow the positive-match returns')
print('PASS: negated NAT uses jump / positive match return / translation')
PY_NEGATED_NAT
}

# End-to-end output from actual FWB UserService objects, including the
# SingleSrvNegation lowering.  Reject syntactically invalid "meta skuid not".
check_user_service() {
    local name=$1 expected=$2
    if ! check_positive "$name" 4 'meta skuid'; then
        return 1
    fi
    python3 - "$work/$name.ruleset.nft" "$expected" <<'PY_USER_SERVICE'
from pathlib import Path
import re
import sys

rules = Path(sys.argv[1]).read_text().splitlines()
expected = sys.argv[2]
owner_rules = [line for line in rules
               if re.match(r'^add rule ip filter OUTPUT ', line)
               and 'meta skuid' in line]
if not owner_rules:
    sys.exit('FAIL: expected UserService in native OUTPUT chain')
for line in owner_rules:
    matches = re.findall(r'\bmeta\s+skuid\s+(?:!=\s+)?1000\b', line)
    if not matches or any(m != expected for m in matches):
        sys.exit('FAIL: incorrect UserService match: ' + line)
    if re.search(r'\bmeta\s+skuid\s+not\b', line):
        sys.exit('FAIL: invalid nftables owner negation: ' + line)
print('PASS: native UserService expression:', expected)
PY_USER_SERVICE
}

# Both IPv6 filter and NAT transport selectors must skip IPv6 extension
# headers. ip6 nexthdr only reads the fixed IPv6 header's next-header field.
check_ipv6_lb_transport() {
    local name=$1 expected=$2 rules
    if ! check_positive "$name" 6 "$expected"; then
        return 1
    fi
    rules="$work/$name.ruleset.nft"
    for table in filter nat; do
        if ! grep -Eq "^add rule ip6 ${table} .*meta l4proto tcp " "$rules"; then
            echo "FAIL: $name has no extension-header-safe TCP selector in $table" >&2
            return 1
        fi
    done
    if grep -Eq '^add rule ip6 (filter|nat) .*ip6 nexthdr tcp ' "$rules"; then
        echo "FAIL: $name still uses immediate IPv6 next-header matching" >&2
        return 1
    fi
    echo "PASS: $name uses extension-header-safe IPv6 TCP matching in filter and NAT"
}

# The native runtime initializes dynamic-interface IPv6 network variables
# from IPv6 kernel routes, not accidentally from IPv4 routes. The mock
# refuses commands without the family and the exact interface selector.
check_dynamic_ipv6_routes() {
    local fake_ip="$work/mock-ip-route"
    cat > "$fake_ip" <<'MOCK_IP_ROUTE'
#!/bin/sh
case "$*" in
    '-4 route list proto kernel dev eth0')
        printf '192.0.2.0/24 dev eth0 proto kernel scope link\n' ;;
    '-6 route list proto kernel dev eth0')
        printf '2001:db8:1::/64 dev eth0 proto kernel metric 256\n' ;;
    '-6 route list proto kernel dev eth1')
        printf '2001:db8:2::/64 dev eth1 proto kernel metric 256\n' ;;
    *) printf 'Unexpected ip route arguments: %s\n' "$*" >&2; exit 71 ;;
esac
MOCK_IP_ROUTE
    chmod +x "$fake_ip"
    (
        IP="$fake_ip"
        # Only source the native configlet, not the similar legacy copy.
        source src/res/configlets/nftables/nft_shell_functions
        getnet eth0 CHECK_V4
        getnet6 eth0 CHECK_V6
        getnet6 eth1 CHECK_V6_OTHER
        [[ "${CHECK_V4_list:-}" == '192.0.2.0/24' ]] || exit 1
        [[ "${CHECK_V6_list:-}" == '2001:db8:1::/64' ]] || exit 1
        [[ "${CHECK_V6_OTHER_list:-}" == '2001:db8:2::/64' ]] || exit 1
    ) || { echo 'FAIL: native dynamic IPv6 routes use wrong family/interface' >&2; return 1; }
    echo 'PASS: dynamic IPv4/IPv6 network lookup selects correct family and interface'
}

# Unsupported options must fail with the *specific* fail-closed diagnostic.
check_negative() {
    local name=$1 expected=$2 family=${3:-4}
    local family_flag=-4
    [[ "$family" == 6 ]] && family_flag=-6
    mkdir -p "$work/$name"
    if "$compiler" "$family_flag" -f "$work/xml/$name.fwb" -d "$work/$name" nft-test \
        > "$work/$name.compile.log" 2>&1; then
        echo "FAIL: unsupported $name compiled successfully" >&2
        return 1
    fi
    if ! grep -Fq "$expected" "$work/$name.compile.log"; then
        cat "$work/$name.compile.log" >&2
        echo "FAIL: $name failed without expected guard: $expected" >&2
        return 1
    fi
    echo "PASS: $name rejected by the specific native compiler guard"
}

# The set fixture is a full generated shell script. Its nft transactions are
# assembled at runtime from an external file, not from a static heredoc.
# Keep it out of the direct-transaction checks, and test it via real start.
check_dynamic_sets() {
    local name=dynamic-address-sets
    mkdir -p "$work/$name" "$output/../nft-sets-output"
    if ! "$compiler" -4 -f "$work/xml/$name.fwb" -d "$work/$name" nft-test \
         > "$work/$name.compile.log" 2>&1; then
        cat "$work/$name.compile.log" >&2
        return 1
    fi
    local -a generated=("$work/$name"/*.fw)
    [[ ${#generated[@]} == 1 && -s ${generated[0]} ]] || return 1
    sh -n "${generated[0]}" || return 1
    grep -Fq 'fwb_nft_stage_address_tables || exit 1' "${generated[0]}" || return 1
    grep -Eq 'add rule ip filter .*ip saddr @bad_guys' "${generated[0]}" || return 1
    grep -Fq "fwb_nft_stage_one_address_table 'bad_guys' '/tmp/fwb-pr6-ci-address-set.data'" "${generated[0]}" || return 1
    # block_action() is a separate emergency-policy transaction. In set
    # mode the start branch omits its add-table lines (fwb_nft_stage_
    # address_tables declares the tables), so a literal add-table may
    # only appear in the lockdown declarations shared by block_action.
    if ! awk '
        /<<FWB_NFT_BLOCK_BASE/ { in_block = 1; next }
        /^FWB_NFT_BLOCK_BASE$/ { in_block = 0; next }
        in_block && /^add table ip filter[[:space:]]*$/ { in_block_count++ }
        !in_block && /^add table ip filter[[:space:]]*$/ { outside = 1 }
        END { exit !(outside == 0 && in_block_count == 1) }
    ' "${generated[0]}"; then
        echo 'Unexpected duplicate add-table declaration in set mode' >&2
        return 1
    fi
    cp -- "${generated[0]}" "$output/../nft-sets-output/nft-ci-dynamic-address-sets.fw"
    echo 'PASS: dynamic-address-sets generated from real FWB AddressTable'
}

# Dynamic interface addresses historically aborted the final legacy-marker
# validation ("Native nftables script contains legacy command: $i_"), so
# fwb_nft wrote NO output file even though every rule compiled. Later the
# iptables-era loop wrappers leaked INTO the unquoted ruleset heredoc: the
# heredoc expanded the loop variables while it was read (empty for a down
# interface), and the for/do/test lines themselves reached "nft -f" as
# staged input. The atomic driver now stages multi-value rules through
# dedicated FWB_NFT_DYNRULE wrapper blocks OUTSIDE the ruleset heredoc; the
# wrapper appends every resolved copy into the same open transaction.
check_dynamic_interface() {
    local name=dynamic-interface
    mkdir -p "$work/$name" "$output/../nft-dynif-output"
    if ! "$compiler" -4 -f "$work/xml/$name.fwb" -d "$work/$name" nft-test \
         > "$work/$name.compile.log" 2>&1; then
        cat "$work/$name.compile.log" >&2
        echo 'FAIL: dynamic interface address compile was rejected again' >&2
        return 1
    fi
    if grep -Fq 'Native nftables script contains legacy command' \
        "$work/$name.compile.log"; then
        echo 'FAIL: stale legacy-marker abort for dynamic interface' >&2
        return 1
    fi
    local -a generated=("$work/$name"/*.fw)
    [[ ${#generated[@]} == 1 && -s ${generated[0]} ]] || {
        echo 'FAIL: expected exactly one generated dynamic-interface script' >&2
        return 1
    }
    sh -n "${generated[0]}" || return 1
    if ! sh ci/check-nft-output.sh "${generated[0]}"; then
        echo 'FAIL: invalid native script structure for dynamic-interface' >&2
        return 1
    fi
    # The plain ruleset segments must use an UNQUOTED heredoc.
    grep -Fq 'cat >> "$FWB_NFT_TXN" <<FWB_NFT_RULESET' "${generated[0]}" || {
        echo 'FAIL: ruleset heredoc is missing or quoted' >&2
        return 1
    }
    if grep -Fq "<<'FWB_NFT_RULESET'" "${generated[0]}"; then
        echo 'FAIL: quoted ruleset heredoc returned' >&2
        return 1
    fi
    # Multi-value rules stage through wrapper loops OUTSIDE the heredoc.
    grep -Fq 'for i_eth1 in $i_eth1_list' "${generated[0]}" || {
        echo 'FAIL: no dynamic-interface wrapper loop for $i_eth1' >&2
        return 1
    }
    grep -Fq 'for i_eth1_network in $i_eth1_network_list' "${generated[0]}" || {
        echo 'FAIL: no attached-network wrapper loop for $i_eth1_network' >&2
        return 1
    }
    # The emitter must guard the per-value append and stay fail-soft: an
    # interface without addresses stages no rule instead of a broken one.
    grep -Fq 'test -n "$i_eth1" && cat >> "$FWB_NFT_TXN" <<FWB_NFT_DYNRULE' \
        "${generated[0]}" || {
        echo 'FAIL: dynamic rule copies are not guarded transaction appends' >&2
        return 1
    }
    grep -Fq 'test -n "$i_eth1_network" && cat >> "$FWB_NFT_TXN" <<FWB_NFT_DYNRULE' \
        "${generated[0]}" || {
        echo 'FAIL: attached-network copies are not guarded transaction appends' >&2
        return 1
    }
    # The wrapped rule itself still references the shell variable; it is
    # expanded by the per-rule FWB_NFT_DYNRULE heredoc at activation time.
    grep -Eq 'add rule ip filter .*ip saddr \$i_eth1([^_A-Za-z0-9]|$)' "${generated[0]}" || {
        echo 'FAIL: no rule references the dynamic interface address $i_eth1' >&2
        return 1
    }
    grep -Eq 'add rule ip filter .*ip saddr \$i_eth1_network' "${generated[0]}" || {
        echo 'FAIL: no rule references attached networks via $i_eth1_network' >&2
        return 1
    }
    # configure_interfaces() fills the loop lists before the staging starts.
    grep -Eq '^[[:space:]]*getaddr[[:space:]]+eth1[[:space:]]+i_eth1([[:space:]]|$)' "${generated[0]}" || {
        echo 'FAIL: generated script never resolves the dynamic interface address' >&2
        return 1
    }
    grep -Eq '^[[:space:]]*getnet[[:space:]]+eth1[[:space:]]+i_eth1_network([[:space:]]|$)' "${generated[0]}" || {
        echo 'FAIL: generated script never resolves attached networks' >&2
        return 1
    }
    grep -Fq 'fwb_nft_begin_transaction || exit 1' "${generated[0]}" || return 1
    grep -Fq 'fwb_nft_commit_transaction || exit 1' "${generated[0]}" || return 1
    cp -- "${generated[0]}" "$output/../nft-dynif-output/nft-ci-dynamic-interface.fw"
    echo 'PASS: dynamic-interface stages resolved copies outside the ruleset heredoc'
}

# Run-time DNSName objects used to print their raw host name into the
# staged ruleset; nft resolves names itself at commit time and aborts the
# whole atomic activation when a name carries several records
# ("Hostname resolves to multiple addresses"). Real-world projects use
# such names (e.g. imap.gmail.com), so atomic activation was effectively
# unusable. The compilers now register a sanitized $dn_ placeholder and
# the script expands every record at activation time through
# fwb_nft_resolve(), staging one rule copy per address into the same
# open transaction.
check_runtime_dns_name() {
    local name=runtime-dns-name
    mkdir -p "$work/$name" "$output/../nft-dns-output"
    if ! "$compiler" -4 -f "$work/xml/$name.fwb" -d "$work/$name" nft-test \
         > "$work/$name.compile.log" 2>&1; then
        cat "$work/$name.compile.log" >&2
        echo 'FAIL: run-time DNSName compile was rejected' >&2
        return 1
    fi
    local -a generated=("$work/$name"/*.fw)
    [[ ${#generated[@]} == 1 && -s ${generated[0]} ]] || {
        echo 'FAIL: expected exactly one generated runtime-dns-name script' >&2
        return 1
    }
    sh -n "${generated[0]}" || return 1
    if ! sh ci/check-nft-output.sh "${generated[0]}"; then
        echo 'FAIL: invalid native script structure for runtime-dns-name' >&2
        return 1
    fi
    # The resolver helper must ship with the generated script itself.
    grep -Fq 'fwb_nft_resolve() {' "${generated[0]}" || {
        echo 'FAIL: fwb_nft_resolve helper is missing' >&2
        return 1
    }
    # The wrapper loop resolves at activation time, IPv4 family pinned by
    # the compiled family of the rule.
    grep -Fq 'for dn_fwb_ci_rt_dns_example_org in $(fwb_nft_resolve "fwb-ci-rt-dns.example.org" 4)' \
        "${generated[0]}" || {
        echo 'FAIL: no resolver wrapper loop for the run-time DNSName' >&2
        return 1
    }
    # Every resolved record stages through a guarded transaction append.
    grep -Fq 'test -n "$dn_fwb_ci_rt_dns_example_org" && cat >> "$FWB_NFT_TXN" <<FWB_NFT_DYNRULE' \
        "${generated[0]}" || {
        echo 'FAIL: DNS rule copies are not guarded transaction appends' >&2
        return 1
    }
    grep -Eq 'add rule ip filter .*ip saddr \$dn_fwb_ci_rt_dns_example_org([^_A-Za-z0-9]|$)' \
        "${generated[0]}" || {
        echo 'FAIL: no rule references the DNS placeholder $dn_fwb_ci_rt_dns_example_org' >&2
        return 1
    }
    # A raw host name operand must never reach "nft -f" again.
    if grep -Eq 'ip saddr fwb-ci-rt-dns\.example\.org' "${generated[0]}"; then
        echo 'FAIL: raw DNS name printed as a rule operand' >&2
        return 1
    fi
    cp -- "${generated[0]}" "$output/../nft-dns-output/nft-ci-runtime-dns-name.fw"
    echo 'PASS: run-time DNSName stages one resolver-loop copy per record'
}

# Kernel-native nftables autoloads its conntrack/NAT modules, and appliance
# systems (OpenWrt 25.x) ship neither /lib/modules/$(uname -r) nor a
# modprobe binary: the iptables-era "find $MODULES_DIR ... modprobe"
# search aborted generated scripts right at the tool check. The
# load_modules() body must stay a documented no-op even when the
# "load kernel modules" firewall option is enabled, which imported
# iptables projects do.
check_module_loading() {
    local name=module-load-ignored
    mkdir -p "$work/$name"
    if ! "$compiler" -4 -f "$work/xml/$name.fwb" -d "$work/$name" nft-test \
         > "$work/$name.compile.log" 2>&1; then
        cat "$work/$name.compile.log" >&2
        echo 'FAIL: module-load-ignored compile was rejected' >&2
        return 1
    fi
    local -a generated=("$work/$name"/*.fw)
    [[ ${#generated[@]} == 1 && -s ${generated[0]} ]] || {
        echo 'FAIL: expected exactly one generated module-load-ignored script' >&2
        return 1
    }
    sh -n "${generated[0]}" || return 1
    if ! sh ci/check-nft-output.sh "${generated[0]}"; then
        echo 'FAIL: invalid native script structure for module-load-ignored' >&2
        return 1
    fi
    # The function stays (vlan/bonding modprobe users may follow later),
    # but its body must be a documented no-op: only ':' and comments.
    grep -Fq 'load_modules() {' "${generated[0]}" || {
        echo 'FAIL: load_modules function disappeared from the script' >&2
        return 1
    }
    if ! awk '/^load_modules\(\) \{$/ { in_body = 1; next }
              in_body && /^\}$/ { in_body = 0; exit !(body_ok == 1) }
              in_body && /^[[:space:]]*:([[:space:]]|$)/ { body_ok = 1; next }
              in_body && /^[[:space:]]*($|#)/ { next }
              in_body { body_ok = 0 }' "${generated[0]}"; then
        echo 'FAIL: load_modules body is not a pure no-op' >&2
        return 1
    fi
    # The activation path still calls load_modules (inert, kept for layout
    # compatibility), but nothing may reference the iptables-era module
    # search: no $MODPROBE use, no MODULES_DIR, no /lib/modules scan.
    grep -Fq 'load_modules "' "${generated[0]}" || {
        echo 'FAIL: activation no longer calls load_modules' >&2
        return 1
    }
    if grep -Eq '\$MODPROBE|MODULES_DIR|/lib/modules' "${generated[0]}"; then
        echo 'FAIL: iptables-era module search code still present' >&2
        return 1
    fi
    echo 'PASS: load_modules option stays accepted and emits a no-op'
}

# Prolog place "after policy reset" used to abort every atomic-mode compile,
# including single-rule compiles of migrated iptables firewalls. The prolog
# must now be generated and must run right before script_body() commits the
# nftables transaction, so it applies before the firewall policy is replaced.
check_prolog_after_flush() {
    local name=prolog-after-flush
    mkdir -p "$work/$name"
    if ! "$compiler" -4 -f "$work/xml/$name.fwb" -d "$work/$name" nft-test \
        > "$work/$name.compile.log" 2>&1; then
        cat "$work/$name.compile.log" >&2
        echo 'FAIL: prolog place "after policy reset" was rejected again' >&2
        return 1
    fi
    if grep -Fiq 'can not be used when policy is activated' \
        "$work/$name.compile.log"; then
        echo 'FAIL: the stale after-flush abort is still emitted' >&2
        return 1
    fi
    local -a files=()
    shopt -s nullglob
    files=("$work/$name"/*.fw)
    shopt -u nullglob
    if (( ${#files[@]} != 1 )) || [[ ! -s "${files[0]}" ]]; then
        echo 'FAIL: expected exactly one generated script for prolog-after-flush' >&2
        return 1
    fi
    if ! sh ci/check-nft-output.sh "${files[0]}"; then
        echo 'FAIL: invalid native script structure for prolog-after-flush' >&2
        return 1
    fi
    grep -Fq 'ci-prolog-after-flush' "${files[0]}" || {
        echo 'FAIL: generated script lost the prolog commands' >&2
        return 1
    }
    grep -Fq 'ci_provider_ip' "${files[0]}" || {
        echo 'FAIL: generated script lost the epilog commands' >&2
        return 1
    }
    # The prolog must run before the nftables transaction, the epilog after it.
    if ! awk '
        /^[[:space:]]*start\)/ { in_start = 1; seen_prolog = 0; seen_body = 0;
                                 ok_prolog = 0; ok_epilog = 0; next }
        in_start && /^[[:space:]]*;;/ { in_start = 0; next }
        in_start && /^[[:space:]]*prolog_commands[[:space:]]*$/ {
            if (seen_body) ok_prolog = 0; else seen_prolog = 1; next }
        in_start && /^[[:space:]]*script_body[[:space:]]*$/ {
            ok_prolog = seen_prolog; seen_body = 1; next }
        in_start && /^[[:space:]]*epilog_commands[[:space:]]*$/ {
            if (seen_body) ok_epilog = 1; next }
        END { exit !(ok_prolog && ok_epilog) }
    ' "${files[0]}"; then
        echo 'FAIL: prolog/epilog are not placed around the nftables transaction' >&2
        return 1
    fi
    cp -- "${files[0]}" "$output/nft-ci-$name.fw"
    echo 'PASS: prolog-after-flush compiles and surrounds the nftables transaction'
}

# Named iproute2 routing tables (W3). The second Routing rule set must
# land in table ci_pbr while the main rule set keeps its historical
# keyword-less commands. With manage_rt_tables the script also appends
# the missing rt_tables entry; without it the commands use table 102.
_common_routing_table_greps() {
    local fw=$1 token=$2
    local -a needles=(
        "\$IP route add 192.168.2.0/24 via 192.168.1.10 dev eth1 table $token"
        "fwb_route_prepare 4 $token '192.168.2.0/24'"
        "fwb_route_committed 4 $token '192.168.2.0/24' '192.168.2.0/24 via 192.168.1.10 dev eth1'"
        "\$IP route add default via 192.168.1.10 dev eth1"
        "fwb_route_prepare 4 main 'default'"
        # W4.6: route labels carry the iproute2 table name they
        # install into (the label follows routing_table_name, so it
        # stays ci_pbr even in the numeric-id case).
        "echo \"Routing rule 0 (ci_pbr)\""
    )
    local needle
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$fw"; then
            echo "FAIL: routing-table fixture is missing: $needle" >&2
            return 1
        fi
    done
    # The main table must not gain a table keyword.
    if grep -Fq 'route add default via 192.168.1.10 dev eth1 table' "$fw"; then
        echo 'FAIL: main-table default route carries a table keyword' >&2
        return 1
    fi
    if grep -Eq "fwb_route_(prepare|committed) 4 $token 'default'" "$fw"; then
        echo 'FAIL: named table token was applied to the main default route' >&2
        return 1
    fi
    local begins finishes
    begins=$(grep -c 'FWB_ROUTING_INITIALIZED=1' "$fw")
    finishes=$(grep -c '^fwb_routing_finish$' "$fw")
    if [[ "$begins" != 1 || "$finishes" != 1 ]]; then
        echo "FAIL: routing functions initialized ${begins} times and finished ${finishes} times" >&2
        return 1
    fi
    return 0
}

check_routing_table() {
    check_positive routing-table 4 || return 1
    local fw="$output/nft-ci-routing-table.fw"
    _common_routing_table_greps "$fw" ci_pbr || return 1
    if grep -Fq 'FWB_ROUTE_ADOPT=1' "$fw"; then
        echo 'FAIL: adoption must stay off without the firewall option' >&2
        return 1
    fi
    if ! grep -Fq 'FWB_ROUTE_ADOPT=0' "$fw"; then
        echo 'FAIL: routing activation lost its adoption default' >&2
        return 1
    fi
    local ensures
    ensures=$(grep -c '^fwb_rt_tables_ensure ci_pbr 101 ' "$fw")
    if [[ "$ensures" != 1 ]]; then
        echo "FAIL: expected exactly one rt_tables maintenance call for ci_pbr; found $ensures" >&2
        return 1
    fi
    echo 'PASS: named routing table ci_pbr compiled with rt_tables maintenance'
}

check_routing_table_numeric() {
    check_positive routing-table-numeric 4 || return 1
    local fw="$output/nft-ci-routing-table-numeric.fw"
    _common_routing_table_greps "$fw" 102 || return 1
    if grep -Eq '^fwb_rt_tables_ensure +[^ ]+' "$fw"; then
        echo 'FAIL: numeric routing table must not maintain /etc/iproute2/rt_tables' >&2
        return 1
    fi
    if grep -Fq 'table ci_pbr' "$fw"; then
        echo 'FAIL: numeric-only routing table leaked the table name ci_pbr' >&2
        return 1
    fi
    echo 'PASS: named routing table compiles with its numeric table id'
}


# W4.5: adopt_foreign_routes lets the activation take over an existing
# route no script of this firewall installed (e.g. an OpenWrt netifd
# static route re-created at boot) instead of refusing it. Protected
# kernel, DHCP and RA routes stay untouchable even in adoption mode.
check_routing_adopt_foreign() {
    check_positive routing-adopt-foreign 4 || return 1
    local fw="$output/nft-ci-routing-adopt-foreign.fw"
    _common_routing_table_greps "$fw" ci_pbr || return 1
    if ! grep -Fq 'FWB_ROUTE_ADOPT=1' "$fw"; then
        echo 'FAIL: adopt_foreign_routes did not reach the routing activation' >&2
        return 1
    fi
    # The adoption branch and its rollback recording must ship, and the
    # refusal with its option hint stays available for adoption off.
    local -a needles=(
        'Adopting foreign route $dest'
        'refusing to replace foreign route $dest'
        'adopt_foreign_routes'
    )
    local needle
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$fw"; then
            echo "FAIL: routing-adopt-foreign fixture is missing: $needle" >&2
            return 1
        fi
    done
    echo 'PASS: adopt_foreign_routes switches the activation into adoption mode'
}


check_routing_in_deleted_objects() {
    check_positive routing-in-deleted-objects 4 || return 1
    local fw="$output/nft-ci-routing-in-deleted-objects.fw"
    if ! grep -Fq '$IP route add default via 192.168.1.10 dev eth1' "$fw"; then
        echo 'FAIL: parked Routing rule set changed the main default route' >&2
        return 1
    fi
    if grep -Fq 'Routing_1' "$fw"; then
        echo 'FAIL: parked Routing rule set leaked into the compiled script' >&2
        return 1
    fi
    echo 'PASS: Routing rule set parked in Deleted Objects is ignored by the compiler'
}


# IPRule objects (policy-based routing, W4). Every compiled ip rule is
# wrapped by the fwb_rule_prepare/fwb_rule_committed helpers; the quoted
# spec is the retire key of the shell state management.
check_ip_rule() {
    check_positive ip-rule 4 || return 1
    local fw="$output/nft-ci-ip-rule.fw"
    local spec="from 192.0.2.0/24 fwmark 64 iif eth0 oif eth1 lookup ci_iprule"
    local -a needles=(
        "# ip rule (policy-based routing)"
        "FWB_RULE_REPLACE=0"
        "fwb_rule_prepare 4 100 '$spec' && \\"
        "\$IP rule add pref 100 $spec && \\"
        "fwb_rule_committed 4 100 '$spec' \\"
        "|| route_command_error \"1 (ci_iprule)\""
        'fwb_rt_tables_ensure ci_iprule 103 '
        "\$IP route add default via 192.168.1.10 dev eth1"
    )
    local needle
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$fw"; then
            echo "FAIL: ip-rule fixture is missing: $needle" >&2
            return 1
        fi
    done
    if grep -Fq 'FWB_RULE_REPLACE=1' "$fw"; then
        echo 'FAIL: strict default strategy must not set FWB_RULE_REPLACE=1' >&2
        return 1
    fi
    if grep -Fq '$IP -6 rule add pref 100' "$fw"; then
        echo 'FAIL: the IPv4-marked ip rule leaked into the IPv6 command form' >&2
        return 1
    fi
    echo 'PASS: IPRule compiled into the strict ci_iprule lookup section'
}

check_ip_rule_ipv6() {
    # ip6 saddr / icmpv6 type: case_ipv6() in the generator flips the
    # preserved policy to IPv6; without compiled native rules the -6
    # script contains no FWB_NFT_RULESET block at all and the structure
    # check rejects it.
    check_positive ip-rule-ipv6 6 'ip6 saddr' 'icmpv6 type' || return 1
    local fw="$output/nft-ci-ip-rule-ipv6.fw"
    local spec="from 2001:db8::/32 lookup main"
    local -a needles=(
        "FWB_RULE_REPLACE=0"
        "fwb_rule_prepare 6 200 '$spec' && \\"
        "\$IP -6 rule add pref 200 $spec && \\"
        "fwb_rule_committed 6 200 '$spec' \\"
    )
    local needle
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$fw"; then
            echo "FAIL: ip-rule-ipv6 fixture is missing: $needle" >&2
            return 1
        fi
    done
    if grep -Fq '$IP rule add pref 200' "$fw"; then
        echo 'FAIL: the IPv6 ip rule emitted a plain v4 rule line' >&2
        return 1
    fi
    echo 'PASS: IPv6 IPRule compiled into the $IP -6 rule form'
}

check_ip_rule_replace() {
    check_positive ip-rule-replace 4 || return 1
    local fw="$output/nft-ci-ip-rule-replace.fw"
    local spec="fwmark 65 lookup 104"
    local -a needles=(
        "FWB_RULE_REPLACE=1"
        "fwb_rule_prepare 4 300 '$spec' && \\"
        "\$IP rule add pref 300 $spec && \\"
        "fwb_rule_committed 4 300 '$spec' \\"
    )
    local needle
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$fw"; then
            echo "FAIL: ip-rule-replace fixture is missing: $needle" >&2
            return 1
        fi
    done
    if grep -Fq 'FWB_RULE_REPLACE=0' "$fw"; then
        echo 'FAIL: the replace strategy still emits FWB_RULE_REPLACE=0' >&2
        return 1
    fi
    echo 'PASS: ip_rule_strategy=replace selects the flush helpers'
}


# IPRule objects in their own per-firewall IPRules rule set (W4.2).
# The rule set only adds to the "ip rule" section: it must never print
# a "Routing rule set" header or maintain /etc/iproute2/rt_tables.
check_ip_rule_set() {
    check_positive ip-rule-set 4 || return 1
    local fw="$output/nft-ci-ip-rule-set.fw"
    local spec="from 192.0.2.0/24 lookup main"
    local -a needles=(
        "# ip rule (policy-based routing)"
        "FWB_RULE_REPLACE=0"
        "fwb_rule_prepare 4 110 '$spec' && \\"
        "\$IP rule add pref 110 $spec && \\"
        "fwb_rule_committed 4 110 '$spec' \\"
        "\$IP route add default via 192.168.1.10 dev eth1"
    )
    local needle
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$fw"; then
            echo "FAIL: ip-rule-set fixture is missing: $needle" >&2
            return 1
        fi
    done
    if grep -Fq '# Routing rule set IP Rules' "$fw"; then
        echo 'FAIL: the IPRules rule set must not print a routing header' >&2
        return 1
    fi
    if grep -Eq '^fwb_rt_tables_ensure +[^ ]+' "$fw"; then
        echo 'FAIL: the IPRules rule set must not maintain rt_tables' >&2
        return 1
    fi
    echo 'PASS: the per-firewall IPRules rule set compiled into the ip rule section'
}


# W4.6: the rule set address family (GUI combo "Address Family") gates
# family-less ip rules. A fwmark-only rule carries no address, so it
# compiles once per family its rule set allows. The IPv4-only rule set
# (the default, both family flags False) must keep its rule out of the
# "$IP -6" section, the dual rule set must emit both twins. The gate is
# only visible in a default dual compile, which generates both address
# families into one script, so this check compiles the fixture twice.
check_ip_rule_ruleset_family() {
    check_positive ip-rule-ruleset-family 4 || return 1
    local name=ip-rule-ruleset-family
    local dual="$work/$name-dual"
    mkdir -p "$dual"
    if ! "$compiler" -f "$work/xml/$name.fwb" -d "$dual" nft-test \
        > "$work/$name.dual.compile.log" 2>&1; then
        cat "$work/$name.dual.compile.log" >&2
        echo "FAIL: native FWB compiler rejected $name (default dual compile)" >&2
        return 1
    fi
    local script
    local -a files=()
    shopt -s nullglob
    files=("$dual"/*.fw)
    shopt -u nullglob
    if (( ${#files[@]} != 1 )) || [[ ! -s "${files[0]}" ]]; then
        echo "FAIL: expected exactly one generated script for the dual compile" >&2
        return 1
    fi
    script="${files[0]}"
    if ! sh ci/check-nft-output.sh "$script"; then
        echo "FAIL: invalid native script structure for the dual compile" >&2
        return 1
    fi
    local spec="fwmark 66 lookup main"
    local -a needles=(
        "fwb_rule_prepare 4 400 '$spec' && \\"
        "\$IP rule add pref 400 $spec && \\"
        "fwb_rule_prepare 6 401 '$spec' && \\"
        "\$IP -6 rule add pref 401 $spec && \\"
    )
    local needle
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$script"; then
            echo "FAIL: dual compile of $name is missing: $needle" >&2
            return 1
        fi
    done
    if grep -Fq '$IP -6 rule add pref 400' "$script"; then
        echo 'FAIL: the IPv4-only rule set emitted an IPv6 fwmark twin' >&2
        return 1
    fi
    echo 'PASS: the rule set address family gates family-less fwmark ip rules'
}


# W4.3: an IPRule may select on a shell variable that the prolog fills
# at activation time (the dynamic provider address behind a modem).
# The helper must ship before the prolog runs; the ip rule section must
# guard the variable and expand it through a spec variable BEFORE
# fwb_rule_prepare compares the state, so the state file records the
# resolved address and a changed provider address retires the outdated
# kernel rule on the next run.
check_ip_rule_runtime_var() {
    check_positive ip-rule-runtime-var 4 || return 1
    local fw="$output/nft-ci-ip-rule-runtime-var.fw"
    local spec_var='fwb_rule_spec_4_120_0'
    local -a needles=(
        'fwb_get_provider_ip() {'
        'fwb_get_provider_ip eth0 192.168.1.10 || exit 1'
        "case \"\$provider_ip\" in \"\"|*:*) route_command_error"
        'runtime variable provider_ip is empty or not an IPv4 address'
        # Each .fw line below ends with ONE line-continuation
        # backslash; inside double quotes that is one escaped pair,
        # so the needles carry exactly two source backslashes, not
        # four: four produce two and never match the generated file.
        "$spec_var=\"from \$provider_ip lookup main\" && \\"
        "fwb_rule_prepare 4 120 \"\$$spec_var\" && \\"
        "\$IP rule add pref 120 \$$spec_var && \\"
        "fwb_rule_committed 4 120 \"\$$spec_var\" \\"
    )
    local needle
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$fw"; then
            echo "FAIL: ip-rule-runtime-var fixture is missing: $needle" >&2
            return 1
        fi
    done
    # The literal (unexpanded) spec must not reach the state helpers.
    if grep -Fq "fwb_rule_prepare 4 120 'from \$provider_ip" "$fw"; then
        echo 'FAIL: runtime-variable rule compared the unexpanded spec' >&2
        return 1
    fi
    if grep -Fq '$IP -6 rule add pref 120' "$fw"; then
        echo 'FAIL: the runtime-variable ip rule leaked into the IPv6 form' >&2
        return 1
    fi
    # The helper must be defined before the prolog function is even
    # declared; its definition sits with the other early shell
    # functions, routing_functions only reaches the script later.
    if ! awk '/^fwb_get_provider_ip\(\) \{/ { helper = NR }
              /^prolog_commands\(\) \{/ { prolog = NR; exit }
              END { exit !(helper && prolog && helper < prolog) }' "$fw"; then
        echo 'FAIL: fwb_get_provider_ip is not defined before the prolog' >&2
        return 1
    fi
    # The expansion happens per combination, so a changed provider
    # address changes the state entry and retires the old rule.
    if grep -Fq "$spec_var=" "$fw" && ! grep -Fq "\"\$$spec_var\"" "$fw"; then
        echo 'FAIL: spec variable is assigned but never expanded' >&2
        return 1
    fi
    echo 'PASS: runtime-variable IPRule ships the helper, guard and state-safe expansion'
}

# W4.4: runtime shell variables in policy, NAT and mangle rules. The
# compiled rule text references the guarded $rv_<name> placeholder and
# lives in a FWB_NFT_DYNRULE wrapper block outside the staged heredoc,
# so the needles grep the whole generated script, not the extracted
# start transaction. The wrapper must fail the activation (exit 1
# before the commit, old policy stays active) when the user variable is
# unset, and the raw variable must never reach the staged rule text.
check_runtime_var_wrapper() {
    local name=$1 fw=$2
    local -a needles=(
        'fwb_get_provider_ip() {'
        'fwb_get_provider_ip eth0 192.168.1.10 || exit 1'
        'test -n "$provider_ip" || {'
        'rv_provider_ip="$provider_ip"'
        'test -n "$rv_provider_ip" && cat >> "$FWB_NFT_TXN" <<FWB_NFT_DYNRULE'
    )
    local needle
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$fw"; then
            echo "FAIL: $name fixture is missing: $needle" >&2
            return 1
        fi
    done
    # The helper must be defined before the prolog function runs.
    if ! awk '/^fwb_get_provider_ip\(\) \{/ { helper = NR }
              /^prolog_commands\(\) \{/ { prolog = NR; exit }
              END { exit !(helper && prolog && helper < prolog) }' "$fw"; then
        echo "FAIL: fwb_get_provider_ip is not defined before the prolog in $name" >&2
        return 1
    fi
    return 0
}

check_nat_runtime_var() {
    check_positive nat-snat-runtime-var 4 || return 1
    local fw="$output/nft-ci-nat-snat-runtime-var.fw"
    if ! check_runtime_var_wrapper nat-snat-runtime-var "$fw"; then
        return 1
    fi
    # One guarded SNAT row in the nat table: the fwmark match from the
    # TagService plus the placeholder translation.
    if ! grep -Eq 'add rule ip nat POSTROUTING .*meta mark == 4.* snat to \$rv_provider_ip' "$fw"; then
        echo 'FAIL: no guarded SNAT row translating to $rv_provider_ip' >&2
        return 1
    fi
    if grep -Fq 'snat to $provider_ip' "$fw"; then
        echo 'FAIL: raw runtime variable reached the SNAT translation' >&2
        return 1
    fi
    echo 'PASS: runtime-variable SNAT stages through the guarded wrapper'
}

check_policy_runtime_var() {
    check_positive policy-src-runtime-var 4 || return 1
    local fw="$output/nft-ci-policy-src-runtime-var.fw"
    if ! check_runtime_var_wrapper policy-src-runtime-var "$fw"; then
        return 1
    fi
    if ! grep -Eq 'add rule ip filter .*ip saddr \$rv_provider_ip' "$fw"; then
        echo 'FAIL: no guarded filter row matching $rv_provider_ip' >&2
        return 1
    fi
    if grep -Fq 'ip saddr $provider_ip' "$fw"; then
        echo 'FAIL: raw runtime variable reached the filter match' >&2
        return 1
    fi
    echo 'PASS: runtime-variable filter rule stages through the guarded wrapper'
}

check_mangle_runtime_var() {
    # The only mangle row is the wrapper copy; pass no ruleset needles.
    check_positive mangle-src-runtime-var 4 || return 1
    local fw="$output/nft-ci-mangle-src-runtime-var.fw"
    if ! check_runtime_var_wrapper mangle-src-runtime-var "$fw"; then
        return 1
    fi
    if ! grep -Eq 'add rule ip mangle .*ip saddr \$rv_provider_ip.*meta mark set 66' "$fw"; then
        echo 'FAIL: no guarded mangle row marking traffic from $rv_provider_ip' >&2
        return 1
    fi
    echo 'PASS: runtime-variable mangle rule stages through the guarded wrapper'
}


failures=0
cases=0
run_case() {
    local name=$1
    shift
    cases=$((cases+1))
    if "$@"; then
        printf 'RESULT: PASS %s\n' "$name"
    else
        failures=$((failures+1))
        printf 'RESULT: FAIL %s\n' "$name" >&2
    fi
}

run_case ipv6-icmp check_positive ipv6-icmp 6 'ip6 saddr' 'icmpv6 type'
check_ipv6_ndp_with_routes() {
    check_positive ipv6-ndp 6 'icmpv6 type 128' 'icmpv6 type 135' 'icmpv6 type 136' || return 1
    local fw="$output/nft-ci-ipv6-ndp.fw"
    local needle
    local -a needles=(
        '$IP route add default via 192.168.1.10 dev eth1'
        '$IP -6 route add 2001:db8:9::/64 metric 100 via 2001:db8:1::fe dev eth0'
        '$IP -6 route add 2001:db8:8::/64 via fe80::1 dev eth0'
        '$IP -6 route add default via fe80::1 dev eth0'
        '$IP -6 route add 2001:db8:50::/64 metric 20 nexthop via 2001:db8:1::2 dev eth0 nexthop via 2001:db8:2::2 dev eth1'
    )
    for needle in "${needles[@]}"; do
        if ! grep -Fq "$needle" "$fw"; then
            echo "FAIL: generated script is missing compiler route: $needle" >&2
            return 1
        fi
    done
    local begins finishes
    begins=$(grep -c 'FWB_ROUTING_INITIALIZED=1' "$fw")
    finishes=$(grep -c '^fwb_routing_finish$' "$fw")
    if [[ "$begins" != 1 || "$finishes" != 1 ]]; then
        echo "FAIL: routing functions initialized ${begins} times and finished ${finishes} times" >&2
        return 1
    fi
    if grep -Eq 'route flush|while read route' "$fw"; then
        echo 'FAIL: generated routing script flushes or walks the whole routing table' >&2
        return 1
    fi
    echo 'PASS: compiler emitted one dual-stack routing activation'
}

run_case ipv6-ndp check_ipv6_ndp_with_routes
run_case ipv6-route-rollback check_positive ipv6-route-rollback 6 'icmpv6 type 128'
run_case reject-ipv6-route-link-local check_negative reject-ipv6-route-link-local 'Link-local IPv6 gateway requires an interface' 6
run_case reject-ipv6-route-netmask check_negative reject-ipv6-route-netmask 'has invalid netmask' 6
run_case reject-ipv6-route-mixed check_negative reject-ipv6-route-mixed 'Routing rule mixes IPv4 and IPv6' 6
run_case udp-workhours check_positive udp-workhours 4 'meta hour' 'meta day'
run_case reject-hashlimit-bad-mode check_negative reject-hashlimit-bad-mode 'Unsupported native nftables hashlimit mode'
run_case reject-hashlimit-icmp-port check_negative reject-hashlimit-icmp-port 'Native nftables port-key hashlimit needs a TCP or UDP service'
run_case hashlimit-srcip check_positive hashlimit-srcip 4 'add set ip filter fwb_ci_srcip \{ type ipv4_addr; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip \{ ip saddr limit rate 8/second burst 4 packets \}'
run_case hashlimit-srcip-dstport check_positive hashlimit-srcip-dstport 4 'add set ip filter fwb_ci_srcip_dstport \{ type ipv4_addr \. inet_service; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip_dstport \{ ip saddr \. tcp dport limit rate 8/second burst 4 packets \}'
run_case hashlimit-udp-srcip-dstport check_positive hashlimit-udp-srcip-dstport 4 'add set ip filter fwb_ci_srcip_dstport \{ type ipv4_addr \. inet_service; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip_dstport \{ ip saddr \. udp dport limit rate 8/second burst 4 packets \}'
run_case ipv6-hashlimit-srcip check_positive ipv6-hashlimit-srcip 6 'add set ip6 filter fwb_ci_srcip \{ type ipv6_addr; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip \{ ip6 saddr limit rate 8/second burst 4 packets \}'
run_case ipv6-hashlimit-srcip-dstport check_positive ipv6-hashlimit-srcip-dstport 6 'add set ip6 filter fwb_ci_srcip_dstport \{ type ipv6_addr \. inet_service; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip_dstport \{ ip6 saddr \. tcp dport limit rate 8/second burst 4 packets \}'
run_case user-service-outbound check_user_service user-service-outbound 'meta skuid 1000'
run_case negated-user-service-outbound check_user_service negated-user-service-outbound 'meta skuid != 1000'
run_case policy-fragments check_positive policy-fragments 4 'ip frag-off'
run_case nat-fragments check_positive nat-fragments 4 'ip frag-off'
# The native backend prints set-capable ODst as one inline nftables
# address set, so this negation lowering stages ONE positive-match
# return row ("ip daddr { 192.0.2.101, 192.0.2.102 } return") instead
# of one row per object; the destination needle accepts both shapes.
run_case negated-nat-odst check_negated_nat negated-nat-odst 'ip daddr (\{ )?192\.0\.2\.10[12]' 'snat to 192\.0\.2\.100'
run_case multi-address-set check_multi_address_set multi-address-set
run_case nat-multi-address-set check_nat_multi_address_set nat-multi-address-set
run_case nat-masquerade check_nat_masquerade nat-masquerade
run_case mangle-tag check_mangle_tag mangle-tag
run_case rule-counter check_rule_counter rule-counter
run_case mark-match check_mark_match mark-match
run_case mangle-classify check_mangle_classify mangle-classify
run_case routing-table check_routing_table
run_case routing-table-numeric check_routing_table_numeric
run_case routing-adopt-foreign check_routing_adopt_foreign
run_case reject-routing-table-duplicate check_negative reject-routing-table-duplicate 'use the same routing table id 101'
run_case routing-in-deleted-objects check_routing_in_deleted_objects
run_case ip-rule check_ip_rule
run_case ip-rule-ipv6 check_ip_rule_ipv6
run_case ip-rule-replace check_ip_rule_replace
run_case ip-rule-set check_ip_rule_set
run_case ip-rule-ruleset-family check_ip_rule_ruleset_family
run_case ip-rule-runtime-var check_ip_rule_runtime_var
run_case reject-ip-rule-var-conflict check_negative reject-ip-rule-var-conflict 'combines static source addresses with runtime variable'
run_case reject-ip-rule-var-badname check_negative reject-ip-rule-var-badname 'is not a valid shell variable name'
run_case reject-ip-rule-duplicate-priority check_negative reject-ip-rule-duplicate-priority 'use the same ip rule priority 100'
# W4.4: runtime shell variables in policy, NAT and mangle rules stage
# through the same guarded wrapper mechanism as the W4.3 ip rules.
run_case nat-snat-runtime-var check_nat_runtime_var
run_case policy-src-runtime-var check_policy_runtime_var
run_case mangle-src-runtime-var check_mangle_runtime_var
run_case reject-nat-runtime-var-conflict check_negative reject-nat-runtime-var-conflict 'combines static translated source addresses with runtime variable'
run_case reject-nat-runtime-var-badname check_negative reject-nat-runtime-var-badname 'is not a valid shell variable name'
run_case reject-policy-runtime-var-conflict check_negative reject-policy-runtime-var-conflict 'combines static source addresses with runtime variable'
run_case ipv4-option-rr check_positive ipv4-option-rr 4 'ip option rr exists'
run_case ipv4-option-lsrr check_positive ipv4-option-lsrr 4 'ip option lsrr exists'
run_case ipv4-option-ssrr check_positive ipv4-option-ssrr 4 'ip option ssrr exists'
run_case ipv4-option-ra check_positive ipv4-option-ra 4 'ip option ra exists'
run_case ipv4-option-any check_positive ipv4-option-any 4 'ip hdrlength > 5'
run_case ipv4-option-combined check_positive ipv4-option-combined 4 'ip option lsrr exists ip option rr exists'
run_case negated-ipv4-option-rr check_negated_ip_service negated-ipv4-option-rr 'ip option rr exists'
run_case negated-ipv4-option-ra check_negated_ip_service negated-ipv4-option-ra 'ip option ra exists'
run_case negated-ipv4-option-any check_negated_ip_service negated-ipv4-option-any 'ip hdrlength > 5'
run_case negated-ipv4-option-combined check_negated_ip_service negated-ipv4-option-combined 'ip option lsrr exists ip option rr exists'
run_case negated-ipv4-fragment check_negated_ip_service negated-ipv4-fragment 'ip frag-off'
run_case reject-negated-ipv4-timestamp check_negative reject-negated-ipv4-timestamp 'Native nftables IPv4 timestamp option matching is not supported'
run_case reject-policy-options check_negative reject-policy-options 'Native nftables IPv4 timestamp option matching is not supported'
run_case reject-nat-options check_negative reject-nat-options 'Native nftables NAT IP option matching is not supported'
# Use the same explicit native map for contiguous and sparse IPv4 LB;
# reject unsafe target objects or unsupported address+port translations.
# IPv6 uses the exact same per-connection distribution instead of a DNAT
# address range. Real packet fixtures are exercised by the NAT LB kernel job.
run_case ipv6-nat-lb-contiguous check_ipv6_lb_transport ipv6-nat-lb-contiguous 'dnat to numgen random mod 2 map \{ 0 : 2001:db8:2::100, 1 : 2001:db8:2::101 \}'
run_case ipv6-nat-lb-sparse check_ipv6_lb_transport ipv6-nat-lb-sparse 'dnat to numgen random mod 2 map \{ 0 : 2001:db8:2::100, 1 : 2001:db8:2::103 \}'
run_case packet-ipv6-nat-lb-contiguous check_positive packet-ipv6-nat-lb-contiguous 6 'tcp dport 80' 'dnat to numgen random mod 2 map \{ 0 : 2001:db8:2::100, 1 : 2001:db8:2::101 \}'
run_case packet-ipv6-nat-lb-sparse check_positive packet-ipv6-nat-lb-sparse 6 'tcp dport 80' 'dnat to numgen random mod 2 map \{ 0 : 2001:db8:2::100, 1 : 2001:db8:2::103 \}'
run_case reject-ipv6-nat-lb-network check_negative reject-ipv6-nat-lb-network 'Native nftables load-balancing destinations must be host addresses of the selected IP family' 6
run_case reject-ipv6-nat-lb-duplicate check_negative reject-ipv6-nat-lb-duplicate 'Duplicate native nftables load-balancing destination' 6
run_case reject-ipv6-nat-lb-port-translation check_negative reject-ipv6-nat-lb-port-translation 'Native nftables load-balancing address maps cannot translate ports' 6
run_case nat-lb-contiguous check_positive nat-lb-contiguous 4 'dnat to numgen random mod 2 map \{ 0 : 192\.168\.1\.100, 1 : 192\.168\.1\.101 \}'
run_case nat-lb-sparse check_positive nat-lb-sparse 4 'dnat to numgen random mod 2 map \{ 0 : 192\.168\.1\.100, 1 : 192\.168\.1\.103 \}'
# Dedicated packet fixtures use the same FWB-generated DNAT but explicitly
# allow TCP/80 forwarding, so isolated kernel tests exercise real connections.
run_case packet-nat-lb-sparse check_positive packet-nat-lb-sparse 4 'tcp dport 80' 'dnat to numgen random mod 2 map \{ 0 : 192\.168\.1\.100, 1 : 192\.168\.1\.103 \}'
run_case packet-nat-lb-contiguous check_positive packet-nat-lb-contiguous 4 'tcp dport 80' 'dnat to numgen random mod 2 map \{ 0 : 192\.168\.1\.100, 1 : 192\.168\.1\.101 \}'
run_case reject-nat-lb-network check_negative reject-nat-lb-network 'Native nftables load-balancing destinations must be host addresses of the selected IP family'
run_case reject-nat-lb-duplicate check_negative reject-nat-lb-duplicate 'Duplicate native nftables load-balancing destination'
run_case reject-nat-lb-port-translation check_negative reject-nat-lb-port-translation 'Native nftables load-balancing address maps cannot translate ports'
run_case reject-timezone check_negative reject-timezone 'xt_time kernel timezone mode is not supported by native nftables'
run_case prolog-after-flush check_prolog_after_flush
# Real traffic fixtures are compiled from FWB XML, never handwritten nft.
# Their emitted policies are exercised against real packets in ci/check-nft-packets.py.
run_case packet-tcp-input check_positive packet-tcp-input 4 'tcp dport 80'
run_case packet-udp-forward check_positive packet-udp-forward 4 'udp dport 53'
run_case packet-snat check_positive packet-snat 4 'udp dport 53' 'snat to 192\.0\.2\.100'
run_case packet-dnat check_positive packet-dnat 4 'tcp dport 80' 'ip daddr 192\.0\.2\.101' 'dnat to 192\.168\.1\.100'
run_case dynamic-address-sets check_dynamic_sets
run_case dynamic-interface check_dynamic_interface
run_case runtime-dns-name check_runtime_dns_name
run_case module-load-ignored check_module_loading
run_case reject-addressless-interface check_negative reject-addressless-interface 'it has no IP address and is not marked dynamic'
run_case reject-runtime-address-tables check_negative reject-runtime-address-tables 'requires named nftables sets'
# Ancillary native runtime guard; not an additional FWB XML fixture.
if ! check_dynamic_ipv6_routes; then
    failures=$((failures+1))
fi


printf 'FWB XML fixture matrix: %d cases; %d passed; %d failed\n' \
    "$cases" "$((cases - failures))" "$failures"
if (( failures )); then
    exit 1
fi
echo 'PASS: real FWB XML fixture matrix including dynamic address tables'
