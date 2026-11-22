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

# Do not let the first failing fixture hide the other six outcomes.
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
