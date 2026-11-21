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

    # Store the extracted ruleset for reproducible diagnostics.  Testing the
    # script preamble could accidentally accept unrelated IPv6 addresses.
    if ! awk '/<<\047FWB_NFT_RULESET\047/ { on=1; next } /^FWB_NFT_RULESET$/ { on=0 } on { print }' \
        "$generated" > "$work/$name.ruleset.nft"; then
        echo "FAIL: could not extract native ruleset for $name" >&2
        return 1
    fi
    local table_family=ip
    [[ "$family" == 6 ]] && table_family=ip6
    if ! grep -Eq "^add table $table_family fwb_filter[[:space:]]*\$" "$work/$name.ruleset.nft"; then
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
        elif ! grep -Eq "^add rule $table_family fwb_(filter|nat|mangle) .*${expected}" "$work/$name.ruleset.nft"; then
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
    match = re.fullmatch(r'add rule ip fwb_filter (\S+) (.+)', line)
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
               if re.match(r'^add rule ip fwb_filter OUTPUT ', line)
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
        if ! grep -Eq "^add rule ip6 fwb_${table} .*meta l4proto tcp " "$rules"; then
            echo "FAIL: $name has no extension-header-safe TCP selector in $table" >&2
            return 1
        fi
    done
    if grep -Eq '^add rule ip6 fwb_(filter|nat) .*ip6 nexthdr tcp ' "$rules"; then
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
    grep -Eq 'add rule ip fwb_filter .*ip saddr @bad_guys' "${generated[0]}" || return 1
    grep -Fq "fwb_nft_stage_one_address_table 'bad_guys' '/tmp/fwb-pr6-ci-address-set.data'" "${generated[0]}" || return 1
    # block_action() has a separate emergency-policy transaction, so its
    # add-table declarations are not duplicates in the start transaction.
    if awk '
        /^block_action\(\) \{/ { in_block = 1; next }
        in_block && /^}/ { in_block = 0; next }
        !in_block && /^add table ip fwb_filter[[:space:]]*$/ { duplicate = 1 }
        END { exit !duplicate }
    ' "${generated[0]}"; then
        echo 'Unexpected duplicate add-table declaration in set mode' >&2
        return 1
    fi
    cp -- "${generated[0]}" "$output/../nft-sets-output/nft-ci-dynamic-address-sets.fw"
    echo 'PASS: dynamic-address-sets generated from real FWB AddressTable'
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
run_case hashlimit-srcip check_positive hashlimit-srcip 4 'add set ip fwb_filter fwb_ci_srcip \{ type ipv4_addr; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip \{ ip saddr limit rate 8/second burst 4 packets \}'
run_case hashlimit-srcip-dstport check_positive hashlimit-srcip-dstport 4 'add set ip fwb_filter fwb_ci_srcip_dstport \{ type ipv4_addr \. inet_service; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip_dstport \{ ip saddr \. tcp dport limit rate 8/second burst 4 packets \}'
run_case hashlimit-udp-srcip-dstport check_positive hashlimit-udp-srcip-dstport 4 'add set ip fwb_filter fwb_ci_srcip_dstport \{ type ipv4_addr \. inet_service; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip_dstport \{ ip saddr \. udp dport limit rate 8/second burst 4 packets \}'
run_case ipv6-hashlimit-srcip check_positive ipv6-hashlimit-srcip 6 'add set ip6 fwb_filter fwb_ci_srcip \{ type ipv6_addr; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip \{ ip6 saddr limit rate 8/second burst 4 packets \}'
run_case ipv6-hashlimit-srcip-dstport check_positive ipv6-hashlimit-srcip-dstport 6 'add set ip6 fwb_filter fwb_ci_srcip_dstport \{ type ipv6_addr \. inet_service; size 65535; flags dynamic,timeout; timeout 3000ms; \}' 'update @fwb_ci_srcip_dstport \{ ip6 saddr \. tcp dport limit rate 8/second burst 4 packets \}'
run_case user-service-outbound check_user_service user-service-outbound 'meta skuid 1000'
run_case negated-user-service-outbound check_user_service negated-user-service-outbound 'meta skuid != 1000'
run_case policy-fragments check_positive policy-fragments 4 'ip frag-off'
run_case nat-fragments check_positive nat-fragments 4 'ip frag-off'
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
# Real traffic fixtures are compiled from FWB XML, never handwritten nft.
# Their emitted policies are exercised against real packets in ci/check-nft-packets.py.
run_case packet-tcp-input check_positive packet-tcp-input 4 'tcp dport 80'
run_case packet-udp-forward check_positive packet-udp-forward 4 'udp dport 53'
run_case packet-snat check_positive packet-snat 4 'udp dport 53' 'snat to 192\.0\.2\.100'
run_case packet-dnat check_positive packet-dnat 4 'tcp dport 80' 'ip daddr 192\.0\.2\.101' 'dnat to 192\.168\.1\.100'
run_case dynamic-address-sets check_dynamic_sets
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
