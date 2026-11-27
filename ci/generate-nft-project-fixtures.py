#!/usr/bin/env python3
"""Create real FWB XML regression cases from the preserved nft-test project.

No hand-written schema guesses: every variant starts from the checked-in FWB
project and references real service, address and interval objects in that file.
Generated XML belongs only to disposable CI artifacts, not the repository.
"""
import argparse
from copy import deepcopy
from pathlib import Path
import xml.etree.ElementTree as ET

NS = 'http://www.fwbuilder.org/1.0/'
ET.register_namespace('', NS)


def tag(name):
    return '{%s}%s' % (NS, name)


def only(root, expression):
    found = root.findall(expression)
    if len(found) != 1:
        raise ValueError('%s: expected exactly one object; found %d' % (expression, len(found)))
    return found[0]


def replace_ref(parent, child, ref):
    element = only(parent, './' + tag(child))
    found = list(element)
    if len(found) != 1 or 'ref' not in found[0].attrib:
        raise ValueError('unexpected FWB rule element ' + child)
    found[0].set('ref', ref)


def prepare(tree):
    root = tree.getroot()
    fw = only(root, ".//%s[@name='nft-test']" % tag('Firewall'))
    if fw.get('platform') != 'nftables':
        raise ValueError('original project no longer uses the nftables platform')
    policy = only(fw, './%s' % tag('Policy'))
    nat = only(fw, './%s' % tag('NAT'))
    pr = only(policy, "./%s[@id='id9001X30989']" % tag('PolicyRule'))
    nr = only(nat, "./%s[@id='id2842X30989']" % tag('NATRule'))
    # Guard the baseline test semantics before modifying cloned projects.
    if only(pr, './' + tag('Srv'))[0].get('ref') != 'tcp-HTTP':
        raise ValueError('baseline policy service changed')
    if only(nr, './' + tag('OSrv'))[0].get('ref') != 'sysid1':
        raise ValueError('baseline NAT service changed')
    return root, fw, pr, nr


def case_ipv6(tree):
    root, fw, pr, _ = prepare(tree)
    # -6 selects the compiler pass, but RuleSet::matchingAddressFamily()
    # also requires an IPv6-enabled Policy. The preserved project is IPv4.
    policy = only(fw, './' + tag('Policy'))
    if (policy.get('ipv4_rule_set'), policy.get('ipv6_rule_set')) != ('False', 'False'):
        raise ValueError('unexpected baseline policy address family')
    policy.set('ipv4_rule_set', 'False')
    policy.set('ipv6_rule_set', 'True')
    # The preserved Policy begins with an unconditional deny rule. For the
    # IPv6 fixture, place the specific ICMPv6 allow BEFORE that fallback deny;
    # otherwise the FWB shadowing check correctly rejects the allow rule.
    fallback = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    if (list(policy)[:2] != [fallback, pr]
            or fallback.get('position') != '0'
            or fallback.get('action') != 'Deny'
            or pr.get('position') != '1'
            or pr.get('action') != 'Accept'):
        raise ValueError('unexpected baseline policy order: cannot reorder IPv6 fixture')
    policy.remove(pr)
    policy.insert(0, pr)
    pr.set('position', '0')
    fallback.set('position', '1')
    replace_ref(pr, 'Src', 'id2088X75851')  # RFC 3849 documentation IPv6 /32
    only(pr, './' + tag('Src')).set('neg', 'False')
    replace_ref(pr, 'Dst', 'sysid0')
    replace_ref(pr, 'Srv', 'ipv6-icmp-ping_request')
    pr.set('direction', 'Both')
    # Stateful ICMPv6 is automatically converted to stateless by the policy
    # compiler. That emits a warning and a non-zero FWCOMPILER_WARNING status
    # even after writing a complete script. Declare the intended semantics
    # explicitly instead of treating compiler warnings as successful builds.
    rule_options = only(pr, './' + tag('PolicyRuleOptions'))
    stateless = only(rule_options, "./%s[@name='stateless']" % tag('Option'))
    if (stateless.text or '').strip() != 'False':
        raise ValueError('unexpected baseline IPv6 policy statefulness')
    stateless.text = 'True'
    # Add documentation-only IPv6 addresses to the existing FWB interfaces.
    for name, address in [('eth0', '2001:db8:1::1'), ('eth1', '2001:db8:2::1')]:
        iface = only(fw, "./%s[@name='%s']" % (tag('Interface'), name))
        v6 = ET.Element(tag('IPv6'), {
            'id': 'fwb-ci-ipv6-' + name, 'name': 'ci-' + name + '-v6',
            'comment': 'CI documentation address', 'ro': 'False',
            'address': address, 'netmask': '64',
        })
        iface.insert(len(iface) - 1, v6)  # immediately before InterfaceOptions


def case_ipv6_ndp(tree):
    """IPv6 echo via dynamic neighbor discovery, with explicit FWB NS/NA permits."""
    case_ipv6(tree)
    root = tree.getroot()
    fw = only(root, ".//%s[@name='nft-test']" % tag('Firewall'))
    policy = only(fw, './' + tag('Policy'))
    echo = only(policy, "./%s[@id='id9001X30989']" % tag('PolicyRule'))
    deny = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    if list(policy)[:2] != [echo, deny]:
        raise ValueError('unexpected IPv6 allow/fallback order for NDP fixture')
    # Keep the echo allow restricted to the documentation source prefix.
    # Neighbor discovery can legitimately originate from :: or fe80::/10,
    # so its two *separate* rules need wildcard source/destination matches.
    for pos, suffix, service in (
            (1, 'ns', 'ipv6-icmp-neighbrsol'),
            (2, 'na', 'ipv6-icmp-neighbradv')):
        rule = deepcopy(echo)
        rule.set('id', 'fwb-ci-ndp-' + suffix)
        rule.set('position', str(pos))
        rule.set('comment', 'CI: allow ICMPv6 neighbor ' + suffix.upper())
        replace_ref(rule, 'Src', 'sysid0')
        replace_ref(rule, 'Dst', 'sysid0')
        replace_ref(rule, 'Srv', service)
        policy.insert(pos, rule)
    deny.set('position', '3')
    _install_successful_ipv6_routes(tree)


def case_udp_workhours(tree):
    _, _, pr, _ = prepare(tree)
    replace_ref(pr, 'Srv', 'udp-DNS')
    replace_ref(pr, 'When', 'int-workhours')


def case_policy_fragments(tree):
    _, _, pr, _ = prepare(tree)
    replace_ref(pr, 'Srv', 'ip-IP_Fragments')


def case_nat_fragments(tree):
    _, _, _, nr = prepare(tree)
    replace_ref(nr, 'OSrv', 'ip-IP_Fragments')


def case_negated_nat_odst(tree):
    """SNAT with a two-object NEG ODst, lowering like iptables NAT negation.

    Regression test: NEG ODst in a translation rule ran doODstNegation,
    whose generated rows keep the original rule type but jump to a
    temporary chain that positively matches the negated destination and
    returns. The native nftables PrintRule derived the verdict from the
    rule type alone, so the jump row aborted with "Unsupported native
    nftables SNAT target" and the return row with "Unsupported native
    nftables NAT rule type". The verdict now mirrors iptables
    "-j $ipt_target" using native jump / return statements.
    """
    root, fw, _, _ = prepare(tree)
    nat = only(fw, './%s' % tag('NAT'))
    rule = only(nat, "./%s[@id='id2842X30989']" % tag('NATRule'))
    target = only(rule, './' + tag('ODst'))
    if [o.get('ref') for o in target] != ['sysid0']:
        raise ValueError('unexpected original NAT rule destination')
    # Two documentation destinations so single-object negation does not
    # apply and the generic three-row negation lowering is exercised.
    cloned = deepcopy(only(root, ".//%s[@id='id11875X30989']" % tag('IPv4')))
    cloned.set('id', 'fwb-ci-nat-neg-dst-102')
    cloned.set('name', 'CI negated NAT destination 192.0.2.102')
    cloned.set('address', '192.0.2.102')
    only(root, ".//%s[@id='id1550X1251']" % tag('ObjectGroup')).append(cloned)
    replace_ref(rule, 'ODst', 'id11875X30989')
    ET.SubElement(target, tag('ObjectRef'), {'ref': 'fwb-ci-nat-neg-dst-102'})
    target.set('neg', 'True')
    # Keep the verified translation shape: 192.168.1.0/24 -> 192.0.2.100.
    replace_ref(rule, 'OSrc', 'id3DC75CE7-1')
    only(rule, './' + tag('OSrc')).set('neg', 'False')
    only(rule, './' + tag('OSrv')).set('neg', 'False')
    for other in nat.findall('./' + tag('NATRule')):
        other.set('disabled', 'False' if other is rule else 'True')


def _case_native_ipv4_options(tree, enabled):
    _, _, pr, _ = prepare(tree)
    service = only(tree.getroot(), ".//" + tag('IPService') + "[@id='ip-RR']")
    if service.get('rr') != 'True' or service.get('ts') != 'False':
        raise ValueError('unexpected baseline IPv4 RR service')
    flags = ('any_opt', 'lsrr', 'ssrr', 'rr', 'ts', 'rtralt')
    if not set(enabled).issubset(set(flags) - {'ts'}):
        raise ValueError('unsupported native IPv4 fixture flag')
    for flag in flags:
        if service.get(flag) not in (None, 'True', 'False'):
            raise ValueError('unexpected IPv4 option attribute')
        service.set(flag, 'True' if flag in enabled else 'False')
    replace_ref(pr, 'Srv', 'ip-RR')


def case_ipv4_option_rr(tree):
    _case_native_ipv4_options(tree, ('rr',))


def case_ipv4_option_lsrr(tree):
    _case_native_ipv4_options(tree, ('lsrr',))


def case_ipv4_option_ssrr(tree):
    _case_native_ipv4_options(tree, ('ssrr',))


def case_ipv4_option_ra(tree):
    _case_native_ipv4_options(tree, ('rtralt',))


def case_ipv4_option_any(tree):
    _case_native_ipv4_options(tree, ('any_opt',))


def case_ipv4_option_combined(tree):
    _case_native_ipv4_options(tree, ('lsrr', 'rr'))


def _negate_fixture_policy_service(tree, service_id):
    # Exercise the actual FWB Srv neg=True compiler path. Reorder the
    # preserved deny-first policy to make the negated accept reachable.
    root = tree.getroot()
    fw = only(root, ".//%s[@name='nft-test']" % tag('Firewall'))
    policy = only(fw, './' + tag('Policy'))
    pr = only(policy, "./%s[@id='id9001X30989']" % tag('PolicyRule'))
    fallback = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    srvrel = only(pr, './' + tag('Srv'))
    if srvrel.get('neg') != 'False' or srvrel[0].get('ref') != service_id:
        raise ValueError('unexpected baseline service element for negation')
    if list(policy)[:2] != [fallback, pr]:
        raise ValueError('unexpected baseline rule order for negation')
    srvrel.set('neg', 'True')
    policy.remove(pr)
    policy.insert(0, pr)
    pr.set('position', '0')
    fallback.set('position', '1')


def _case_negated_ipv4_service(tree, enabled):
    _case_native_ipv4_options(tree, enabled)
    _negate_fixture_policy_service(tree, 'ip-RR')


def case_negated_ipv4_option_rr(tree):
    _case_negated_ipv4_service(tree, ('rr',))


def case_negated_ipv4_option_ra(tree):
    _case_negated_ipv4_service(tree, ('rtralt',))


def case_negated_ipv4_option_any(tree):
    _case_negated_ipv4_service(tree, ('any_opt',))


def case_negated_ipv4_option_combined(tree):
    _case_negated_ipv4_service(tree, ('lsrr', 'rr'))


def case_negated_ipv4_fragment(tree):
    _, _, pr, _ = prepare(tree)
    replace_ref(pr, 'Srv', 'ip-IP_Fragments')
    _negate_fixture_policy_service(tree, 'ip-IP_Fragments')


def case_reject_negated_ipv4_timestamp(tree):
    _case_negated_ipv4_service(tree, ('rr',))
    service = only(tree.getroot(), ".//" + tag('IPService') + "[@id='ip-RR']")
    service.set('rr', 'False')
    service.set('ts', 'True')


def case_reject_policy_options(tree):
    _, _, pr, _ = prepare(tree)
    # This isolated fixture must exercise an unsupported IPv4 option.
    service = only(
        tree.getroot(),
        ".//" + tag('IPService') + "[@id='ip-RR']"
    )
    if service.get('rr') != 'True' or service.get('ts') != 'False':
        raise ValueError('unexpected baseline IPv4 RR service')
    service.set('rr', 'False')
    service.set('ts', 'True')
    service.set('name', 'unsupported-ipv4-timestamp')
    replace_ref(pr, 'Srv', 'ip-RR')


def case_reject_nat_options(tree):
    _, _, _, nr = prepare(tree)
    replace_ref(nr, 'OSrv', 'ip-RR')


def case_prolog_after_flush(tree):
    """Prolog place "after policy reset" must compile, not abort.

    Regression test: this prolog position used to abort the whole compile
    whenever policy was activated in atomic nftables mode, e.g. after a
    firewall migrated from the iptables platform kept its old options.
    The scripts use native nftables commands and shell substitutions to
    make sure realistic user prologue/epilogue content survives the
    legacy-marker validation and is emitted around the nftables
    transaction.
    """
    root, fw, _, _ = prepare(tree)
    opts = only(fw, './' + tag('FirewallOptions'))
    prolog = (
        '# ci-prolog-after-flush: cleanup from the previous activation\n'
        'nft delete table ip fwb_ci_mangle\n'
        'ip route flush table novpn\n'
        'ip rule del from 192.168.19.0/24 lookup novpn\n'
    )
    epilog = (
        '# ci-epilog: policy-based routing set up with native nftables\n'
        'ci_provider_ip=$(curl --silent ipinfo.io/ip)\n'
        'nft add table ip fwb_ci_mangle\n'
        "nft add chain ip fwb_ci_mangle PREROUTING "
        "'{ type filter hook prerouting priority mangle; policy accept; }'\n"
        'nft add rule ip fwb_ci_mangle PREROUTING '
        'ip saddr 192.168.19.0/24 counter meta mark set 0x2\n'
        'nft insert rule ip fwb_ci_nat POSTROUTING '
        'meta mark 0x4 counter snat to $ci_provider_ip\n'
        'ip rule add fwmark 0x2 lookup novpn priority 99\n'
    )
    for name, value in (
            ('prolog_place', 'after_flush'),
            ('prolog_script', prolog),
            ('epilog_script', epilog),
    ):
        found = opts.findall("./%s[@name='%s']" % (tag('Option'), name))
        if len(found) > 1:
            raise ValueError('duplicate firewall option ' + name)
        opt = found[0] if found else ET.SubElement(opts, tag('Option'), {'name': name})
        opt.text = value


def case_reject_timezone(tree):
    _, fw, pr, _ = prepare(tree)
    replace_ref(pr, 'When', 'int-workhours')
    opts = only(fw, './' + tag('FirewallOptions'))
    existing = opts.findall("./%s[@name='use_kerneltz']" % tag('Option'))
    if len(existing) > 1:
        raise ValueError('duplicate timezone options')
    opt = existing[0] if existing else ET.SubElement(opts, tag('Option'), {'name': 'use_kerneltz'})
    opt.text = 'True'


def prepare_packet_policy(tree, service):
    """Build an ordered allow-service / deny-all Policy from preserved objects."""
    _, fw, allow, _ = prepare(tree)
    policy = only(fw, './' + tag('Policy'))
    deny = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    if list(policy)[:2] != [deny, allow] or (deny.get('action'), allow.get('action')) != ('Deny', 'Accept'):
        raise ValueError('unexpected baseline Policy ordering')
    policy.remove(allow)
    policy.insert(0, allow)
    allow.set('position', '0')
    deny.set('position', '1')
    allow.set('direction', 'Both')
    replace_ref(allow, 'Src', 'sysid0')
    replace_ref(allow, 'Dst', 'sysid0')
    replace_ref(allow, 'Srv', service)
    for elem in ('Src', 'Dst', 'Srv'):
        only(allow, './' + tag(elem)).set('neg', 'False')
    # Logging is not part of this packet decision test.
    deny.set('log', 'False')
    return fw


def _case_native_user_service(tree, negated):
    # Add a genuine UserService to the UserServices library in the cloned
    # project.  The class serializes its user identity as the XML 'userid'
    # attribute, not 'user_id' or 'uid'.  The original project is untouched.
    fw = prepare_packet_policy(tree, 'tcp-HTTP')
    root = tree.getroot()
    group = only(root, ".//%s[@id='stdid20']" % tag('ServiceGroup'))
    if group.get('name') != 'UserServices' or len(group):
        raise ValueError('unexpected UserServices library contents')
    uid = 'fwb-ci-user-service-1000'
    ET.SubElement(group, tag('UserService'), {
        'id': uid, 'name': 'ci-user-1000', 'comment': 'CI owner match',
        'ro': 'False', 'userid': '1000',
    })
    policy = only(fw, './' + tag('Policy'))
    rule = only(policy, "./%s[@id='id9001X30989']" % tag('PolicyRule'))
    replace_ref(rule, 'Srv', uid)
    # Owner matches are valid only in OUTPUT.  'Outbound' alone can still
    # select FORWARD if the rule's source is Any; bind it to the firewall.
    if not fw.get('id'):
        raise ValueError('fixture firewall has no FWB object id')
    replace_ref(rule, 'Src', fw.get('id'))
    rule.set('direction', 'Outbound')
    only(rule, './' + tag('Srv')).set('neg', 'True' if negated else 'False')


def _case_native_hashlimit(tree, ipv6=False, combo=False, udp=False):
    if ipv6:
        case_ipv6(tree)
        fw = only(tree.getroot(), ".//%s[@name='nft-test']" % tag('Firewall'))
        pr = only(only(fw, './' + tag('Policy')), "./%s[@id='id9001X30989']" % tag('PolicyRule'))
        replace_ref(pr, 'Srv', 'udp-DNS' if udp else 'tcp-HTTP')
    else:
        fw = prepare_packet_policy(tree, 'udp-DNS' if udp else 'tcp-HTTP')
        pr = only(only(fw, './' + tag('Policy')), "./%s[@id='id9001X30989']" % tag('PolicyRule'))
    opts = only(pr, './' + tag('PolicyRuleOptions'))
    chosen = {
        'hashlimit_value': '8',
        'hashlimit_suffix': '/second',
        'hashlimit_burst': '4',
        'hashlimit_mode': 'srcip,dstport' if combo else 'srcip',
        'hashlimit_name': 'ci_srcip_dstport' if combo else 'ci_srcip',
        'hashlimit_expire': '3000',
    }
    for option_name, value in chosen.items():
        existing = opts.find("./%s[@name='%s']" % (tag('Option'), option_name))
        if existing is None:
            existing = ET.SubElement(opts, tag('Option'), {'name': option_name})
        existing.text = value


def case_hashlimit_srcip(tree):
    _case_native_hashlimit(tree)


def case_hashlimit_srcip_dstport(tree):
    _case_native_hashlimit(tree, combo=True)


def case_hashlimit_udp_srcip_dstport(tree):
    _case_native_hashlimit(tree, combo=True, udp=True)


def case_ipv6_hashlimit_srcip(tree):
    _case_native_hashlimit(tree, ipv6=True)


def case_ipv6_hashlimit_srcip_dstport(tree):
    _case_native_hashlimit(tree, ipv6=True, combo=True)


def case_reject_hashlimit_bad_mode(tree):
    _case_native_hashlimit(tree)
    pr = only(tree.getroot(), ".//%s[@id='id9001X30989']" % tag('PolicyRule'))
    opts = only(pr, './' + tag('PolicyRuleOptions'))
    only(opts, "./%s[@name='hashlimit_mode']" % tag('Option')).text = 'srcip;accept'


def case_reject_hashlimit_icmp_port(tree):
    _case_native_hashlimit(tree)
    pr = only(tree.getroot(), ".//%s[@id='id9001X30989']" % tag('PolicyRule'))
    replace_ref(pr, 'Srv', 'ip-IP_Fragments')
    opts = only(pr, './' + tag('PolicyRuleOptions'))
    only(opts, "./%s[@name='hashlimit_mode']" % tag('Option')).text = 'srcport'


def case_user_service_outbound(tree):
    _case_native_user_service(tree, False)


def case_negated_user_service_outbound(tree):
    _case_native_user_service(tree, True)


def case_packet_tcp_input(tree):
    prepare_packet_policy(tree, 'tcp-HTTP')


def case_packet_udp_forward(tree):
    prepare_packet_policy(tree, 'udp-DNS')


def case_packet_snat(tree):
    fw = prepare_packet_policy(tree, 'udp-DNS')
    nat = only(fw, './' + tag('NAT'))
    snat = only(nat, "./%s[@id='id2842X30989']" % tag('NATRule'))
    if snat.get('action') != 'Translate':
        raise ValueError('baseline source NAT rule changed')
    # 192.168.1.0/24 -> 192.0.2.100; preserved project contains both
    # address objects. Disabled unrelated DNAT/SNAT rules cannot interfere.

    replace_ref(snat, 'OSrc', 'id3DC75CE7-1')
    replace_ref(snat, 'ODst', 'sysid0')
    replace_ref(snat, 'OSrv', 'sysid1')
    replace_ref(snat, 'TSrc', 'id2864X30989')
    replace_ref(snat, 'TDst', 'sysid0')
    replace_ref(snat, 'TSrv', 'sysid1')
    only(snat, './' + tag('OSrc')).set('neg', 'False')
    for rule in nat.findall('./' + tag('NATRule')):
        if rule is not snat:
            rule.set('disabled', 'True')


def case_packet_dnat(tree):
    """WAN TCP/80 to public .101 must reach internal .100 via FWB DNAT."""
    fw = prepare_packet_policy(tree, 'tcp-HTTP')
    nat = only(fw, './' + tag('NAT'))
    dnat = only(nat, "./%s[@id='id11861X30989']" % tag('NATRule'))
    if dnat.get('action') != 'Translate':
        raise ValueError('baseline destination NAT rule changed')
    # Use the real original FWB destination-NAT rule and existing address
    # objects; restrict translation to TCP/80 so the default deny is testable.
    if (only(dnat, './' + tag('ODst'))[0].get('ref') != 'id11875X30989'
            or only(dnat, './' + tag('TDst'))[0].get('ref') != 'id11890X30989'):
        raise ValueError('baseline DNAT address objects changed')
    replace_ref(dnat, 'OSrc', 'sysid0')
    replace_ref(dnat, 'OSrv', 'tcp-HTTP')
    replace_ref(dnat, 'TSrc', 'sysid0')
    replace_ref(dnat, 'TSrv', 'sysid1')
    for elem in ('OSrc', 'ODst', 'OSrv'):
        only(dnat, './' + tag(elem)).set('neg', 'False')
    for rule in nat.findall('./' + tag('NATRule')):
        rule.set('disabled', 'False' if rule is dnat else 'True')


def case_multi_address_set(tree):
    """Multi-object Src/Dst must stay one flat rule with inline sets.

    The optimize1 pass chainified such rules for iptables; the native
    backend can print the addresses as inline nftables sets, so the
    compiled result must be a single rule instead of a jump chain.
    Both referenced networks are real FWB objects in the baseline file.
    """
    _, fw, allow, _ = prepare(tree)
    policy = only(fw, './%s' % tag('Policy'))
    if (only(allow, './' + tag('Src'))[0].get('ref'),
            only(allow, './' + tag('Dst'))[0].get('ref')) != \
            ('id3DC75CE7-1', 'id3D84EECF'):
        raise ValueError('baseline policy address objects changed')
    # Real FWB networks: 192.168.1.0/24 and 192.168.2.0/24.
    networks = ('id3DC75CE7-1', 'id3DC75CE7-2')
    for elem_name in ('Src', 'Dst'):
        elem = only(allow, './' + tag(elem_name))
        elem.clear()
        elem.set('neg', 'False')
        for ref in networks:
            ET.SubElement(elem, tag('ObjectRef'), {'ref': ref})
    # Keep the compiled policy minimal and free of unrelated jump chains.
    deny = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    deny.set('disabled', 'True')


def case_nat_multi_address_set(tree):
    """Multi-object NAT Src/Dst must stay one flat rule with inline sets.

    The iptables-era splitMultiSrcAndDst pass chainified such rules and
    the shared ConvertToAtomicForAddresses exploded them into a cartesian
    product; the native backend prints inline nftables sets instead.
    OSrc uses two real FWB networks, ODst a real network plus a real host
    from the same subnet (so splitODstForSNAT keeps one rule), and the
    baseline SNAT translation address stays unchanged.
    """
    _, fw, _, nr = prepare(tree)
    nat = only(fw, './%s' % tag('NAT'))
    if only(nr, './' + tag('OSrc'))[0].get('ref') != 'id3DC75CE7-1':
        raise ValueError('baseline NAT source changed')
    if only(nr, './' + tag('TSrc'))[0].get('ref') != 'id2864X30989':
        raise ValueError('baseline NAT translation source changed')
    for elem_name, refs in (
            ('OSrc', ('id3DC75CE7-1', 'id3DC75CE7-2')),      # 192.168.1.0/24, 192.168.2.0/24
            ('ODst', ('id3F4ECE3F', 'id11875X30989'))):      # 192.0.2.0/24, 192.0.2.101
        elem = only(nr, './' + tag(elem_name))
        elem.clear()
        elem.set('neg', 'False')
        for ref in refs:
            ET.SubElement(elem, tag('ObjectRef'), {'ref': ref})
    for other in nat.findall('./' + tag('NATRule')):
        other.set('disabled', 'False' if other is nr else 'True')


def case_nat_masquerade(tree):
    """The ipt_use_masq rule option must flip SNAT into native masquerade.

    The backend has always honored the iptables-style rule options
    (alwaysUseMasquerading), so the fixture guards the compiled
    statement: one masquerade row, no residual snat translation.
    """
    _, fw, _, nr = prepare(tree)
    nat = only(fw, './%s' % tag('NAT'))
    if only(nr, './' + tag('TSrc'))[0].get('ref') != 'id2864X30989':
        raise ValueError('baseline NAT translation source changed')
    opts = only(nr, './' + tag('NATRuleOptions'))
    if list(opts):
        raise ValueError('unexpected baseline NAT rule options')
    ET.SubElement(opts, tag('Option'), {'name': 'ipt_use_masq'}).text = 'True'
    for other in nat.findall('./' + tag('NATRule')):
        other.set('disabled', 'False' if other is nr else 'True')


def _widen_rule_element_to_any(rule, element, any_ref='sysid0'):
    """Drop the baseline match/negation and match 'any' instead."""
    node = only(rule, './' + tag(element))
    node.clear()
    node.set('neg', 'False')
    ET.SubElement(node, tag('ObjectRef'), {'ref': any_ref})


def _set_rule_options(rule, options):
    """Replace the rule's PolicyRuleOptions with the given option values."""
    opts = only(rule, './' + tag('PolicyRuleOptions'))
    opts.clear()
    for name in sorted(options):
        ET.SubElement(opts, tag('Option'), {'name': name}).text = options[name]


def _add_tag_service(root, service_id, tagcode, comment):
    group = only(root, ".//%s[@id='id1565X1251']" % tag('ServiceGroup'))
    if group.get('name') != 'TagServices':
        raise ValueError('unexpected TagServices group id1565X1251')
    if group.findall("./%s[@id='%s']" % (tag('TagService'), service_id)):
        raise ValueError('TagService %s already exists' % service_id)
    ET.SubElement(group, tag('TagService'), {
        'id': service_id,
        'name': 'ci-tag-' + tagcode,
        'comment': comment,
        'ro': 'False',
        'tagcode': tagcode,
    })


def _promote_before_fallback(policy, rule, fallback):
    """Move the baseline allow rule in front of the fallback deny.

    Tagging/classify rules use action Continue, but the fwbuilder shadowing
    check still rejects rules placed after an unconditional fallback deny.
    """
    if list(policy)[:2] != [fallback, rule]:
        raise ValueError('unexpected baseline policy order for the mangle fixture')
    policy.remove(rule)
    policy.insert(0, rule)
    rule.set('position', '0')
    fallback.set('position', '1')


def case_mangle_tag(tree):
    """Tagging must produce native 'meta mark set' rows in the mangle table.

    The mangle table pipeline was ported from the iptables backend but stayed
    unreachable through the GUI because the Tag action was marked unsupported
    for nftables. The rule additionally sets ipt_mark_connections, so the
    compiled script must contain the CONNMARK save statement and the
    automatic 'meta mark set ct mark' restoration rows.
    """
    root, fw, pr, _ = prepare(tree)
    policy = only(fw, './%s' % tag('Policy'))
    fallback = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    _promote_before_fallback(policy, pr, fallback)
    _add_tag_service(root, 'fwb-ci-tag-64', '64', 'CI packet mark 64')
    pr.set('action', 'Continue')
    pr.set('direction', 'Both')
    pr.set('comment', 'CI: mark every packet with fwmark 64')
    _widen_rule_element_to_any(pr, 'Src')
    _widen_rule_element_to_any(pr, 'Dst')
    _set_rule_options(pr, {
        'tagging': 'True',
        'tagobject_id': 'fwb-ci-tag-64',
        'ipt_mark_connections': 'True',
    })


def case_mark_match(tree):
    """A TagService rule element matches packets, it never writes marks.

    The baseline allow rule becomes 'accept packets carrying fwmark 42';
    since the rule only reads the mark, the compiled script must not contain
    any mangle table at all.
    """
    root, fw, pr, _ = prepare(tree)
    policy = only(fw, './%s' % tag('Policy'))
    fallback = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    _promote_before_fallback(policy, pr, fallback)
    _add_tag_service(root, 'fwb-ci-tag-42', '42', 'CI packet mark 42')
    pr.set('action', 'Accept')
    pr.set('direction', 'Inbound')
    pr.set('comment', 'CI: allow packets marked with fwmark 42')
    _widen_rule_element_to_any(pr, 'Src')
    _widen_rule_element_to_any(pr, 'Dst')
    srv = only(pr, './' + tag('Srv'))
    srv.clear()
    srv.set('neg', 'False')
    ET.SubElement(srv, tag('ServiceRef'), {'ref': 'fwb-ci-tag-42'})
    _set_rule_options(pr, {'stateless': 'False'})


def case_mangle_classify(tree):
    """Classification must translate the TC handle into a numeric priority.

    The iptables CLASSIFY target takes 'major:minor' TC handles while the
    native backend emits 'meta priority set'; 1:10 must become 0x0001000a
    rather than leaking the raw iptables syntax into the nftables script.
    """
    root, fw, pr, _ = prepare(tree)
    policy = only(fw, './%s' % tag('Policy'))
    fallback = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    _promote_before_fallback(policy, pr, fallback)
    pr.set('action', 'Continue')
    pr.set('direction', 'Both')
    pr.set('comment', 'CI: classify every packet as 1:10')
    _widen_rule_element_to_any(pr, 'Src')
    _widen_rule_element_to_any(pr, 'Dst')
    _set_rule_options(pr, {
        'classification': 'True',
        'classify_str': '1:10',
    })


def _case_nat_load_balancing(tree, destination, extra_address='192.168.1.101'):
    """Real FWB NAT LB using the existing DNAT rule and real host objects."""
    _, fw, _, _ = prepare(tree)
    nat = only(fw, './' + tag('NAT'))
    rule = only(nat, "./%s[@id='id11861X30989']" % tag('NATRule'))
    target = only(rule, './' + tag('TDst'))
    if len(target) != 1 or target[0].get('ref') != 'id11890X30989':
        raise ValueError('unexpected original translated destination')
    original = only(tree.getroot(), ".//%s[@id='id11890X30989']" % tag('IPv4'))
    if original.get('address') != '192.168.1.100':
        raise ValueError('unexpected original IPv4 destination')
    if destination == 'network':
        new_id = 'id3DC75CE7-1'  # Real FWB 192.168.1.0/24 network
    else:
        new_id = 'fwb-ci-nat-lb-' + extra_address.replace('.', '-')
        clone = deepcopy(original)
        clone.set('id', new_id)
        clone.set('name', 'CI LB backend ' + extra_address)
        clone.set('address', extra_address)
        address_group = only(tree.getroot(), ".//%s[@id='id1550X1251']" % tag('ObjectGroup'))
        address_group.append(clone)
    ET.SubElement(target, tag('ObjectRef'), {'ref': new_id})
    replace_ref(rule, 'OSrc', 'sysid0')
    replace_ref(rule, 'OSrv', 'tcp-HTTP')
    replace_ref(rule, 'TSrc', 'sysid0')
    replace_ref(rule, 'TSrv', 'sysid1')
    for element in ('OSrc', 'ODst', 'OSrv'):
        only(rule, './' + tag(element)).set('neg', 'False')
    for other in nat.findall('./' + tag('NATRule')):
        other.set('disabled', 'False' if other is rule else 'True')


def case_nat_lb_contiguous(tree):
    _case_nat_load_balancing(tree, 'hosts')


def case_nat_lb_sparse(tree):
    _case_nat_load_balancing(tree, 'hosts', '192.168.1.103')


def case_packet_nat_lb_sparse(tree):
    # Reuse the identical sparse DNAT rule while enabling the real FWB TCP/80
    # allow BEFORE the fallback deny; packet tests must exercise forwarding.
    case_nat_lb_sparse(tree)
    prepare_packet_policy(tree, 'tcp-HTTP')


def case_packet_nat_lb_contiguous(tree):
    case_nat_lb_contiguous(tree)
    prepare_packet_policy(tree, 'tcp-HTTP')


def case_reject_nat_lb_network(tree):
    _case_nat_load_balancing(tree, 'network')


def case_reject_nat_lb_duplicate(tree):
    _case_nat_load_balancing(tree, 'hosts', '192.168.1.100')


def case_reject_nat_lb_port_translation(tree):
    _case_nat_load_balancing(tree, 'hosts', '192.168.1.103')
    fw = only(tree.getroot(), ".//%s[@name='nft-test']" % tag('Firewall'))
    rule = only(only(fw, './' + tag('NAT')),
                "./%s[@id='id11861X30989']" % tag('NATRule'))
    replace_ref(rule, 'TSrv', 'id3B4FED69')  # Existing TCP HTTPS, 443


def _case_ipv6_nat_lb(tree, second='2001:db8:2::101', packet=False,
                      invalid=None):
    """IPv6 DNAT LB from real FWB policy/NAT objects, without schema guesses."""
    case_ipv6(tree)  # Real IPv6 Policy and two FWB IPv6 interfaces.
    root = tree.getroot()
    fw = only(root, ".//%s[@name='nft-test']" % tag('Firewall'))
    policy = only(fw, './' + tag('Policy'))
    allow = only(policy, "./%s[@id='id9001X30989']" % tag('PolicyRule'))
    # Reuse the proven IPv6 rule ordering with a real TCP/80 forward permit.
    replace_ref(allow, 'Src', 'sysid0')
    replace_ref(allow, 'Dst', 'sysid0')
    replace_ref(allow, 'Srv', 'tcp-HTTP')
    allow.set('direction', 'Both')
    nat = only(fw, './' + tag('NAT'))
    if (nat.get('ipv4_rule_set'), nat.get('ipv6_rule_set')) != ('False', 'False'):
        raise ValueError('unexpected baseline NAT address family')
    nat.set('ipv4_rule_set', 'False')
    nat.set('ipv6_rule_set', 'True')
    rule = only(nat, "./%s[@id='id11861X30989']" % tag('NATRule'))
    target = only(rule, './' + tag('TDst'))
    if len(target) != 1 or target[0].get('ref') != 'id11890X30989':
        raise ValueError('unexpected original translated destination')
    template = only(root, ".//%s[@id='id11890X30989']" % tag('IPv4'))
    if template.get('address') != '192.168.1.100':
        raise ValueError('unexpected original IPv4 backend')
    group = only(root, ".//%s[@id='id1550X1251']" % tag('ObjectGroup'))

    def make_host(suffix, address):
        host = deepcopy(template)
        host.tag = tag('IPv6')
        host.set('id', 'fwb-ci-ipv6-lb-' + suffix)
        host.set('name', 'CI IPv6 LB ' + suffix)
        host.set('address', address)
        host.set('netmask', '128')
        group.append(host)
        return host.get('id')

    public = make_host('public', '2001:db8:1::101')
    first = make_host('first', '2001:db8:2::100')
    if invalid == 'network':
        last = 'id2088X75851'  # Preserved IPv6 documentation network /32.
    else:
        last = make_host('second', '2001:db8:2::100' if invalid == 'duplicate' else second)
    replace_ref(rule, 'ODst', public)
    replace_ref(rule, 'TDst', first)
    ET.SubElement(target, tag('ObjectRef'), {'ref': last})
    replace_ref(rule, 'OSrc', 'sysid0')
    replace_ref(rule, 'OSrv', 'tcp-HTTP')
    replace_ref(rule, 'TSrc', 'sysid0')
    replace_ref(rule, 'TSrv', 'sysid1' if invalid != 'port' else 'id3B4FED69')
    for element in ('OSrc', 'ODst', 'OSrv'):
        only(rule, './' + tag(element)).set('neg', 'False')
    for other in nat.findall('./' + tag('NATRule')):
        other.set('disabled', 'False' if other is rule else 'True')


def case_ipv6_nat_lb_contiguous(tree):
    _case_ipv6_nat_lb(tree)


def case_ipv6_nat_lb_sparse(tree):
    _case_ipv6_nat_lb(tree, second='2001:db8:2::103')


def case_packet_ipv6_nat_lb_contiguous(tree):
    _case_ipv6_nat_lb(tree, packet=True)


def case_packet_ipv6_nat_lb_sparse(tree):
    _case_ipv6_nat_lb(tree, second='2001:db8:2::103', packet=True)


def case_reject_ipv6_nat_lb_network(tree):
    _case_ipv6_nat_lb(tree, invalid='network')


def case_reject_ipv6_nat_lb_duplicate(tree):
    _case_ipv6_nat_lb(tree, invalid='duplicate')


def case_reject_ipv6_nat_lb_port_translation(tree):
    _case_ipv6_nat_lb(tree, invalid='port')


def _route_group(root):
    return only(root, ".//%s[@id='id1550X1251']" % tag('ObjectGroup'))


def _add_named_routing_ruleset(tree, table_name, table_id, uid_suffix):
    """Second Routing rule set compiled into its own iproute2 table.

    The route reuses the real baseline gateway and interface objects,
    so the named table compiles to
    "$IP route add 192.168.2.0/24 via 192.168.1.10 dev eth1 table <t>"
    while the untouched main rule set keeps its default route.
    """
    root = tree.getroot()
    fw = only(root, ".//%s[@name='nft-test']" % tag('Firewall'))
    # The baseline project name is stable even after other generated
    # fixtures added further Routing rule sets.
    baseline_rulesets = [r for r in fw.findall('./' + tag('Routing'))
                         if r.get('name') == 'Routing']
    if len(baseline_rulesets) != 1:
        raise ValueError('expected exactly the baseline Routing rule set')
    routing = baseline_rulesets[0]
    enabled = [r for r in routing.findall('./' + tag('RoutingRule'))
               if r.get('disabled') != 'True']
    if len(enabled) != 1:
        raise ValueError('expected exactly one baseline routing rule')
    baseline = enabled[0]
    gtw_ref = only(baseline, './' + tag('RGtw'))[0].get('ref')
    itf_ref = only(baseline, './' + tag('RItf'))[0].get('ref')
    if gtw_ref != 'id3D84EECE' or itf_ref != 'id2692X30989':
        raise ValueError('unexpected baseline gateway or interface object')
    new_rs = ET.Element(tag('Routing'), {
        'id': 'fwb-ci-route-' + uid_suffix,
        'name': 'route_' + uid_suffix,
        'comment': 'CI named iproute2 routing table',
        'ro': 'False',
        'ipv4_rule_set': 'False',
        'ipv6_rule_set': 'False',
        'top_rule_set': 'False',
    })
    rule = ET.Element(tag('RoutingRule'), {
        'id': 'fwb-ci-route-' + uid_suffix + '-rule',
        'disabled': 'False',
        'group': '',
        'metric': '0',
        'position': '0',
        'comment': 'CI route into named routing table',
    })
    # id3DC75CE7-2 is the real FWB network object 192.168.2.0/24.
    for child_name, ref in (('RDst', 'id3DC75CE7-2'),
                            ('RGtw', gtw_ref), ('RItf', itf_ref)):
        child = ET.SubElement(rule, tag(child_name), {'neg': 'False'})
        ET.SubElement(child, tag('ObjectRef'), {'ref': ref})
    ET.SubElement(rule, tag('RoutingRuleOptions'))
    new_rs.append(rule)
    options = ET.SubElement(new_rs, tag('RuleSetOptions'))
    ET.SubElement(options, tag('Option'),
                  {'name': 'routing_table_name'}).text = table_name
    ET.SubElement(options, tag('Option'),
                  {'name': 'routing_table_id'}).text = table_id
    fw.insert(list(fw).index(routing) + 1, new_rs)


def _set_manage_rt_tables(tree, value):
    fw = only(tree.getroot(), ".//%s[@name='nft-test']" % tag('Firewall'))
    opts = only(fw, './' + tag('FirewallOptions'))
    if opts.findall("./%s[@name='manage_rt_tables']" % tag('Option')):
        raise ValueError('baseline must not set manage_rt_tables')
    option = ET.SubElement(opts, tag('Option'), {'name': 'manage_rt_tables'})
    option.text = value
    return opts


def case_routing_table(tree):
    _add_named_routing_ruleset(tree, 'ci_pbr', '101', 'ci1')
    _set_manage_rt_tables(tree, 'True')


def case_routing_table_numeric(tree):
    _add_named_routing_ruleset(tree, 'ci_pbr', '102', 'numeric')


def case_reject_routing_table_duplicate(tree):
    _add_named_routing_ruleset(tree, 'ci_pbr', '101', 'dup1')
    _add_named_routing_ruleset(tree, 'ci_other', '101', 'dup2')


def case_routing_in_deleted_objects(tree):
    """A Routing rule set parked in the Deleted Objects library.

    Deleting a Routing rule set from the GUI parks it in the trash
    library, and rule sets and rules can legally live directly under
    Library (Policy and NAT already do). The baseline main route must
    stay untouched.
    """
    root = tree.getroot()
    trash = only(root, ".//%s[@id='sysid99']" % tag('Library'))
    parked = ET.Element(tag('Routing'), {
        'id': 'fwb-ci-route-trash',
        'name': 'Routing_1',
        'comment': 'parked routing rule set',
        'ro': 'False',
        'ipv4_rule_set': 'False',
        'ipv6_rule_set': 'False',
        'top_rule_set': 'False',
    })
    ET.SubElement(parked, tag('RuleSetOptions'))
    trash.append(parked)


def _route_group(root):
    return only(root, ".//%s[@id='id1550X1251']" % tag('ObjectGroup'))


def _add_route_object(group, kind, obj_id, name, address, netmask):
    element = ET.Element(tag(kind), {
        'id': obj_id,
        'name': name,
        'comment': 'CI routing object',
        'ro': 'False',
        'address': address,
        'netmask': netmask,
    })
    group.append(element)
    return obj_id


def _add_routing_rule(fw, rule_id, position, dst, gtw, itf, metric):
    routing = only(fw, './' + tag('Routing'))
    rule = ET.Element(tag('RoutingRule'), {
        'id': rule_id,
        'disabled': 'False',
        'group': '',
        'metric': str(metric),
        'position': str(position),
        'comment': '',
    })
    for child_name, ref in (('RDst', dst), ('RGtw', gtw), ('RItf', itf)):
        child = ET.SubElement(rule, tag(child_name), {'neg': 'False'})
        ET.SubElement(child, tag('ObjectRef'), {'ref': ref})
    ET.SubElement(rule, tag('RoutingRuleOptions'))
    options = only(routing, './' + tag('RuleSetOptions'))
    routing.insert(list(routing).index(options), rule)


def _ipv6_route_ids(tree):
    """Real IPv6 route objects. The caller already selected the IPv6 fixture."""
    root = tree.getroot()
    fw = only(root, ".//%s[@name='nft-test']" % tag('Firewall'))
    group = _route_group(root)
    eth0 = only(fw, "./%s[@name='eth0']" % tag('Interface')).get('id')
    eth1 = only(fw, "./%s[@name='eth1']" % tag('Interface')).get('id')
    objects = {
        'net9': _add_route_object(group, 'NetworkIPv6', 'fwb-ci-route-net9',
                                  'CI route net9', '2001:db8:9::', '64'),
        'net8': _add_route_object(group, 'NetworkIPv6', 'fwb-ci-route-net8',
                                  'CI route net8', '2001:db8:8::', '64'),
        'net50': _add_route_object(group, 'NetworkIPv6', 'fwb-ci-route-net50',
                                   'CI route net50', '2001:db8:50::', '64'),
        'default6': _add_route_object(group, 'NetworkIPv6', 'fwb-ci-route-default6',
                                      'CI IPv6 default', '::', '0'),
        'gw': _add_route_object(group, 'IPv6', 'fwb-ci-route-gw',
                                'CI global gateway', '2001:db8:1::fe', '128'),
        'll': _add_route_object(group, 'IPv6', 'fwb-ci-route-ll',
                                'CI link-local gateway', 'fe80::1', '128'),
        'ecmp_a': _add_route_object(group, 'IPv6', 'fwb-ci-route-ecmp-a',
                                    'CI ECMP gateway A', '2001:db8:1::2', '128'),
        'ecmp_b': _add_route_object(group, 'IPv6', 'fwb-ci-route-ecmp-b',
                                    'CI ECMP gateway B', '2001:db8:2::2', '128'),
        'connected': _add_route_object(
            group, 'NetworkIPv6', 'fwb-ci-route-connected',
            'CI connected net', '2001:db8:1::', '64'),
    }
    return fw, eth0, eth1, objects


def _install_successful_ipv6_routes(tree):
    fw, eth0, eth1, obj = _ipv6_route_ids(tree)
    _add_routing_rule(fw, 'fwb-ci-route-net9-rule', 1,
                      obj['net9'], obj['gw'], eth0, 100)
    _add_routing_rule(fw, 'fwb-ci-route-ll-rule', 2,
                      obj['net8'], obj['ll'], eth0, 0)
    _add_routing_rule(fw, 'fwb-ci-route-default6-rule', 3,
                      obj['default6'], obj['ll'], eth0, 0)
    _add_routing_rule(fw, 'fwb-ci-route-ecmp-a-rule', 4,
                      obj['net50'], obj['ecmp_a'], eth0, 20)
    _add_routing_rule(fw, 'fwb-ci-route-ecmp-b-rule', 5,
                      obj['net50'], obj['ecmp_b'], eth1, 20)
    return fw


def case_ipv6_route_rollback(tree):
    """Successful routes, then one destination owned by the kernel."""
    case_ipv6_ndp(tree)
    fw = only(tree.getroot(), ".//%s[@name='nft-test']" % tag('Firewall'))
    eth0 = only(fw, "./%s[@name='eth0']" % tag('Interface')).get('id')
    _add_routing_rule(fw, 'fwb-ci-route-connected-rule', 6,
                      'fwb-ci-route-connected', 'fwb-ci-route-ll', eth0, 0)


def case_reject_ipv6_route_link_local(tree):
    case_ipv6(tree)
    fw, _eth0, _eth1, obj = _ipv6_route_ids(tree)
    _add_routing_rule(fw, 'fwb-ci-route-ll-no-dev', 1,
                      obj['net8'], obj['ll'], 'sysid0', 0)


def case_reject_ipv6_route_netmask(tree):
    case_ipv6(tree)
    fw, eth0, _eth1, obj = _ipv6_route_ids(tree)
    bad = _add_route_object(
        _route_group(tree.getroot()), 'NetworkIPv6', 'fwb-ci-route-bad-mask',
        'CI invalid IPv6 net', '2001:db8:9::1', '64')
    _add_routing_rule(fw, 'fwb-ci-route-bad-mask-rule', 1,
                      bad, obj['gw'], eth0, 0)


def case_reject_ipv6_route_mixed(tree):
    case_ipv6(tree)
    fw, eth0, _eth1, obj = _ipv6_route_ids(tree)
    _add_routing_rule(fw, 'fwb-ci-route-mixed-rule', 1,
                      obj['net9'], 'id3D84EECE', eth0, 0)


def case_dynamic_address_sets(tree):
    """Real FWB AddressTable: an IPv4 allowlist with atomic runtime sets."""
    fw = prepare_packet_policy(tree, 'tcp-HTTP')
    policy = only(fw, './' + tag('Policy'))
    allow = only(policy, "./%s[@id='id9001X30989']" % tag('PolicyRule'))
    replace_ref(allow, 'Src', 'id3002X5927')
    table = only(tree.getroot(), ".//%s[@id='id3002X5927']" % tag('AddressTable'))
    if table.get('run_time') != 'True' or table.get('name') != 'bad_guys':
        raise ValueError('unexpected baseline run-time address table')
    table.set('filename', '/tmp/fwb-pr6-ci-address-set.data')
    opts = only(fw, './' + tag('FirewallOptions'))
    matches = opts.findall("./%s[@name='use_nft_sets']" % tag('Option'))
    if len(matches) > 1:
        raise ValueError('duplicate use_nft_sets options')
    option = matches[0] if matches else ET.SubElement(opts, tag('Option'), {'name': 'use_nft_sets'})
    option.text = 'True'


def case_dynamic_interface(tree):
    """Dynamic interface address must compile, not abort on $i_ markers.

    Regression test: native compiles that referenced a dynamic interface
    (or the networks attached to it) emitted fwbuilder $i_* shell
    variables which the final legacy-marker validation rejected, so
    fwb_nft produced no output file at all even though every rule
    compiled. The ruleset heredoc is unquoted and expands those
    variables at activation time now.
    """
    fw = prepare_packet_policy(tree, 'tcp-HTTP')
    policy = only(fw, './' + tag('Policy'))
    allow = only(policy, "./%s[@id='id9001X30989']" % tag('PolicyRule'))
    eth1 = only(fw, "./%s[@name='eth1']" % tag('Interface'))
    if eth1.get('dyn') != 'False' or not eth1.get('id'):
        raise ValueError('unexpected baseline interface eth1')
    # A dynamic interface has no fixed address; drop its IPv4 child.
    for child in list(eth1):
        if child.tag == tag('IPv4'):
            eth1.remove(child)
    # "Dynamic" (address discovered at run time) is deliberately different
    # from "unnumbered" (no address at all, e.g. serial links).  The
    # preserved baseline declares eth1 unnumbered with a stray address
    # child; the generic fwcompiler guard correctly rejects unnumbered
    # interfaces in rules, so the dynamic fixture must clear that flag.
    eth1.set('dyn', 'True')
    eth1.set('unnum', 'False')
    # Networks attached to a dynamic interface become run-time objects,
    # resolved with getnet() into the $i_eth1_network shell variable.
    # The FWB DTD requires AttachedNetworks as the LAST Interface child
    # (IPv4*, IPv6*, physAddress?, InterfaceOptions?, Interface*,
    # FailoverClusterGroup?, AttachedNetworks?).
    attached = ET.Element(tag('AttachedNetworks'), {
        'id': 'fwb-ci-att-nets-eth1',
        'name': 'nft-test:eth1:attached',
        'comment': 'CI run-time networks attached to eth1',
        'ro': 'False',
    })
    if only(eth1, './' + tag('InterfaceOptions')) is None:
        raise ValueError('baseline eth1 has no InterfaceOptions element')
    eth1.append(attached)
    # First rule: match the firewall's own dynamic interface address.
    replace_ref(allow, 'Src', eth1.get('id'))
    only(allow, './' + tag('Src')).set('neg', 'False')
    allow.set('comment', 'CI: source is the dynamic eth1 address')
    # Second rule: match a network attached to the dynamic interface.
    attached_rule = deepcopy(allow)
    attached_rule.set('id', 'fwb-ci-dynif-attached')
    attached_rule.set('position', '1')
    attached_rule.set('comment', 'CI: source is a network attached to eth1')
    replace_ref(attached_rule, 'Src', attached.get('id'))
    only(attached_rule, './' + tag('Src')).set('neg', 'False')
    policy.insert(1, attached_rule)
    only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule')).set('position', '2')
    # The single baseline route reaches 192.168.1.10 via eth1 (192.168.1.1/24).
    # Once eth1 is dynamic it contributes no local network, so the routing
    # compiler correctly rejects that static gateway; routing through dynamic
    # interfaces is not what this fixture tests. Disable the route instead.
    for route in only(fw, './%s' % tag('Routing')).findall('./' + tag('RoutingRule')):
        route.set('disabled', 'True')


def case_reject_runtime_address_tables(tree):
    """Clear abort for run-time AddressTables without named nft sets.

    The $at_ shell variables can not be filled at activation time
    unless the run-time table is loaded into named nftables sets, so the
    compiler must reject this combination with an actionable message
    instead of generating a rule with an empty address operand.
    """
    root, fw, allow, _ = prepare(tree)
    replace_ref(allow, 'Src', 'id3002X5927')
    table = only(root, ".//" + tag('AddressTable') + "[@id='id3002X5927']")
    if table.get('run_time') != 'True' or table.get('name') != 'bad_guys':
        raise ValueError('unexpected baseline run-time address table')
    table.set('filename', '/tmp/fwb-pr6-ci-address-set.data')
    opts = only(fw, './' + tag('FirewallOptions'))
    if opts.findall("./%s[@name='use_nft_sets']" % tag('Option')):
        raise ValueError('baseline must not enable use_nft_sets for the reject fixture')


def case_runtime_dns_name(tree):
    """Run-time DNSName stages a resolver loop instead of a name literal.

    nftables resolves names itself when the transaction is committed and
    refuses names with several records ("... resolves to multiple
    addresses"), which killed whole atomic activations of projects with
    run-time DNSName objects (e.g. imap.gmail.com). The generated script
    must expand every record at activation time through fwb_nft_resolve()
    and stage one copy of the rule per address into the same open
    transaction.
    """
    root, fw, allow, _ = prepare(tree)
    dns_group = only(root, ".//" + tag('ObjectGroup') + "[@id='id1551X1251']")
    if dns_group.get('name') != 'DNS Names':
        raise ValueError('unexpected baseline DNS Names group')
    if dns_group.findall('./' + tag('DNSName')):
        raise ValueError('baseline DNS Names group is not empty')
    ET.SubElement(dns_group, tag('DNSName'), {
        'id': 'fwb-ci-rt-dns',
        'name': 'fwb-ci-rt-dns.example.org',
        'comment': 'CI run-time DNSName (several A records at activation)',
        'ro': 'False',
        'dnsrec': 'fwb-ci-rt-dns.example.org',
        'dnsrectype': 'A',
        'run_time': 'True',
    })
    replace_ref(allow, 'Src', 'fwb-ci-rt-dns')
    only(allow, './' + tag('Src')).set('neg', 'False')
    allow.set('comment', 'CI: source is a run-time DNS name')


def case_module_load_ignored(tree):
    """load_modules must not emit iptables-era module search code.

    Kernel-native nftables autoloads its modules; searching
    /lib/modules/... for conntrack/NAT modules breaks on appliance
    systems (OpenWrt) that ship no kernel modules on disk and no
    modprobe binary. Pin the option explicitly so the generated script
    with load_modules enabled stays a no-op.
    """
    _root, fw, _allow, _nr = prepare(tree)
    opts = only(fw, './' + tag('FirewallOptions'))
    option = opts.find("./%s[@name='load_modules']" % tag('Option'))
    if option is None:
        option = ET.SubElement(opts, tag('Option'), {'name': 'load_modules'})
    option.text = 'True'


def case_reject_addressless_interface(tree):
    """A rule matching a bridge-port interface without an address must abort.

    The driver-level CompilerDriver::commonChecks2 already refuses REGULAR
    interfaces without an address ("Missing IP address for interface %1")
    before any rule is inspected, so that shape can not reach the guard
    under test here. The addressless shape that does reach the ruleset
    compilers is a bridge port: Interface::isRegular() is false for it,
    yet it is neither dynamic nor unnumbered. iptables silently swallowed
    the empty address operand of such a port, widening the rule to "any";
    the address expansion here cleared the Dst rule element and
    dropRuleWithEmptyRE silently dropped the whole rule. Only the
    checkForAddresslessInterface guard fails closed naming the interface.
    """
    _root, fw, allow, _nr = prepare(tree)
    fresh_ids = ('fwb-ci-br1', 'fwb-ci-br1-ip', 'fwb-ci-eth9')
    for fresh_id in fresh_ids:
        if _root.findall(".//*[@id='%s']" % fresh_id):
            raise ValueError('fixture id %s already exists' % fresh_id)
    # A bridge parent carries the address, the bridge port itself does not.
    bridge = ET.Element(tag('Interface'), {
        'id': 'fwb-ci-br1', 'dedicated_failover': 'False', 'dyn': 'False',
        'label': 'ci', 'mgmt': 'False', 'ro': 'False',
        'security_level': '0', 'unnum': 'False', 'unprotected': 'False',
        'name': 'br1', 'comment': 'CI addressless bridge port parent'})
    ET.SubElement(bridge, tag('IPv4'), {
        'id': 'fwb-ci-br1-ip', 'name': 'nft-test:br1:ip', 'comment': '',
        'ro': 'False', 'address': '192.0.2.7', 'netmask': '255.255.255.0'})
    options = ET.SubElement(bridge, tag('InterfaceOptions'))
    ET.SubElement(options, tag('Option'), {'name': 'type'}).text = 'bridge'
    port = ET.SubElement(bridge, tag('Interface'), {
        'id': 'fwb-ci-eth9', 'dedicated_failover': 'False', 'dyn': 'False',
        'label': '', 'mgmt': 'False', 'ro': 'False', 'security_level': '100',
        'unnum': 'False', 'unprotected': 'False', 'name': 'eth9',
        'comment': 'CI bridge port without an address'})
    port_options = ET.SubElement(port, tag('InterfaceOptions'))
    ET.SubElement(port_options, tag('Option'),
                  {'name': 'type'}).text = 'ethernet'
    # Keep the interface section together: insert in front of Management.
    fw.insert(list(fw).index(only(fw, "./%s" % tag('Management'))), bridge)
    replace_ref(allow, 'Dst', 'fwb-ci-eth9')


def _add_ip_rule_routing_ruleset(tree, ruleset_id, name, table_name=None,
                                 table_id=None):
    """A Routing rule set hosting only IPRule objects (policy-based
    routing, W4). Without table options it stays an empty main-table
    rule set; the IPRule lookup target selects the table."""
    root = tree.getroot()
    fw = only(root, ".//%s[@name='nft-test']" % tag('Firewall'))
    baseline_rulesets = [r for r in fw.findall('./' + tag('Routing'))
                         if r.get('name') == 'Routing']
    if len(baseline_rulesets) != 1:
        raise ValueError('expected exactly the baseline Routing rule set')
    routing = baseline_rulesets[0]
    new_rs = ET.Element(tag('Routing'), {
        'id': ruleset_id,
        'name': name,
        'comment': 'CI ip rule routing rule set',
        'ro': 'False',
        'ipv4_rule_set': 'False',
        'ipv6_rule_set': 'False',
        'top_rule_set': 'False',
    })
    options = ET.SubElement(new_rs, tag('RuleSetOptions'))
    if table_name:
        ET.SubElement(options, tag('Option'),
                      {'name': 'routing_table_name'}).text = table_name
        ET.SubElement(options, tag('Option'),
                      {'name': 'routing_table_id'}).text = table_id
    fw.insert(list(fw).index(routing) + 1, new_rs)
    return new_rs


def _add_ip_rules_ruleset(tree, ruleset_id, name):
    """The per-firewall IPRules rule set that hosts IPRule objects
    (policy-based routing, W4.2). IP rules select which iproute2
    routing table a packet consults; they do not live in any table
    themselves. The rule set compiles into the "ip rule" script
    section only, never into the routing/route part."""
    root = tree.getroot()
    fw = only(root, ".//%s[@name='nft-test']" % tag('Firewall'))
    routing_sets = fw.findall('./' + tag('Routing'))
    if not routing_sets:
        raise ValueError('expected the baseline Routing rule set')
    # DTD Firewall content keeps the order NAT*, Policy*, Routing*,
    # IPRules*, Interface*: insert right after the last routing rule
    # set.
    new_rs = ET.Element(tag('IPRules'), {
        'id': ruleset_id,
        'name': name,
        'comment': 'CI per-firewall ip rules rule set',
        'ro': 'False',
        'ipv4_rule_set': 'False',
        'ipv6_rule_set': 'False',
        'top_rule_set': 'False',
    })
    ET.SubElement(new_rs, tag('RuleSetOptions'))
    fw.insert(list(fw).index(routing_sets[-1]) + 1, new_rs)
    return new_rs


def _add_ip_rule(ruleset, rule_id, position, priority, src='sysid0',
                 dst='sysid0', srv='sysid1', itf_inb='sysid0',
                 itf_outb='sysid0', lookup_ruleset_id=None, comment='',
                 extra_options=None):
    """One IPRule in the exact DTD child order (Src, Dst, Srv, ItfInb,
    ItfOutb, IPRuleOptions). "any" references keep the selector out of
    the compiled ip rule spec. extra_options adds further free-form
    IPRuleOptions entries (W4.3 runtime variables)."""
    rule = ET.Element(tag('IPRule'), {
        'id': rule_id,
        'disabled': 'False',
        'group': '',
        'position': str(position),
        'priority': str(priority),
        'comment': comment,
    })
    for child_name, ref_tagname, ref in (
            ('Src', 'ObjectRef', src), ('Dst', 'ObjectRef', dst),
            ('Srv', 'ServiceRef', srv),
            ('ItfInb', 'ObjectRef', itf_inb),
            ('ItfOutb', 'ObjectRef', itf_outb)):
        child = ET.SubElement(rule, tag(child_name), {'neg': 'False'})
        ET.SubElement(child, tag(ref_tagname), {'ref': ref})
    options = ET.SubElement(rule, tag('IPRuleOptions'))
    option = ET.SubElement(options, tag('Option'),
                           {'name': 'ip_rule_lookup_id'})
    option.text = lookup_ruleset_id
    if extra_options:
        for name, value in extra_options.items():
            extra = ET.SubElement(options, tag('Option'),
                                  {'name': name})
            extra.text = value
    ruleset.insert(list(ruleset).index(
        only(ruleset, './' + tag('RuleSetOptions'))), rule)


def case_ip_rule(tree):
    """One IPRule using every selector: source network, fwmark tag,
    iif/oif interfaces and a named-table lookup target.

    Expected compiled section:

        FWB_RULE_REPLACE=0
        fwb_rule_prepare 4 100 'from 192.0.2.0/24 fwmark 64 iif eth0 \
            oif eth1 lookup ci_iprule' && \
        $IP rule add pref 100 from 192.0.2.0/24 fwmark 64 iif eth0 \
            oif eth1 lookup ci_iprule && \
        ...
    """
    _add_named_routing_ruleset(tree, 'ci_iprule', '103', 'iprule')
    _set_manage_rt_tables(tree, 'True')
    root = tree.getroot()
    _add_tag_service(root, 'fwb-ci-iprule-tag-64', '64',
                     'CI ip rule fwmark 64')
    ruleset = only(root, ".//%s[@id='fwb-ci-route-iprule']" % tag('Routing'))
    # id3F4ECE3F is the real baseline TEST-NET 192.0.2.0/24, eth0 and
    # eth1 are the real nft-test interfaces.
    _add_ip_rule(ruleset, 'fwb-ci-iprule-1', 1, 100,
                 src='id3F4ECE3F',
                 srv='fwb-ci-iprule-tag-64',
                 itf_inb='id2687X30989',
                 itf_outb='id2692X30989',
                 lookup_ruleset_id='fwb-ci-route-iprule',
                 comment='CI: marked test-net traffic goes to ci_iprule')


def case_ip_rule_ipv6(tree):
    """An IPv6-only IPRule looking up the untouched main table.

    case_ipv6() first flips the preserved IPv4-only policy to IPv6.
    The -6 compiler pass requires RuleSet::matchingAddressFamily() plus
    at least one compiled native rule; without an IPv6 policy the -6
    script contains no FWB_NFT_RULESET block and the structure check
    rejects it, exactly like the other IPv6 fixtures. The pure IPv6
    rule must compile into the "$IP -6 rule add" form and must never
    emit a plain v4 rule line.
    """
    case_ipv6(tree)
    ruleset = _add_ip_rule_routing_ruleset(tree, 'fwb-ci-route-ip6',
                                           'route_ip6')
    # id2088X75851 is the real baseline 2001:db8::/32 documentation
    # net; id2734X30989 is the baseline main "Routing" rule set.
    _add_ip_rule(ruleset, 'fwb-ci-iprule-2', 0, 200,
                 src='id2088X75851',
                 lookup_ruleset_id='id2734X30989',
                 comment='CI: documentation-net traffic stays in main')


def case_ip_rule_replace(tree):
    """The ip_rule_strategy=replace option flips the helper switch.

    The ruleset table is not managed this time, so the lookup token is
    the numeric table id 104; the section still defaults to the strict
    helpers, only FWB_RULE_REPLACE selects the flush behavior.
    """
    _add_named_routing_ruleset(tree, 'ci_iprulex', '104', 'ipx')
    fw = only(tree.getroot(), ".//%s[@name='nft-test']" % tag('Firewall'))
    opts = only(fw, './' + tag('FirewallOptions'))
    option = ET.SubElement(opts, tag('Option'),
                           {'name': 'ip_rule_strategy'})
    option.text = 'replace'
    root = tree.getroot()
    _add_tag_service(root, 'fwb-ci-iprule-tag-65', '65',
                     'CI ip rule fwmark 65')
    ruleset = only(root, ".//%s[@id='fwb-ci-route-ipx']" % tag('Routing'))
    _add_ip_rule(ruleset, 'fwb-ci-iprule-3', 1, 300,
                 srv='fwb-ci-iprule-tag-65',
                 lookup_ruleset_id='fwb-ci-route-ipx',
                 comment='CI: replace-strategy fwmark rule')


def case_ip_rule_set(tree):
    """IPRule objects in their own per-firewall IPRules rule set (W4.2).

    The rule set sits next to the routing rule sets (content order
    NAT, Policy, Routing, IPRules, Interface) and only adds to the
    "ip rule" script section: no "Routing rule set" header and no
    route commands may appear for it. The lookup target is the
    untouched main rule set, so the lookup token is "main".
    """
    ruleset = _add_ip_rules_ruleset(tree, 'fwb-ci-iprules', 'IP Rules')
    # id3F4ECE3F is the real baseline TEST-NET 192.0.2.0/24,
    # id2734X30989 is the baseline main "Routing" rule set.
    _add_ip_rule(ruleset, 'fwb-ci-iprules-1', 0, 110,
                 src='id3F4ECE3F',
                 lookup_ruleset_id='id2734X30989',
                 comment='CI: test-net traffic stays in the main table')


def case_ip_rule_runtime_var(tree):
    """One IPRule selecting on the runtime shell variable provider_ip.

    W4.3: the address behind the modem is only known at activation
    time, so the prolog fills $provider_ip with the shipped
    fwb_get_provider_ip helper and the compiled ip rule references
    the variable. The helper must be defined before the prolog runs;
    the ip rule section must guard the variable and expand it through
    a per-combination spec variable before fwb_rule_prepare compares
    the state, so the state file records the resolved address.
    """
    root, fw, _, _ = prepare(tree)
    opts = only(fw, './' + tag('FirewallOptions'))
    prolog = (
        '# ci-prolog: determine the provider address, fail otherwise\n'
        'fwb_get_provider_ip eth0 192.168.1.10 || exit 1\n'
    )
    for name, value in (
            ('prolog_place', 'after_interfaces'),
            ('prolog_script', prolog),
    ):
        found = opts.findall("./%s[@name='%s']" % (tag('Option'), name))
        if len(found) > 1:
            raise ValueError('duplicate firewall option ' + name)
        option = found[0] if found else ET.SubElement(
            opts, tag('Option'), {'name': name})
        option.text = value
    ruleset = _add_ip_rules_ruleset(tree, 'fwb-ci-iprules-rt', 'IP Rules')
    _add_ip_rule(ruleset, 'fwb-ci-iprules-rt-1', 0, 120,
                 lookup_ruleset_id='id2734X30989',
                 comment='CI: traffic from the provider address stays in main',
                 extra_options={'ip_rule_src_runtime_var': 'provider_ip'})


def case_reject_ip_rule_var_conflict(tree):
    """A static source object plus a source runtime variable aborts.

    One ip rule can not express the union of a static prefix and a
    runtime-variable selector; the compiler must fail with the
    specific diagnostic instead of silently dropping one part.
    """
    ruleset = _add_ip_rules_ruleset(tree, 'fwb-ci-iprules-rv', 'IP Rules')
    _add_ip_rule(ruleset, 'fwb-ci-iprules-rv-1', 0, 130,
                 src='id3F4ECE3F',
                 lookup_ruleset_id='id2734X30989',
                 extra_options={'ip_rule_src_runtime_var': 'provider_ip'})


def case_reject_ip_rule_var_badname(tree):
    """A runtime variable with shell metacharacters must be rejected.

    The variable name is interpolated into the generated script, so
    anything but a strict shell identifier must abort the compile.
    """
    ruleset = _add_ip_rules_ruleset(tree, 'fwb-ci-iprules-rb', 'IP Rules')
    _add_ip_rule(ruleset, 'fwb-ci-iprules-rb-1', 0, 140,
                 lookup_ruleset_id='id2734X30989',
                 extra_options={'ip_rule_dst_runtime_var': 'pro vider; rm -rf'})


def case_reject_ip_rule_duplicate_priority(tree):
    """Two IPRules in two rule sets sharing priority 100 must abort.

    Priorities are unique per family and firewall, not per rule set:
    the state file and the shell helpers key by priority only.
    """
    _add_named_routing_ruleset(tree, 'ci_dup1', '105', 'dupa')
    _add_named_routing_ruleset(tree, 'ci_dup2', '106', 'dupb')
    root = tree.getroot()
    rs1 = only(root, ".//%s[@id='fwb-ci-route-dupa']" % tag('Routing'))
    rs2 = only(root, ".//%s[@id='fwb-ci-route-dupb']" % tag('Routing'))
    _add_ip_rule(rs1, 'fwb-ci-iprule-dup-1', 1, 100,
                 lookup_ruleset_id='fwb-ci-route-dupa')
    _add_ip_rule(rs2, 'fwb-ci-iprule-dup-2', 1, 100,
                 src='id3F4ECE3F',
                 lookup_ruleset_id='fwb-ci-route-dupb')


def _set_runtime_var_prolog(fw):
    """The W4.3 prolog pattern shared by the W4.4 runtime-variable
    fixtures: the prolog fills $provider_ip with the shipped
    fwb_get_provider_ip helper and aborts when it can not."""
    opts = only(fw, './' + tag('FirewallOptions'))
    prolog = (
        '# ci-prolog: determine the provider address, fail otherwise\n'
        'fwb_get_provider_ip eth0 192.168.1.10 || exit 1\n'
    )
    for name, value in (
            ('prolog_place', 'after_interfaces'),
            ('prolog_script', prolog),
    ):
        found = opts.findall("./%s[@name='%s']" % (tag('Option'), name))
        if len(found) > 1:
            raise ValueError('duplicate firewall option ' + name)
        option = found[0] if found else ET.SubElement(
            opts, tag('Option'), {'name': name})
        option.text = value


def case_nat_snat_runtime_var(tree):
    """SNAT to the runtime shell variable provider_ip (W4.4).

    The translated source address is only known at activation time;
    the prolog fills $provider_ip with fwb_get_provider_ip and the
    compiled rule must reference the guarded $rv_provider_ip
    placeholder through a FWB_NFT_DYNRULE wrapper block. The TagService
    in OSrv mirrors the provider-policy use case: only packets marked 4
    are translated. The raw variable must never reach the staged rule
    and an unset variable must abort the activation before the commit.
    """
    root, fw, _, nr = prepare(tree)
    _set_runtime_var_prolog(fw)
    _add_tag_service(root, 'fwb-ci-tag-4', '4', 'CI provider mark 4')
    nat = only(fw, './' + tag('NAT'))
    replace_ref(nr, 'OSrc', 'id3DC75CE7-1')  # real FWB 192.168.1.0/24
    replace_ref(nr, 'ODst', 'sysid0')
    replace_ref(nr, 'OSrv', 'fwb-ci-tag-4')
    replace_ref(nr, 'TSrc', 'sysid0')  # runtime variable replaces TSrc
    replace_ref(nr, 'TDst', 'sysid0')
    replace_ref(nr, 'TSrv', 'sysid1')
    for element in ('OSrc', 'ODst', 'OSrv', 'TSrc', 'TDst', 'TSrv'):
        only(nr, './' + tag(element)).set('neg', 'False')
    opts = only(nr, './' + tag('NATRuleOptions'))
    ET.SubElement(opts, tag('Option'),
                  {'name': 'nat_tsrc_runtime_var'}).text = 'provider_ip'
    for other in nat.findall('./' + tag('NATRule')):
        other.set('disabled', 'False' if other is nr else 'True')


def case_policy_src_runtime_var(tree):
    """A filter rule matching the runtime provider address (W4.4).

    Source is a shell variable the prolog fills before activation;
    the compiled rule must reference the guarded $rv_provider_ip
    placeholder through a FWB_NFT_DYNRULE wrapper block, never the raw
    variable inside the staged heredoc.
    """
    root, fw, pr, _ = prepare(tree)
    _set_runtime_var_prolog(fw)
    policy = only(fw, './' + tag('Policy'))
    fallback = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    _promote_before_fallback(policy, pr, fallback)
    _widen_rule_element_to_any(pr, 'Src')
    _widen_rule_element_to_any(pr, 'Dst')
    pr.set('comment', 'CI: accept from the runtime provider address')
    _set_rule_options(pr, {'policy_src_runtime_var': 'provider_ip'})


def case_mangle_src_runtime_var(tree):
    """Mark packets from the runtime provider address (W4.4).

    The mangle pipeline shares the policy processors, so a tagging
    rule whose source is the runtime shell variable must stage the
    same guarded wrapper and set the mark inside the mangle table.
    """
    root, fw, pr, _ = prepare(tree)
    _set_runtime_var_prolog(fw)
    policy = only(fw, './' + tag('Policy'))
    fallback = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    _promote_before_fallback(policy, pr, fallback)
    _add_tag_service(root, 'fwb-ci-tag-66', '66', 'CI provider mark 66')
    pr.set('action', 'Continue')
    pr.set('direction', 'Both')
    pr.set('comment', 'CI: mark packets from the runtime provider address')
    _widen_rule_element_to_any(pr, 'Src')
    _widen_rule_element_to_any(pr, 'Dst')
    _set_rule_options(pr, {
        'tagging': 'True',
        'tagobject_id': 'fwb-ci-tag-66',
        'policy_src_runtime_var': 'provider_ip',
    })


def case_reject_nat_runtime_var_conflict(tree):
    """A static translated source plus the runtime variable aborts.

    One SNAT rule can not translate to both a static address and a
    runtime-variable address; the compiler must fail with the
    specific diagnostic instead of silently dropping one part.
    """
    _, fw, _, nr = prepare(tree)
    nat = only(fw, './' + tag('NAT'))
    # The baseline TSrc holds a real address object (guarded by
    # case_nat_masquerade); only adding the option creates the conflict.
    opts = only(nr, './' + tag('NATRuleOptions'))
    ET.SubElement(opts, tag('Option'),
                  {'name': 'nat_tsrc_runtime_var'}).text = 'provider_ip'
    for other in nat.findall('./' + tag('NATRule')):
        other.set('disabled', 'False' if other is nr else 'True')


def case_reject_nat_runtime_var_badname(tree):
    """A runtime variable with shell metacharacters must be rejected.

    The variable name is interpolated into the generated script, so
    anything but a strict shell identifier must abort the compile.
    """
    _, fw, _, nr = prepare(tree)
    nat = only(fw, './' + tag('NAT'))
    opts = only(nr, './' + tag('NATRuleOptions'))
    ET.SubElement(opts, tag('Option'),
                  {'name': 'nat_tsrc_runtime_var'}).text = 'pro vider; rm -rf'
    for other in nat.findall('./' + tag('NATRule')):
        other.set('disabled', 'False' if other is nr else 'True')


def case_reject_policy_runtime_var_conflict(tree):
    """A static source object plus a source runtime variable aborts.

    One filter rule can not match the union of a static prefix and a
    runtime-variable address; the compiler must fail with the
    specific diagnostic instead of silently widening the match. The
    rule is promoted in front of the fallback deny so the shadowing
    pre-pass can not reject it for unrelated reasons first.
    """
    _, fw, pr, _ = prepare(tree)
    policy = only(fw, './' + tag('Policy'))
    fallback = only(policy, "./%s[@id='id2830X30989']" % tag('PolicyRule'))
    _promote_before_fallback(policy, pr, fallback)
    replace_ref(pr, 'Src', 'id3DC75CE7-1')  # real FWB 192.168.1.0/24
    only(pr, './' + tag('Src')).set('neg', 'False')
    _set_rule_options(pr, {'policy_src_runtime_var': 'provider_ip'})


CASES = {
    'reject-hashlimit-bad-mode': case_reject_hashlimit_bad_mode,
    'reject-hashlimit-icmp-port': case_reject_hashlimit_icmp_port,
    'hashlimit-srcip': case_hashlimit_srcip,
    'hashlimit-srcip-dstport': case_hashlimit_srcip_dstport,
    'hashlimit-udp-srcip-dstport': case_hashlimit_udp_srcip_dstport,
    'ipv6-hashlimit-srcip': case_ipv6_hashlimit_srcip,
    'ipv6-hashlimit-srcip-dstport': case_ipv6_hashlimit_srcip_dstport,
    'user-service-outbound': case_user_service_outbound,
    'negated-user-service-outbound': case_negated_user_service_outbound,
    'negated-ipv4-option-rr': case_negated_ipv4_option_rr,
    'negated-ipv4-option-ra': case_negated_ipv4_option_ra,
    'negated-ipv4-option-any': case_negated_ipv4_option_any,
    'negated-ipv4-option-combined': case_negated_ipv4_option_combined,
    'negated-ipv4-fragment': case_negated_ipv4_fragment,
    'reject-negated-ipv4-timestamp': case_reject_negated_ipv4_timestamp,
    'ipv4-option-rr': case_ipv4_option_rr,
    'ipv4-option-lsrr': case_ipv4_option_lsrr,
    'ipv4-option-ssrr': case_ipv4_option_ssrr,
    'ipv4-option-ra': case_ipv4_option_ra,
    'ipv4-option-any': case_ipv4_option_any,
    'ipv4-option-combined': case_ipv4_option_combined,
    'ipv6-icmp': case_ipv6,
    'ipv6-ndp': case_ipv6_ndp,
    'ipv6-route-rollback': case_ipv6_route_rollback,
    'reject-ipv6-route-link-local': case_reject_ipv6_route_link_local,
    'reject-ipv6-route-netmask': case_reject_ipv6_route_netmask,
    'reject-ipv6-route-mixed': case_reject_ipv6_route_mixed,
    'udp-workhours': case_udp_workhours,
    'policy-fragments': case_policy_fragments,
    'nat-fragments': case_nat_fragments,
    'negated-nat-odst': case_negated_nat_odst,
    'multi-address-set': case_multi_address_set,
    'nat-multi-address-set': case_nat_multi_address_set,
    'nat-masquerade': case_nat_masquerade,
    'mangle-tag': case_mangle_tag,
    'mark-match': case_mark_match,
    'mangle-classify': case_mangle_classify,
    'routing-table': case_routing_table,
    'routing-table-numeric': case_routing_table_numeric,
    'reject-routing-table-duplicate': case_reject_routing_table_duplicate,
    'routing-in-deleted-objects': case_routing_in_deleted_objects,
    'reject-policy-options': case_reject_policy_options,
    'reject-nat-options': case_reject_nat_options,
    'reject-timezone': case_reject_timezone,
    'prolog-after-flush': case_prolog_after_flush,
    'packet-tcp-input': case_packet_tcp_input,
    'packet-udp-forward': case_packet_udp_forward,
    'packet-snat': case_packet_snat,
    'packet-dnat': case_packet_dnat,
    'ipv6-nat-lb-contiguous': case_ipv6_nat_lb_contiguous,
    'ipv6-nat-lb-sparse': case_ipv6_nat_lb_sparse,
    'packet-ipv6-nat-lb-contiguous': case_packet_ipv6_nat_lb_contiguous,
    'packet-ipv6-nat-lb-sparse': case_packet_ipv6_nat_lb_sparse,
    'reject-ipv6-nat-lb-network': case_reject_ipv6_nat_lb_network,
    'reject-ipv6-nat-lb-duplicate': case_reject_ipv6_nat_lb_duplicate,
    'reject-ipv6-nat-lb-port-translation': case_reject_ipv6_nat_lb_port_translation,
    'nat-lb-contiguous': case_nat_lb_contiguous,
    'packet-nat-lb-sparse': case_packet_nat_lb_sparse,
    'packet-nat-lb-contiguous': case_packet_nat_lb_contiguous,
    'nat-lb-sparse': case_nat_lb_sparse,
    'reject-nat-lb-network': case_reject_nat_lb_network,
    'reject-nat-lb-duplicate': case_reject_nat_lb_duplicate,
    'reject-nat-lb-port-translation': case_reject_nat_lb_port_translation,
    'dynamic-address-sets': case_dynamic_address_sets,
    'dynamic-interface': case_dynamic_interface,
    'runtime-dns-name': case_runtime_dns_name,
    'module-load-ignored': case_module_load_ignored,
    'reject-addressless-interface': case_reject_addressless_interface,
    'ip-rule': case_ip_rule,
    'ip-rule-ipv6': case_ip_rule_ipv6,
    'ip-rule-replace': case_ip_rule_replace,
    'ip-rule-set': case_ip_rule_set,
    'ip-rule-runtime-var': case_ip_rule_runtime_var,
    'reject-ip-rule-var-conflict': case_reject_ip_rule_var_conflict,
    'reject-ip-rule-var-badname': case_reject_ip_rule_var_badname,
    'reject-ip-rule-duplicate-priority': case_reject_ip_rule_duplicate_priority,
    'nat-snat-runtime-var': case_nat_snat_runtime_var,
    'policy-src-runtime-var': case_policy_src_runtime_var,
    'mangle-src-runtime-var': case_mangle_src_runtime_var,
    'reject-nat-runtime-var-conflict': case_reject_nat_runtime_var_conflict,
    'reject-nat-runtime-var-badname': case_reject_nat_runtime_var_badname,
    'reject-policy-runtime-var-conflict': case_reject_policy_runtime_var_conflict,
    'reject-runtime-address-tables': case_reject_runtime_address_tables,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)
    for name, mutate in CASES.items():
        tree = ET.parse(args.baseline)
        root = tree.getroot()
        if root.tag != tag('FWObjectDatabase'):
            raise ValueError('not an FWB object database')
        mutate(tree)
        if name in ('ipv6-icmp', 'ipv6-ndp'):
            fw = only(root, ".//%s[@name='nft-test']" % tag('Firewall'))
            policy = only(fw, './' + tag('Policy'))
            if (policy.get('ipv4_rule_set'), policy.get('ipv6_rule_set')) != ('False', 'True'):
                raise ValueError('IPv6 fixture is not an IPv6 rule set')
            rules = policy.findall('./' + tag('PolicyRule'))
            expected = [('id9001X30989', '0', 'Accept'),
                        ('id2830X30989', '1', 'Deny')]
            if name == 'ipv6-ndp':
                expected = [('id9001X30989', '0', 'Accept'),
                            ('fwb-ci-ndp-ns', '1', 'Accept'),
                            ('fwb-ci-ndp-na', '2', 'Accept'),
                            ('id2830X30989', '3', 'Deny')]
                for rule, service in zip(rules[1:3],

                                         ('ipv6-icmp-neighbrsol', 'ipv6-icmp-neighbradv')):
                    if (only(rule, './' + tag('Src'))[0].get('ref') != 'sysid0'
                            or only(rule, './' + tag('Dst'))[0].get('ref') != 'sysid0'
                            or only(rule, './' + tag('Srv'))[0].get('ref') != service):
                        raise ValueError('invalid NDP rule references')
            actual = [(r.get('id'), r.get('position'), r.get('action')) for r in rules]
            if actual != expected:
                raise ValueError('IPv6 fixture has an unexpected policy rule order: ' + repr(actual))
            allow = rules[0]
            opts = only(allow, './' + tag('PolicyRuleOptions'))
            if (only(opts, "./%s[@name='stateless']" % tag('Option')).text != 'True'):
                raise ValueError('ICMPv6 allow must be explicitly stateless')
        id_values = [elem.attrib['id'] for elem in root.iter() if 'id' in elem.attrib]
        if len(id_values) != len(set(id_values)):
            raise ValueError('duplicated FWB ids in ' + name)
        out = args.destination / (name + '.fwb')
        with out.open('wb') as stream:
            stream.write(b'<?xml version="1.0" encoding="utf-8"?>\n')
            stream.write(b'<!DOCTYPE FWObjectDatabase SYSTEM "fwbuilder.dtd">\n')
            stream.write(ET.tostring(root, encoding='utf-8'))
            stream.write(b'\n')
        if ET.parse(out).getroot().tag != tag('FWObjectDatabase'):
            raise ValueError('invalid generated fixture ' + name)
        print('FWB XML fixture: ' + name)


if __name__ == '__main__':
    main()
