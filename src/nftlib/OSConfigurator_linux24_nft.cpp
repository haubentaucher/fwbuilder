/* 

                          Firewall Builder

                 Copyright (C) 2002 NetCitadel, LLC

  Author:  Vadim Kurland     vadim@vk.crocodile.org

  $Id$

  This program is free software which we release under the GNU General Public
  License. You may redistribute and/or modify this program under the terms
  of that license as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 
  To get a copy of the GNU General Public License, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include "OSConfigurator_linux24_nft.h"

#include "nftables_options.h"

#include "fwbuilder/Firewall.h"

#include "Configlet.h"
#include "fwbuilder/FWOptions.h"
#include "fwbuilder/Resources.h"

#include <QRegExp>
#include <QStringList>
#include <cctype>
#include <map>
#include <sstream>

using namespace std;
using namespace fwcompiler;
using namespace libfwbuilder;

OSConfigurator_linux24_nft::OSConfigurator_linux24_nft(
    FWObjectDatabase *_db,
    Firewall *fw,
    bool ipv6_policy) :
    OSConfigurator_linux24(_db, fw, ipv6_policy),
    os_data(fw->getStr("host_OS"))
{
    FWOptions *options = fw->getOptionsObject();
    setUsingIpSet(options->getBool("use_nft_sets"));
}

string OSConfigurator_linux24_nft::getPathForATool(
    const std::string &os_variant,
    OSData_nft::tools tool_name)
{
    FWOptions* options = fw->getOptionsObject();
    string attr = os_data.getAttributeNameForTool(tool_name);

    if (tool_name == OSData_nft::NFT)
    {
        string nft_path = options->getStr(attr);
        if (!nft_path.empty()) return nft_path;
        return "/usr/sbin/nft";
    }

    string s = options->getStr("linux24_" + attr);
    if (!s.empty()) return s;

    string host_os = fw->getStr("host_OS");
    string r = "/FWBuilderResources/Target/tools/" + os_variant + "/" + attr;
    if (Resources::os_res[host_os]->getResourceStr(r).empty())
        r = "/FWBuilderResources/Target/tools/Unknown/" + attr;

    return Resources::os_res[host_os]->getResourceStr(r);
}

string OSConfigurator_linux24_nft::printPathForAllTools(const string &os)
{
    ostringstream res;

    list<int>::const_iterator i;
    const list<int> &all_tools = os_data.getAllTools();
    for (i=all_tools.begin(); i!=all_tools.end(); ++i)
        res << os_data.getVariableName(OSData_nft::tools(*i))
            << "=\""
            << getPathForATool(os, OSData_nft::tools(*i))
            << "\""
            << "\n";

    string nft_conf = fw->getOptionsObject()->getStr("nftables_conf_path");
    if (!nft_conf.empty())
        res << "NFTABLES_CONF=\"" << nft_conf << "\"" << "\n";

    return res.str();
}

string OSConfigurator_linux24_nft::printShellFunctions(bool have_ipv6)
{
    (void)have_ipv6;

    QStringList output;
    FWOptions* options = fw->getOptionsObject();

    Configlet shell_functions(fw, "nftables", "nft_shell_functions");
    output.push_back(shell_functions.expand());

    Configlet configlet(fw, "nftables", "nft_check_utilities");
    configlet.removeComments();
    configlet.collapseEmptyStrings(true);

    // Kernel-native nftables autoloads its conntrack/NAT modules; the
    // "load modules" firewall option must not require a modprobe binary
    // to exist either (appliance systems such as OpenWrt ship none in
    // the base system). Managing vlan or bonding interfaces is the only
    // remaining, genuine modprobe user in a generated script.
    if (options->getBool("configure_vlan_interfaces") ||
        options->getBool("configure_bonding_interfaces"))
    {
        configlet.setVariable("need_modprobe", true);
    }

    if (options->getBool("verify_interfaces") ||
        options->getBool("manage_virtual_addr") ||
        options->getBool("configure_interfaces") )
    {
        configlet.setVariable("need_vconfig",
                              options->getBool("configure_vlan_interfaces"));
        configlet.setVariable("need_brctl",
                              options->getBool("configure_bridge_interfaces"));
        configlet.setVariable("need_ifenslave",
                              options->getBool("configure_bonding_interfaces"));
    }

    configlet.setVariable("need_ipset", false);

    output.push_back(configlet.expand());

    Configlet reset_nftables(fw, "nftables", "reset_nftables");
    output.push_back(reset_nftables.expand());

    Configlet addr_conf(fw, "linux24", "update_addresses");
    output.push_back(addr_conf.expand());

    if (options->getBool("configure_vlan_interfaces"))
    {
        Configlet conf(fw, "linux24", "update_vlans");
        output.push_back(conf.expand());
    }

    if (options->getBool("configure_bridge_interfaces"))
    {
        Configlet conf(fw, "linux24", "update_bridge");
        output.push_back(conf.expand());
    }

    if (options->getBool("configure_bonding_interfaces"))
    {
        Configlet conf(fw, "linux24", "update_bonding");
        output.push_back(conf.expand());
    }

    return output.join("\n").toStdString();
}

namespace {
std::string fwbNftShellQuote(const std::string &value)
{
    std::string result("'");
    for (char ch : value)
    {
        if (ch == '\'') result += "'\"'\"'";
        else result += ch;
    }
    return result + "'";
}
}

string OSConfigurator_linux24_nft::printRunTimeAddressTablesCode()
{
    Configlet conf(fw, "nftables", "nft_run_time_address_tables");
    conf.setVariable("using_ipset", usesIpSet());

    ostringstream check_ostr;
    ostringstream load_ostr;
    const map<string, string> &address_tables = getAddressTableObjects();
    map<string, string>::const_iterator i;
    for (i=address_tables.begin(); i!=address_tables.end(); ++i)
    {
        const string at_name = normalizeSetName(i->first);
        const string &at_file = i->second;
        if (!at_file.empty())
        {
            check_ostr << "check_file " << fwbNftShellQuote(at_name)
                       << " " << fwbNftShellQuote(at_file) << "\n";
            load_ostr << "fwb_nft_stage_one_address_table "
                      << fwbNftShellQuote(at_name) << " "
                      << fwbNftShellQuote(at_file) << " || return 1" << "\n";
        }
    }

    conf.setVariable("check_files_commands", check_ostr.str().c_str());
    conf.setVariable("load_files_commands", load_ostr.str().c_str());

    return conf.expand().toStdString();
}

/*
 * Run-time DNSName objects can not reach "nft -f" as literal host names:
 * nftables resolves names itself at commit time and refuses names that
 * map to several addresses. The compilers emit a stable placeholder
 * variable instead (PolicyCompiler_nft::PrintRule::_printAddr and
 * NATCompiler_nft::PrintRule::_printAddr) which printRunTimeWrappers()
 * below turns into a resolver loop at activation time. Host names that
 * sanitize to the same variable name ("a.b" vs "a_b") must never share a
 * variable: they get deterministic numeric suffixes.
 */
string OSConfigurator_linux24_nft::registerRunTimeDNSName(const string &hostname)
{
    string base = "dn_";
    for (char ch : hostname)
    {
        if (isalnum(static_cast<unsigned char>(ch)) || ch == '_')
            base += ch;
        else
            base += '_';
    }

    string var = base;
    for (int disambiguation = 2; ; ++disambiguation)
    {
        map<string, string>::const_iterator it = run_time_dns_names.find(var);
        if (it == run_time_dns_names.end())
        {
            run_time_dns_names[var] = hostname;
            return var;
        }
        if (it->second == hostname)
            return var;
        ostringstream suffix;
        suffix << "_" << disambiguation;
        var = base + suffix.str();
    }
}

/*
 * Multi-value run-time rules and the atomic nftables transaction.
 *
 * The iptables-era wrapper (OSConfigurator_linux24::printRunTimeWrappers)
 * surrounds a rule with shell loops that iterate over live interface
 * addresses and re-execute the command per value. Native nftables rules
 * are not commands, they are staged text: the driver writes the whole
 * rule stream into the UNQUOTED "cat >> $FWB_NFT_TXN <<FWB_NFT_RULESET"
 * heredoc. A loop construct inside that heredoc is stored verbatim as
 * "nft -f" input (or worse, with the loop variables already expanded to
 * empty strings while the heredoc is read).
 *
 * This override therefore emits dedicated shell blocks that live OUTSIDE
 * the ruleset heredoc, between its segments: each block iterates over its
 * values and appends the resolved copies with its own tiny unquoted
 * FWB_NFT_DYNRULE heredoc into the SAME open transaction. Rule order is
 * preserved (the driver splits the block out of the stream in place),
 * transaction atomicity is preserved (blocks run before the commit) and
 * the "stage nothing when the value list is empty" behavior is preserved
 * (the loop simply never runs).
 *
 * The blocks are surrounded by "#FWB_NFT_WRAPPER_BEGIN" and
 * "#FWB_NFT_WRAPPER_END" marker lines; CompilerDriver_nft::run() moves
 * everything between them out of the heredoc.
 */
string OSConfigurator_linux24_nft::printRunTimeWrappers(FWObject *rule,
                                                        const string &command,
                                                        bool ipv6)
{
    FWOptions *options = fw->getOptionsObject();
    if (!useNftablesAtomic(options))
        return OSConfigurator_linux24::printRunTimeWrappers(rule, command, ipv6);

    QString combined(command.c_str());

    // Run-time address tables are only legal with named nft sets in atomic
    // mode; without them the compilers reject the rule before printing.
    // Guard the impossible combination with the legacy wrapper rather
    // than inventing a hybrid layout.
    if (QRegExp("\\$at_\\S+").indexIn(combined) > -1)
        return OSConfigurator_linux24::printRunTimeWrappers(rule, command, ipv6);

    QStringList loop_inits;   // complete "for <var> in <list>" lines
    QStringList loop_vars;   // variables to guard and close, in nesting order
    QString wildcard_family; // non-empty: one wildcard interface family

    // Dynamic interface addresses and attached networks: either a plain
    // dynamic interface ($i_<name>, $i_<name>_network) or exactly one
    // wildcard interface family ($i_<family>*), like the base class.
    QRegExp intf_re("\\$i_([^ :]+)");
    int pos = -1;
    while ((pos = intf_re.indexIn(combined, pos + 1)) > -1)
    {
        const QString name = intf_re.cap(1);
        if (name.contains('*'))
        {
            wildcard_family = name.section('*', 0, 0);
            // Replace $i_<family>* with $addr; must match the shell code
            // emitted below.
            combined.replace(pos, intf_re.matchedLength(), "$addr");
            break;
        }
        if (loop_vars.contains("i_" + name))
            continue;   // same dynamic interface in Src and Dst
        loop_inits.push_back(QString("for i_%1 in $i_%1_list").arg(name));
        loop_vars.push_back(QString("i_") + name);
    }

    // Run-time DNSName placeholders registered by the compilers. The
    // regex captures the name WITHOUT the "$dn_" prefix; the map keys
    // and the placeholders printed by the compilers DO carry it
    // (registerRunTimeDNSName stores "dn_" + sanitized host). Restore
    // the prefix for the lookup AND the emitted loop variable, or the
    // lookup never succeeds, the loop is never emitted and the rule
    // falls into the plain ruleset heredoc, where the placeholder
    // expands to an empty address operand while the heredoc is read.
    QRegExp dns_re("\\$dn_([A-Za-z0-9_]+)");
    pos = -1;
    while ((pos = dns_re.indexIn(combined, pos + 1)) > -1)
    {
        const QString var_name = QString("dn_") + dns_re.cap(1);
        map<string, string>::const_iterator it =
            run_time_dns_names.find(var_name.toStdString());
        // A placeholder without registration can not be produced by the
        // compilers; leave it to the final validation to catch leftovers.
        if (it == run_time_dns_names.end())
            continue;
        if (loop_vars.contains(var_name))
            continue;
        loop_inits.push_back(
            QString("for %1 in $(fwb_nft_resolve \"%2\" %3)")
                .arg(var_name)
                .arg(QString::fromUtf8(it->second.c_str()))
                .arg(ipv6 ? "6" : "4"));
        loop_vars.push_back(var_name);
    }

    if (loop_vars.isEmpty() && wildcard_family.isEmpty())
        return string(command) + "\n";

    QStringList block;
    block.push_back("#FWB_NFT_WRAPPER_BEGIN");

    if (!wildcard_family.isEmpty())
    {
        // The wildcard loop iterates over every live interface of the
        // family and every address assigned to it, like the base class.
        block.push_back(QString("getinterfaces %1 | while read I; do").arg(wildcard_family));
        block.push_back("ivar=$(getInterfaceVarName $I)");
        block.push_back(QString("getaddr%1 $I $ivar").arg(ipv6 ? "6" : ""));
        block.push_back("cmd=\"$\"${ivar}_list");
        block.push_back("eval \"addr_list=$cmd\"");
        block.push_back("for addr in $addr_list");
        block.push_back("do");
    }
    for (const QString &init : loop_inits)
    {
        block.push_back(init);
        block.push_back("do");
    }

    // Guarded staging append: run per value, stage nothing when a value is
    // empty, never expose the loop to "nft -f" input without the guard.
    QString guard_line;
    QStringList guards(loop_vars);
    if (!wildcard_family.isEmpty())
        guards.push_front("addr");
    for (const QString &var : guards)
        guard_line += QString("test -n \"$%1\" && ").arg(var);
    guard_line += "cat >> \"$FWB_NFT_TXN\" <<FWB_NFT_DYNRULE";
    block.push_back(guard_line);

    const QStringList command_lines = combined.split("\n",
#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
        Qt::KeepEmptyParts);
#else
        QString::KeepEmptyParts);
#endif
    for (const QString &line : command_lines)
        block.push_back(line);
    block.push_back("FWB_NFT_DYNRULE");

    for (int closers = loop_inits.size(); closers > 0; --closers)
        block.push_back("done");
    if (!wildcard_family.isEmpty())
    {
        block.push_back("done");   // closes "for addr in $addr_list"
        block.push_back("done");   // closes "while read I"
    }
    block.push_back("#FWB_NFT_WRAPPER_END");

    return block.join("\n").toStdString() + "\n";
}
