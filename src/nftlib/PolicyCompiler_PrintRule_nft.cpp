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

#include "PolicyCompiler_nft.h"
#include "OSConfigurator_linux24.h"

#include "fwbuilder/RuleElement.h"
#include "fwbuilder/IPService.h"
#include "fwbuilder/ICMPService.h"
#include "fwbuilder/ICMP6Service.h"
#include "fwbuilder/TCPService.h"
#include "fwbuilder/UDPService.h"
#include "fwbuilder/CustomService.h"
#include "fwbuilder/TagService.h"
#include "fwbuilder/Policy.h"
#include "fwbuilder/Network.h"
#include "fwbuilder/DNSName.h"
#include "fwbuilder/AddressRange.h"
#include "fwbuilder/AttachedNetworks.h"

#include "fwbuilder/FWObjectDatabase.h"
#include "fwbuilder/RuleElement.h"
#include "fwbuilder/Policy.h"
#include "fwbuilder/Interface.h"
#include "fwbuilder/IPv4.h"
#include "fwbuilder/Firewall.h"
#include "fwbuilder/Resources.h"
#include "fwbuilder/AddressTable.h"
#include "fwbuilder/UserService.h"

#include "fwbuilder/Inet6AddrMask.h"

#include "combinedAddress.h"

#include "nft_utils.h"
#include "nftables_options.h"

#include "Configlet.h"

#include <QStringList>
#include <QtDebug>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <set>

#include <assert.h>

using namespace libfwbuilder;
using namespace fwcompiler;
using namespace std;

// The legacy 5.3 branch does not have TCPService::getFlagName().
 // Keep this nftables-only formatting helper local to the new backend.
namespace {
std::string nftTcpFlagName(libfwbuilder::TCPService::TCPFlag flag)
{
    using libfwbuilder::TCPService;
    switch (flag) {
    case TCPService::URG: return "urg";
    case TCPService::ACK: return "ack";
    case TCPService::PSH: return "psh";
    case TCPService::RST: return "rst";
    case TCPService::SYN: return "syn";
    case TCPService::FIN: return "fin";
    }
    return "";
}
}




/**
 *-----------------------------------------------------------------------
 *                    Methods for printing
 */

string PolicyCompiler_nft::PrintRule::_printSingleObjectNegation(
    RuleElement *rel)
{
    if (rel->getBool("single_object_negation"))   return "not ";
    else return "";
}

/*
 * Prints single --option with argument and negation "!"
 * taking into account the change that happened in iptables 1.4.3.1
 * that causes warning
 * Using intrapositioned negation (`--option ! this`) is deprecated in favor of extrapositioned (`! --option this`).
 */
string PolicyCompiler_nft::PrintRule::_printSingleOptionWithNegation(
    const string &option, RuleElement *rel, const string &arg)
{
    if (rel->getBool("single_object_negation"))
        return option + " != " + arg + " ";
    return option + " " + arg + " ";
}

void PolicyCompiler_nft::PrintRule::resetSetTracking()
{
    omit_src_addr_for_concat = false;
    omit_dst_addr_for_concat = false;
    omit_src_port_for_concat = false;
    omit_dst_port_for_concat = false;
}

string PolicyCompiler_nft::PrintRule::trimSpaces(const string &value) const
{
    size_t start = value.find_first_not_of(' ');
    if (start == string::npos) return "";
    size_t end = value.find_last_not_of(' ');
    return value.substr(start, end - start + 1);
}

vector<string> PolicyCompiler_nft::PrintRule::collectAddressSetEntries(
    RuleElement *rel)
{
    vector<string> entries;
    for (FWObject::iterator i=rel->begin(); i!=rel->end(); ++i)
    {
        FWObject *o = *i;
        if (FWReference::cast(o)!=nullptr) o = FWReference::cast(o)->getPointer();
        Address *addr = Address::cast(o);
        if (addr == nullptr) continue;
        string entry = formatAddressSetEntry(addr);
        entry = trimSpaces(entry);
        if (!entry.empty()) entries.push_back(entry);
    }
    return entries;
}

vector<string> PolicyCompiler_nft::PrintRule::collectPortSetEntries(
    RuleElementSrv *rel, bool src_ports)
{
    vector<string> entries;
    for (FWObject::iterator i=rel->begin(); i!=rel->end(); ++i)
    {
        FWObject *o = *i;
        if (FWReference::cast(o)!=nullptr) o = FWReference::cast(o)->getPointer();
        Service *srv = Service::cast(o);
        if (srv == nullptr) return vector<string>();
        if (!TCPService::isA(srv) && !UDPService::isA(srv))
            return vector<string>();
        string entry = src_ports ? _printSrcPorts(srv) : _printDstPorts(srv);
        entry = trimSpaces(entry);
        if (entry.empty()) return vector<string>();
        entries.push_back(entry);
    }
    return entries;
}

string PolicyCompiler_nft::PrintRule::formatAddressSetEntry(Address *addr)
{
    if (AddressRange::cast(addr)!=nullptr)
    {
        AddressRange *ar = AddressRange::cast(addr);
        const InetAddr &range_start = ar->getRangeStart();
        const InetAddr &range_end = ar->getRangeEnd();
        if (range_start != range_end)
            return range_start.toString() + "-" + range_end.toString();
        return range_start.toString();
    }
    return _printAddr(addr);
}

string PolicyCompiler_nft::PrintRule::printAddressSet(
    RuleElement *rel, const string &direction)
{
    PolicyCompiler_nft *ipt_comp=dynamic_cast<PolicyCompiler_nft*>(compiler);
    vector<string> entries = collectAddressSetEntries(rel);
    if (entries.empty()) return "";

    std::ostringstream ostr;
    ostr << (ipt_comp->ipv6 ? "ip6 " : "ip ") << direction;
    if (rel->getNeg()) ostr << " != { ";
    else ostr << " { ";

    for (size_t i=0; i<entries.size(); ++i)
    {
        if (i != 0) ostr << ", ";
        ostr << entries[i];
    }
    ostr << " } ";
    return ostr.str();
}

string PolicyCompiler_nft::PrintRule::printPortSet(
    RuleElementSrv *rel, const string &proto, bool src_ports)
{
    vector<string> entries = collectPortSetEntries(rel, src_ports);
    if (entries.empty()) return "";

    std::ostringstream ostr;
    ostr << proto << (src_ports ? " sport" : " dport");
    if (rel->getNeg()) ostr << " != { ";
    else ostr << " { ";

    for (size_t i=0; i<entries.size(); ++i)
    {
        if (i != 0) ostr << ", ";
        ostr << entries[i];
    }
    ostr << " } ";
    return ostr.str();
}

string PolicyCompiler_nft::PrintRule::printConcatenatedSet(PolicyRule *rule)
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    if (!ipt_comp->isNftSetOptimizationEnabled()) return "";

    RuleElementSrc *srcrel = rule->getSrc();
    RuleElementDst *dstrel = rule->getDst();
    RuleElementSrv *srvrel = rule->getSrv();
    if (srvrel->isAny()) return "";
    if (srcrel->getNeg() || dstrel->getNeg() || srvrel->getNeg()) return "";
    if (srcrel->getBool("single_object_negation") ||
        dstrel->getBool("single_object_negation") ||
        srvrel->getBool("single_object_negation"))
        return "";

    Service *srv = compiler->getFirstSrv(rule);
    if (!TCPService::isA(srv) && !UDPService::isA(srv)) return "";

    vector<string> dst_ports = collectPortSetEntries(srvrel, false);
    if (dst_ports.size() <= 1) return "";
    vector<string> src_ports = collectPortSetEntries(srvrel, true);
    if (!src_ports.empty()) return "";

    RuleElement *addr_rel = nullptr;
    string direction;
    if (ipt_comp->canUseNftSetForAddresses(srcrel))
    {
        addr_rel = srcrel;
        direction = "saddr";
        omit_src_addr_for_concat = true;
    } else if (ipt_comp->canUseNftSetForAddresses(dstrel))
    {
        addr_rel = dstrel;
        direction = "daddr";
        omit_dst_addr_for_concat = true;
    } else return "";

    vector<string> addr_entries = collectAddressSetEntries(addr_rel);
    if (addr_entries.size() <= 1) return "";

    vector<string> tuples;
    for (size_t i=0; i<addr_entries.size(); ++i)
    {
        for (size_t j=0; j<dst_ports.size(); ++j)
        {
            tuples.push_back(addr_entries[i] + " . " + dst_ports[j]);
        }
    }
    if (tuples.empty()) return "";

    omit_dst_port_for_concat = true;

    string proto = TCPService::isA(srv) ? "tcp" : "udp";
    std::ostringstream ostr;
    ostr << (ipt_comp->ipv6 ? "ip6 " : "ip ")
         << direction << " . " << proto << " dport { ";
    for (size_t i=0; i<tuples.size(); ++i)
    {
        if (i != 0) ostr << ", ";
        ostr << tuples[i];
    }
    ostr << " } ";
    return ostr.str();
}

void PolicyCompiler_nft::PrintRule::initializeMinusNTracker()
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    for (list<string>::const_iterator i =
             PolicyCompiler_nft::getStandardChains().begin();
         i != PolicyCompiler_nft::getStandardChains().end(); ++i)
    {
        (*(ipt_comp->minus_n_commands))[*i] = true;
    }
    minus_n_tracker_initialized = true;
}
            

/*
 *  check and create new chain if needed
 */
string PolicyCompiler_nft::PrintRule::_createChain(const string &chain)
{
    string res;
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);

    if (!minus_n_tracker_initialized) initializeMinusNTracker();

    if ( ipt_comp->minus_n_commands->count(chain)==0 )
    {
        bool atomic = useNftablesAtomic(compiler->getCachedFwOpt());
        string prefix = nft_utils::commandPrefix(atomic);
        string base_chain = nft_utils::baseChainDefinition(
            ipt_comp->my_table, chain, ipt_comp->ipv6, "drop");
        if (!base_chain.empty())
        {
            res = prefix + base_chain + "\n";
        } else
        {
            res = prefix + "add chain " + nft_utils::familyName(ipt_comp->ipv6) +
                " " + nft_utils::managedTableName(ipt_comp->my_table) + " " + chain + "\n";
        }
	(*(ipt_comp->minus_n_commands))[chain] = true;
    }
    return res;
}

string PolicyCompiler_nft::PrintRule::_startRuleLine()
{            
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    bool atomic = useNftablesAtomic(compiler->getCachedFwOpt());
    string prefix = nft_utils::commandPrefix(atomic);
    return prefix + "add rule " + nft_utils::familyName(ipt_comp->ipv6) + " " +
        nft_utils::managedTableName(ipt_comp->my_table) + " ";
}

string PolicyCompiler_nft::PrintRule::_endRuleLine()
{            
    return string("\n");
}

string PolicyCompiler_nft::PrintRule::_printRuleLabel(PolicyRule *rule)
{
    ostringstream res;

    bool nocomm = Resources::os_res[compiler->fw->getStr("host_OS")]->
        Resources::getResourceBool(
            "/FWBuilderResources/Target/options/suppress_comments");

    // TODO: convert this into virtual function PolicyCompiler_nft::printComment()
    string rl=rule->getLabel();
    if (rl != current_rule_label)
    {
        if (!compiler->inSingleRuleCompileMode())
        {
            if (!nocomm)
            {
                res << "# " << "\n";
                res << "# Rule " << rl << "\n";
                res << "# " << "\n";
            }
            if (useNftablesAtomic(compiler->getCachedFwOpt()))
                res << "# Rule " << rl << "\n";
            else
                res << "echo " << _quote(string("Rule ")+rl) << "\n";
            res << "# " << "\n";
        }

/* do not put comment in the script if it is intended for linksys */
        if (!nocomm || compiler->inSingleRuleCompileMode())
        {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
            QStringList comm = QString(rule->getComment().c_str()).split("\n", Qt::SkipEmptyParts);
#else
            QStringList comm = QString(rule->getComment().c_str()).split("\n", Qt::SkipEmptyParts);
#endif
            foreach(QString line, comm)
            {
                res << "# " << line.toStdString() << "\n";
            }
            //res << "# " << "\n";

            string err = compiler->getErrorsForRule(rule, "# ");
            if (!err.empty()) res << err << "\n";
        }
    }

    current_rule_label = rl;

//    string err = rule->getCompilerMessage();
//    if (!err.empty()) res << "# " << err << "\n";

    return res.str();
}




/**
 *-----------------------------------------------------------------------
 */
string PolicyCompiler_nft::PrintRule::_printChain(PolicyRule *rule)
{
    string s = rule->getStr("ipt_chain");
    if (s.empty()) s = "UNKNOWN";
    // check chain name length per bug report #2507239
    if (s.length() > 30)
    {
        ostringstream str;
        str << "Chain name '" << s << "' ";
        str << "is longer than 30 characters. Rule " << rule->getLabel();
        compiler->abort(rule, str.str());
    }
    s= s + " ";
    return s;
}

string PolicyCompiler_nft::PrintRule::_printModules(PolicyRule *rule)
{
    std::ostringstream ostr;

    string target=rule->getStr("ipt_target");
    if (target.empty()) target="UNKNOWN";

    FWOptions *ruleopt =rule->getOptionsObject();
    int lim = 0;

/*
 * Here is what do we do with limits:
 *
 * Limit set globally in 'Firewall' tab of the firewall dialog 
 * applies only to logging
 *
 * Limit set in the rule options dialog applies only to this 
 * rule's target.
 * 
 *    this is so as of 1.0.11 ( 28/06/03 )  --vk
 */
    if (target=="LOG")
    {
        FWOptions *compopt=compiler->getCachedFwOpt();
        if ((lim=compopt->getInt("limit_value"))>0)
        {
            ostr << " limit rate " << lim;

            string ls=compopt->getStr("limit_suffix");
            if (!ls.empty()) ostr << ls;

            int lb=compopt->getInt("limit_burst");
            if (lb>0) ostr << " burst " << lb;
        }
    } else {
        if (ruleopt!=nullptr && (lim=ruleopt->getInt("limit_value"))>0)
        {
            if (ruleopt->getBool("limit_value_not"))
                ostr << " limit rate over " << lim;
            else
                ostr << " limit rate " << lim;

            string ls=ruleopt->getStr("limit_suffix");
            if (!ls.empty()) ostr << ls;

            int lb=ruleopt->getInt("limit_burst");
            if (lb>0) ostr << " burst " << lb;
        }
    }

    if (ruleopt!=nullptr && (lim=ruleopt->getInt("connlimit_value"))>0)
    {
        if (ruleopt->getBool("connlimit_above_not"))
            ostr << " ct count " << lim;
        else
            ostr << " ct count over " << lim;
    }

    if (ruleopt!=nullptr && (lim=ruleopt->getInt("hashlimit_value"))>0)
    {
        // iptables hashlimit has independent buckets per selected key. A
        // global nft 'limit rate' is only equivalent if no mode was chosen.
        string mode = ruleopt->getStr("hashlimit_mode");
        if (mode.empty())
        {
            const char *legacy_modes[] = {"srcip", "dstip", "srcport", "dstport"};
            for (const char *part : legacy_modes)
                if (ruleopt->getBool(string("hashlimit_mode_") + part))
                {
                    if (!mode.empty()) mode += ",";
                    mode += part;
                }
        }

        string suffix = ruleopt->getStr("hashlimit_suffix");
        if (suffix.empty()) suffix = "/second";
        if (suffix == "/sec") suffix = "/second";
        else if (suffix == "/min") suffix = "/minute";
        else if (suffix == "/hour") suffix = "/hour";
        else if (suffix == "/day") suffix = "/day";
        else if (suffix != "/second" && suffix != "/minute")
            compiler->abort(rule, "Unsupported native nftables hashlimit interval: " + suffix);

        string rate = "limit rate ";
        // Mirror the legacy --hashlimit direction, which tests traffic
        // within the specified rate. The rule action decides what follows.
        rate += std::to_string(lim) + suffix;
        int burst = ruleopt->getInt("hashlimit_burst");
        if (burst > 0) rate += " burst " + std::to_string(burst) + " packets";

        if (mode.empty())
        {
            ostr << " " << rate;
        } else
        {
            PolicyCompiler_nft *nft_comp =
                dynamic_cast<PolicyCompiler_nft*>(compiler);
            string selectors;
            string key_types;
            std::set<string> seen;
            std::istringstream parts(mode);
            string part;
            string transport;
            while (std::getline(parts, part, ','))
            {
                string expr;
                string type;
                if (part == "srcip")
                {
                    expr = nft_comp->ipv6 ? "ip6 saddr" : "ip saddr";
                    type = nft_comp->ipv6 ? "ipv6_addr" : "ipv4_addr";
                }
                else if (part == "dstip")
                {
                    expr = nft_comp->ipv6 ? "ip6 daddr" : "ip daddr";
                    type = nft_comp->ipv6 ? "ipv6_addr" : "ipv4_addr";
                }
                else if (part == "srcport" || part == "dstport")
                {
                    // Raw 'th sport/dport' is not a suitable typed key for
                    // nftables concatenated meters. Use the same transport
                    // protocol as the compiled FWB service match.
                    if (transport.empty())
                    {
                        Service *srv = compiler->getFirstSrv(rule);
                        if (srv == nullptr || (!TCPService::isA(srv) && !UDPService::isA(srv)))
                            compiler->abort(rule,
                                "Native nftables port-key hashlimit needs a TCP or UDP service");
                        transport = TCPService::isA(srv) ? "tcp" : "udp";
                    }
                    expr = transport + (part == "srcport" ? " sport" : " dport");
                    type = "inet_service";
                }
                else compiler->abort(rule, "Unsupported native nftables hashlimit mode: " + part);
                if (!seen.insert(part).second)
                    compiler->abort(rule, "Duplicate native nftables hashlimit mode: " + part);
                if (!selectors.empty())
                {
                    selectors += " . ";
                    key_types += " . ";
                }
                selectors += expr;
                key_types += type;
            }
            if (selectors.empty() || (!mode.empty() && mode.back() == ','))
                compiler->abort(rule, "Invalid native nftables hashlimit mode");

            string name = ruleopt->getStr("hashlimit_name");
            if (name.empty()) name = "htable_rule_" + std::to_string(rule->getPosition());
            if (name.size() > 45 || name.empty() ||
                !((name[0] >= 'a' && name[0] <= 'z') ||
                  (name[0] >= 'A' && name[0] <= 'Z') || name[0] == '_'))
                compiler->abort(rule, "Invalid native nftables hashlimit name");
            for (char c : name)
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_'))
                    compiler->abort(rule, "Invalid native nftables hashlimit name");

            // Unlike iptables, nft meters cannot honor the old hash bucket
            // sizing / GC intervals. Refuse rather than silently changing
            // explicitly configured behavior.
            for (const char *oldopt : {"hashlimit_size", "hashlimit_max", "hashlimit_gcinterval"})
                if (ruleopt->getInt(oldopt) > 0)
                    compiler->abort(rule, string("Unsupported native nftables hashlimit option: ") + oldopt);

            // A named dynamic set is declared exactly once per family/table,
            // then shared by every rule (including INPUT and FORWARD) with
            // the same FWB hashlimit name. Implicit `meter` declarations in
            // two rule statements can conflict inside one nft transaction.
            const string set_name = "fwb_" + name;
            const string table = nft_utils::managedTableName(nft_comp->my_table);
            const string family = nft_utils::familyName(nft_comp->ipv6);
            const int expiry = ruleopt->getInt("hashlimit_expire");
            const string config = selectors + ":" + key_types + ":" + std::to_string(expiry) + ":" + rate;
            const string marker = "__fwb_nft_meter:" + table + ":" + set_name + ":";
            const string tracking_key = marker + config;
            auto *tracking = nft_comp->minus_n_commands;
            if (tracking == nullptr)
                compiler->abort(rule, "Native nftables meter declaration tracking is unavailable");
            for (auto it = tracking->lower_bound(marker);
                 it != tracking->end() && it->first.compare(0, marker.size(), marker) == 0;
                 ++it)
            {
                if (it->first != tracking_key)
                    compiler->abort(rule,
                        "Conflicting native nftables hashlimit settings for name: " + name);
            }
            if (tracking->count(tracking_key) == 0)
            {
                const bool atomic = useNftablesAtomic(compiler->getCachedFwOpt());
                std::ostringstream def;
                def << nft_utils::commandPrefix(atomic) << "add set " << family << " "
                    << table << " " << set_name << " { type " << key_types
                    << "; size 65535; flags dynamic";
                if (expiry > 0)
                    def << ",timeout; timeout " << expiry << "ms";
                def << "; }\n";
                // Register the declaration with the driver.  Emitting it
                // through printRunTimeWrappers() can drop the declaration
                // while retaining the rule's update @set reference.
                // The driver emits each registered definition before the
                // rules, after the managed nftables table is created.
                (*tracking)["__fwb_nft_setdef:" + def.str()] = true;
                (*tracking)[tracking_key] = true;
            }
            ostr << " update @" << set_name << " { " << selectors << " " << rate << " }";
        }
    }

    return ostr.str();
}


string PolicyCompiler_nft::PrintRule::_printTarget(PolicyRule *rule)
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    std::ostringstream ostr;

    string target=rule->getStr("ipt_target");
    if (target.empty()) target="UNKNOWN";

    FWOptions *ruleopt =rule->getOptionsObject();

    if (rule->getTagging())
    {
        ostr << " " << nft_utils::markSetExpression(rule->getTagValue());
        return ostr.str();
    }

    if (rule->getClassification())
    {
        ostr << " meta priority set " << ruleopt->getStr("classify_str");
        return ostr.str();
    }

    if (rule->getRouting())
    {
        string out_iface = ruleopt->getStr("ipt_oif");
        if (!out_iface.empty())
            ostr << " fwd to " << out_iface;
        else
            ostr << " accept";
        return ostr.str();
    }

    if (target==".CUSTOM")
    {
        ostr << " " << ruleopt->getStr("custom_str");
        return ostr.str();
    }

    if (target==".CONTINUE") // not a real target !
        return " continue";


    if (compiler->fw->getStr("host_OS")=="linux317" &&
         compiler->getCachedFwOpt()->getBool("use_ULOG") &&
         target=="LOG") target="NFLOG";

    // there is no ULOG for ip6tables yet
    if (!ipt_comp->ipv6 && compiler->getCachedFwOpt()->getBool("use_ULOG") &&
         target=="LOG") target="ULOG";

    if (target == "ACCEPT") return " accept";
    if (target == "DROP") return " drop";
    if (target == "REJECT") return " " + _printActionOnReject(rule);
    if (target == "LOG" || target=="ULOG" || target=="NFLOG")
        return " log" + _printLogParameters(rule);
    if (target == "QUEUE") return " queue";
    if (target == "RETURN") return " return";

    // splitIfTagAndConnmark generates --save-mark in a separate
    // policy rule. Never turn this iptables target into a nft jump.
    if (target == "CONNMARK")
    {
        try
        {
            return " " + nft_utils::connmarkActionExpression(
                ruleopt->getStr("CONNMARK_arg"));
        }
        catch (const std::invalid_argument &e)
        {
            compiler->abort(rule, string("Invalid native nftables CONNMARK action: ") + e.what());
            return "";
        }
    }

    return " jump " + target;
}

string PolicyCompiler_nft::PrintRule::_printMultiport(PolicyRule *rule)
{
    return printConcatenatedSet(rule);
}

string PolicyCompiler_nft::PrintRule::_printDirectionAndInterface(PolicyRule *rule)
{
    QStringList res;

    if (rule->getStr(".iface") == "nil") return "";

    RuleElementItf *itfrel = rule->getItf();

    QString iface_name;
    FWObject *rule_iface_obj = nullptr;

    if ( ! itfrel->isAny())
    {
        rule_iface_obj = FWObjectReference::getObject(itfrel->front());
        iface_name = rule_iface_obj->getName().c_str();
        // Existing FWB objects can carry iptables-style prefix wildcards
        // (eth+ or bare +). Translate to nftables syntax before checking
        // whether this denotes 'any interface'.
        if (iface_name.endsWith("+"))
        {
            iface_name.chop(1);
            iface_name += "*";
        }
        // A bare '*' must not be emitted as an interface match.
        if (iface_name == "*")
        {
            if (itfrel->getNeg() || itfrel->getBool("single_object_negation"))
                compiler->abort(rule, "Negated any-interface match is not supported by native nftables");
            return "";
        }
 
        string iface_literal = "\"" + iface_name.toStdString() + "\"";
        if (rule->getDirection()==PolicyRule::Inbound)
            res << _printSingleOptionWithNegation(
                "iifname", itfrel, iface_literal).c_str();

        if (rule->getDirection()==PolicyRule::Outbound)
            res << _printSingleOptionWithNegation(
                "oifname", itfrel, iface_literal).c_str();

        res << "";
    }

    return res.join(" ").toStdString();
}

string PolicyCompiler_nft::PrintRule::_printActionOnReject(PolicyRule *rule)
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);

#ifndef NDEBUG
    Service *srv = compiler->getFirstSrv(rule);
    assert(srv);
#endif
    return ipt_comp->getRejectExpression(rule);
}

string PolicyCompiler_nft::PrintRule::_printGlobalLogParameters()
{
    return _printLogParameters(nullptr);
}

string PolicyCompiler_nft::PrintRule::_printLogPrefix(const string &rule_num,
						      const string &action,
						      const string &interf,
						      const string &chain,
                                                      const string &ruleset,
						      const string& ,
						      const string &prefix)
{
    string s = prefix;

/* deal with our logging macros:
 * %N - rule number  ('2', or '2/3' for rule in a branch)
 * %A - action
 * %I - interface name
 * %C - chain name
 * %R - ruleset name
 */
    string::size_type n;
    if ((n=s.find("%N"))!=string::npos ) 
    {
      s.replace(n, 2, rule_num);
    }
    if ((n=s.find("%A"))!=string::npos ) 
    {
      s.replace(n, 2, action);
    }
    if ((n=s.find("%I"))!=string::npos ) 
    {
      s.replace(n, 2, interf);
    }
    if ((n=s.find("%C"))!=string::npos ) 
    {
      s.replace(n, 2, chain);
    }
    if ((n=s.find("%R"))!=string::npos ) 
    {
      s.replace(n, 2, ruleset);
    }

    if (s.length()>29)
    {
        compiler->warning(
                "Log prefix has been truncated to 29 characters"); 
        s=s.substr(0,29);
    }

    return _quote( s );
}

string PolicyCompiler_nft::PrintRule::_printLogPrefix(PolicyRule *rule,
                                                      const string &prefix)
{
    FWObject *ruleset = rule->getParent();

    QString action = QString(rule->getStr("stored_action").c_str()).toUpper();

    RuleElementItf *itf_re = rule->getItf(); assert(itf_re!=nullptr);
    FWObject *rule_iface = FWObjectReference::getObject(itf_re->front());
    string rule_iface_name =  rule_iface->getName();

    if (rule_iface_name=="")     rule_iface_name = "global";
    if (rule_iface_name=="Any")  rule_iface_name = "global";

    std::ostringstream s1;
    int pos = rule->getPosition();
    // parent_rule_num is set by processor "Branching" for branch rules
    string ppos = rule->getStr("parent_rule_num");

    if (ppos != "")
        s1 << ppos << "/";
    s1 << pos;

    return _printLogPrefix(s1.str(),
                           action.toStdString(),
                           rule_iface_name,
                           rule->getStr("ipt_chain"),
                           ruleset->getName(),
                           rule->getLabel(),
                           prefix);
}

string PolicyCompiler_nft::PrintRule::_printLogParameters(PolicyRule *rule)
{
    std::ostringstream str;
    FWOptions *ruleopt = (rule!=nullptr) ? 
        rule->getOptionsObject() : compiler->getCachedFwOpt();

    string group = ruleopt->getStr("nflog_group");
    if (group.empty()) group = compiler->getCachedFwOpt()->getStr("ulog_nlgroup");
    if (!group.empty())
        str << " group " << group;

    string prefix = ruleopt->getStr("log_prefix");
    if (prefix.empty()) prefix = compiler->getCachedFwOpt()->getStr("log_prefix");
    if (!prefix.empty())
        str << " prefix " << _printLogPrefix(rule, prefix);

    return str.str();
}

string PolicyCompiler_nft::PrintRule::_printLimit(libfwbuilder::PolicyRule *rule)
{
    std::ostringstream str;
    string s;
    int    l, lb;
    FWOptions *ruleopt =rule->getOptionsObject();
    FWOptions *compopt =compiler->getCachedFwOpt();

    if ( (ruleopt!=nullptr && (l=ruleopt->getInt("limit_value"))>0) ||
         (l=compopt->getInt("limit_value"))>0 )
    {
        str << " limit rate " << l;

        if (ruleopt!=nullptr) s=ruleopt->getStr("limit_suffix");
        if (s.empty()) 	   s=compopt->getStr("limit_suffix");
        if (!s.empty()) str << s;

        lb=-1;
        if (ruleopt!=nullptr) lb=ruleopt->getInt("limit_burst");
        if (lb<0)          lb=compopt->getInt("limit_burst");
        if (lb>0)          str << " burst " << lb;
    }

    return str.str();
}

string PolicyCompiler_nft::PrintRule::_printProtocol(Service *srv)
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    string s;
    // CustomService returns protocol name starting with v3.0.4
    // However CustomService can return protocol name "any", which we should
    // just skip.
    if (CustomService::isA(srv))
    {
        // check if the code string for this custom service already includes
        // "-p proto" fragment
        string code = CustomService::cast(srv)->getCodeForPlatform(
            compiler->myPlatformName());
        std::size_t minus_p = code.find("-p ");
        if (minus_p != string::npos) return "";
        string pn = srv->getProtocolName();
        if (pn == "any") return "";
    }

    if (!srv->isAny() && !TagService::isA(srv) && !UserService::isA(srv))
    {
        string pn = srv->getProtocolName();
        if (pn=="ip" || pn=="any") return "";

        if (ipt_comp->ipv6)
        {
            if (ICMPService::isA(srv))
            {
                compiler->abort(
                    "Can not use ICMPService in ipv6 rule; "
                    "use ICMP6Service object instead");
            }

            if (ICMP6Service::isA(srv))
            {
                s = "meta l4proto icmpv6 ";
            } else
            {
                s = "meta l4proto " + pn + " ";
            }
        } else
        {
            if (ICMP6Service::isA(srv))
            {
                compiler->abort(
                        "Can not use ICMP6Service in ipv4 rule; "
                        "use ICMPService object instead");
            }

            if (ICMPService::isA(srv))
            {
                s = "ip protocol icmp ";
            } else
            {
                s = "ip protocol " + pn + " ";
            }
        }
    }
    return s;
}

string PolicyCompiler_nft::PrintRule::_printPorts(int rs,int re)
{
    std::ostringstream  str;

    compiler->normalizePortRange(rs,re);

    if (rs>0 || re>0) {
        if (rs==re)  str << rs;
        else if (rs==0 && re!=0)      str << "0-" << re;
        else
            str << rs << "-" << re;
    }
    return str.str();
}

string PolicyCompiler_nft::PrintRule::_printSrcPorts(Service *srv)
{
    std::ostringstream  str;
    if (TCPService::isA(srv) || UDPService::isA(srv)) 
    {
	int rs = TCPUDPService::cast(srv)->getSrcRangeStart();
	int re = TCPUDPService::cast(srv)->getSrcRangeEnd();
	str << _printPorts(rs,re);
    }
    return str.str();
}

string PolicyCompiler_nft::PrintRule::_printDstPorts(Service *srv)
{
    std::ostringstream  str;
    if (TCPService::isA(srv) || UDPService::isA(srv)) 
    {
	int rs = TCPUDPService::cast(srv)->getDstRangeStart();
	int re = TCPUDPService::cast(srv)->getDstRangeEnd();
	str << _printPorts(rs,re);
    }
    return str.str();
}

string PolicyCompiler_nft::PrintRule::_printICMP(ICMPService *srv)
{
    return nft_utils::icmpMatchExpression(srv->getInt("type"),
                                          srv->getInt("code"),
                                          ICMP6Service::isA(srv));
}

string PolicyCompiler_nft::PrintRule::_printIP(IPService *srv, PolicyRule *rule)
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    std::ostringstream str;

    if (srv->getBool("fragm") || srv->getBool("short_fragm"))
        str << " " << nft_utils::fragmentMatchExpression(ipt_comp->ipv6);

    const string tos = srv->getTOSCode();
    const string dscp = srv->getDSCPCode();
    if (!tos.empty())
    {
        // The complete IPv4 TOS octet includes ECN. DSCP-only matching
        // is NOT equivalent. Refuse unsupported IPv6 instead of widening.
        try
        {
            str << " " << nft_utils::tosMatchExpression(tos, ipt_comp->ipv6);
        }
        catch (const std::invalid_argument &e)
        {
            compiler->abort(rule, string("Invalid native nftables TOS match: ") + e.what());
        }
    }
    if (!dscp.empty())
    {
        try
        {
            str << " " << nft_utils::dscpMatchExpression(dscp, ipt_comp->ipv6);
        }
        catch (const std::invalid_argument &e)
        {
            compiler->abort(rule, string("Invalid native nftables DSCP match: ") + e.what());
        }
    }
    if (srv->hasIpOptions())
    {
        if (ipt_comp->ipv6)
            compiler->abort(rule, "IPv4 IP options are not supported for IPv6");

        // The legacy 'any_opt' flag matches any non-minimal IPv4 header.
        // IHL is counted in 32-bit words; 5 denotes an option-free header.
        if (srv->getBool("any_opt"))
            str << " ip hdrlength > 5";
        else
        {
            // These flags are combined with AND, as with ipv4options
            // --flags without --any. nft has no named timestamp option.
            if (srv->getBool("ts"))
                compiler->abort(rule, "Native nftables IPv4 timestamp option matching is not supported");
            bool emitted = false;
            if (srv->getBool("lsrr"))
            { str << " ip option lsrr exists"; emitted = true; }
            if (srv->getBool("ssrr"))
            { str << " ip option ssrr exists"; emitted = true; }
            if (srv->getBool("rr"))
            { str << " ip option rr exists"; emitted = true; }
            if (srv->getBool("rtralt"))
            { str << " ip option ra exists"; emitted = true; }
            if (!emitted)
                compiler->abort(rule, "Unsupported native nftables IPv4 options match");
        }
    }
    // Ordinary FWB service negation (Srv neg=True) is lowered earlier by
    // SrvNegation into a jump, a positive service match with return, and
    // a terminal action.  A per-object `not` prefix cannot express the
    // complement of compound matches and must never reach this printer.
    // Reject even an otherwise empty match, which would silently widen it.
    if (rule->getSrv()->getBool("single_object_negation"))
        compiler->abort(rule, "Negated native nftables IP service match is not yet supported");

    return str.str();
}

string PolicyCompiler_nft::PrintRule::_printTCPFlags(libfwbuilder::TCPService *srv)
{
    if (!srv->inspectFlags()) return "";

    std::set<TCPService::TCPFlag> masks = srv->getAllTCPFlagMasks();
    std::set<TCPService::TCPFlag> flags = srv->getAllTCPFlags();

    std::ostringstream mask_str;
    std::ostringstream comp_str;

    bool first = true;
    for (const auto &flag : masks)
    {
        if (!first) mask_str << ",";
        mask_str << nftTcpFlagName(flag);
        first = false;
    }

    first = true;
    for (const auto &flag : flags)
    {
        if (!first) comp_str << ",";
        comp_str << nftTcpFlagName(flag);
        first = false;
    }

    return nft_utils::tcpFlagsExpression(mask_str.str(), comp_str.str());
}

/*
 * we made sure that all services in rel  represent the same protocol
 */
string PolicyCompiler_nft::PrintRule::_printSrcService(RuleElementSrv  *rel)
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    std::ostringstream  ostr;
    (void)ipt_comp;
/* I do not want to use rel->getFirst because it traverses the tree to
 * find the object. I'd rather use a cached copy in the compiler
 */
    FWObject *o=rel->front();
    if (o && FWReference::cast(o)!=nullptr) o=FWReference::cast(o)->getPointer();

    Service *srv= Service::cast(o);


    if (rel->size()==1)
    {
        if (TCPService::isA(srv) || UDPService::isA(srv))
        {
            string str = _printSrcPorts( srv );
            if (!str.empty())
            {
                string proto = TCPService::isA(srv) ? "tcp" : "udp";
                ostr << _printSingleOptionWithNegation(
                    proto + " sport", rel, str);
            }
        }
        if (TCPService::isA(srv))
        {
            string str=_printTCPFlags(TCPService::cast(srv));
            if (!str.empty())
                ostr << str << " ";
        }
        if (ICMPService::isA(srv) || ICMP6Service::isA(srv))
        {
            string str = _printICMP( ICMPService::cast(srv) );
            if (!str.empty())
                ostr << _printSingleObjectNegation(rel) << str << " ";
        }
        if (IPService::isA(srv))
        {
            string str = _printIP(IPService::cast(srv), PolicyRule::cast(rel->getParent()));
            if (! str.empty() )
                ostr  << _printSingleObjectNegation(rel) << str << " ";
        }
        if (CustomService::isA(srv))
        {
            ostr << _printSingleObjectNegation(rel) << " "
                 << CustomService::cast(srv)->getCodeForPlatform( compiler->myPlatformName() ) << " ";
        }
        if (TagService::isA(srv))
        {
            ostr << nft_utils::markMatchExpression(
                TagService::constcast(srv)->getCode(),
                rel->getBool("single_object_negation")) << " ";
        }
        if (UserService::isA(srv))
        {
            // nftables negates a UID equality with !=, not an infix "not".
            ostr << "meta skuid "
                 << (rel->getBool("single_object_negation") ? "!= " : "")
                 << UserService::cast(srv)->getUserId() << " ";
        }
    } else
    {
        if (UDPService::isA(srv) || TCPService::isA(srv))
        {
            string proto = TCPService::isA(srv) ? "tcp" : "udp";
            ostr << printPortSet(rel, proto, true);
        }
    }
    return ostr.str();
}

string PolicyCompiler_nft::PrintRule::_printDstService(RuleElementSrv  *rel)
{
    PolicyCompiler_nft *ipt_comp=dynamic_cast<PolicyCompiler_nft*>(compiler);
    std::ostringstream  ostr;
    FWObject *o=rel->front();
    if (o && FWReference::cast(o)!=nullptr) o=FWReference::cast(o)->getPointer();

    Service *srv= Service::cast(o);

    if (rel->size()==1)
    {
        if (UDPService::isA(srv) || TCPService::isA(srv))
        {
            string str=_printDstPorts( srv );
            if (! str.empty() )
            {
                string proto = TCPService::isA(srv) ? "tcp" : "udp";
                ostr << _printSingleOptionWithNegation(
                    proto + " dport", rel, str);
            }
        }
        if (TCPService::isA(srv))
        {
            string str=_printTCPFlags(TCPService::cast(srv));
            if (!str.empty())
                ostr << str << " ";
        }
        if (ICMPService::isA(srv) || ICMP6Service::isA(srv))
        {
            string str = _printICMP( ICMPService::cast(srv) );
            if (!str.empty())
                ostr << _printSingleObjectNegation(rel) << str << " ";
        }
        if (IPService::isA(srv))
        {
            string str = _printIP(IPService::cast(srv), PolicyRule::cast(rel->getParent()));
            if (! str.empty() )
                ostr  << _printSingleObjectNegation(rel) << str << " ";
        }
        if (CustomService::isA(srv))
        {
            ostr << _printSingleObjectNegation(rel) << " "
                 << CustomService::cast(srv)->getCodeForPlatform( compiler->myPlatformName() ) << " ";
        }
        if (TagService::isA(srv))
        {
            ostr << nft_utils::markMatchExpression(
                TagService::constcast(srv)->getCode(),
                rel->getBool("single_object_negation")) << " ";
        }
        if (UserService::isA(srv))
        {
            // nftables negates a UID equality with !=, not an infix "not".
            ostr << "meta skuid "
                 << (rel->getBool("single_object_negation") ? "!= " : "")
                 << UserService::cast(srv)->getUserId() << " ";
        }
    } else
    {
        if (UDPService::isA(srv) || TCPService::isA(srv))
        {
            string proto = TCPService::isA(srv) ? "tcp" : "udp";
            ostr << printPortSet(rel, proto, false);
        }
    }
    return ostr.str();
}

string PolicyCompiler_nft::PrintRule::_printSrcAddr(RuleElement *rel, Address  *o)
{
    PolicyCompiler_nft *ipt_comp=dynamic_cast<PolicyCompiler_nft*>(compiler);
    string res;
    if (rel->size() > 1 && ipt_comp->canUseNftSetForAddresses(rel))
        return printAddressSet(rel, "saddr");
    if (AddressRange::cast(o)!=nullptr)
    {
        AddressRange *ar = AddressRange::cast(o);
        const InetAddr &range_start = ar->getRangeStart();
        const InetAddr &range_end = ar->getRangeEnd();

        if (range_start != range_end)
        {
            res += _printSingleOptionWithNegation(
                ipt_comp->ipv6 ? "ip6 saddr" : "ip saddr",
                rel,
                range_start.toString() + "-" + range_end.toString());
        } else
            res += _printSingleOptionWithNegation(
                ipt_comp->ipv6 ? "ip6 saddr" : "ip saddr",
                rel,
                range_start.toString());

        return res;
    }

    MultiAddressRunTime *atrt = MultiAddressRunTime::cast(o);
    if (atrt!=nullptr && atrt->getSubstitutionTypeName()==AddressTable::TYPENAME &&
        ipt_comp->using_ipset)
    {
        return _printIpSetMatch(o, rel);
    }

    return _printSingleOptionWithNegation(
        ipt_comp->ipv6 ? "ip6 saddr" : "ip saddr", rel, _printAddr(o));
}

string PolicyCompiler_nft::PrintRule::_printDstAddr(RuleElement *rel, Address  *o)
{
    PolicyCompiler_nft *ipt_comp=dynamic_cast<PolicyCompiler_nft*>(compiler);
    string res;
    if (rel->size() > 1 && ipt_comp->canUseNftSetForAddresses(rel))
        return printAddressSet(rel, "daddr");
    if (AddressRange::cast(o)!=nullptr)
    {
        AddressRange *ar = AddressRange::cast(o);
        const InetAddr &range_start = ar->getRangeStart();
        const InetAddr &range_end = ar->getRangeEnd();
        if (range_start != range_end)
        {
            res += _printSingleOptionWithNegation(
                ipt_comp->ipv6 ? "ip6 daddr" : "ip daddr",
                rel,
                range_start.toString() + "-" + range_end.toString());
        } else
            res += _printSingleOptionWithNegation(
                ipt_comp->ipv6 ? "ip6 daddr" : "ip daddr",
                rel,
                range_start.toString());

        return res;
    }

    MultiAddressRunTime *atrt = MultiAddressRunTime::cast(o);
    if (atrt!=nullptr && atrt->getSubstitutionTypeName()==AddressTable::TYPENAME &&
        ipt_comp->using_ipset)
    {
        return _printIpSetMatch(o, rel);
    }

    return _printSingleOptionWithNegation(
        ipt_comp->ipv6 ? "ip6 daddr" : "ip daddr", rel, _printAddr(o));
}

string PolicyCompiler_nft::PrintRule::_printIpSetMatch(Address *o, RuleElement *rel)
{
    PolicyCompiler_nft *ipt_comp=dynamic_cast<PolicyCompiler_nft*>(compiler);
    string set_name =
        dynamic_cast<OSConfigurator_linux24*>(ipt_comp->osconfigurator)->normalizeSetName(o->getName());
    string direction = "daddr";
    if (RuleElementSrc::isA(rel)) direction = "saddr";
    if (RuleElementDst::isA(rel)) direction = "daddr";

    return nft_utils::setMatchExpression(
        ipt_comp->ipv6 ? "ip6" : "ip",
        direction,
        set_name,
        rel->getBool("single_object_negation")) + " ";
}

string PolicyCompiler_nft::PrintRule::_printAddr(Address  *o)
{
    PolicyCompiler_nft *ipt_comp=dynamic_cast<PolicyCompiler_nft*>(compiler);
    std::ostringstream  ostr;

    MultiAddressRunTime *atrt = MultiAddressRunTime::cast(o);
    if (atrt!=nullptr)
    {
        if (atrt->getSubstitutionTypeName()==AddressTable::TYPENAME)
        {
            ostr << "$" << ipt_comp->getAddressTableVarName(atrt) << " ";
            return ostr.str();
        }

        if (atrt->getSubstitutionTypeName()==DNSName::TYPENAME)
        {
            return atrt->getSourceName();
        }

        if (atrt->getSubstitutionTypeName()==AttachedNetworks::TYPENAME)
        {
            ostr << "$i_" << atrt->getSourceName() << "_network";
            return ostr.str();
        }


        // at this time we only support two types of MultiAddress
        // objects: AddressTable and DNSName. Both should be converted
        // to MultiAddressRunTime at this point. If we get some other
        // kind of MultiAddressRunTime object, we do not know what to do
        // with it so we stop.
        assert(atrt==nullptr);
    }

    if (Interface::cast(o)!=nullptr)
    {
        Interface *iface=Interface::cast(o);
        if (iface->isDyn())
            ostr << "$" << ipt_comp->getInterfaceVarName(iface, ipt_comp->ipv6)
                 << " ";
        return ostr.str();
    }

    const InetAddr *addr = o->getAddressPtr();
    const InetAddr *mask = o->getNetmaskPtr();

    if (addr==nullptr)
    {
        compiler->warning(
            string("Empty inet address in object ") +
            o->getName() + "(" +
            FWObjectDatabase::getStringId(o->getId())
            + ")");
        return ostr.str();
    }

    // Note that mask can be nullptr, for example if o is AddressRange.
    if (addr->isAny() && (mask==nullptr || mask->isAny()))
    {
        ostr << "0/0 ";
    } else 
    {
        ostr << addr->toString();

        if (Interface::cast(o)==nullptr &&
            Address::cast(o)->dimension() > 1 &&
            !mask->isHostMask())
        {
            ostr << "/" << mask->getLength();
        }
        ostr << " ";
    }
    return ostr.str();
}


string PolicyCompiler_nft::PrintRule::_printTimeInterval(PolicyRule *r)
{
    RuleElementInterval* ri=r->getWhen();
    if (ri==nullptr || ri->isAny()) return "";

    int smin, shour, sday, smonth, syear, sdayofweek;
    int emin, ehour, eday, emonth, eyear, edayofweek;
    string days_of_week;

    Interval *interval = compiler->getFirstWhen(r);
    assert(interval!=nullptr);

    interval->getStartTime( &smin, &shour, &sday, &smonth, &syear, &sdayofweek);
    interval->getEndTime(   &emin, &ehour, &eday, &emonth, &eyear, &edayofweek);
    days_of_week = interval->getDaysOfWeek();

    if (shour<0) shour=0;
    if (smin<0)  smin=0;

    if (ehour<0) ehour=23;
    if (emin<0)  emin=59;

    std::ostringstream start;
    std::ostringstream stop;

    start << setw(2) << setfill('0') << shour << ":" << setw(2) << setfill('0') << smin;
    stop << setw(2) << setfill('0') << ehour << ":" << setw(2) << setfill('0') << emin;

    // Normalize the all-week selection to no weekday condition. Other
    // values are numeric 0..7 as stored in the FWB interval object.
    const string days = (days_of_week == "0,1,2,3,4,5,6")
        ? string() : days_of_week;
    try
    {
        return nft_utils::timeMatchExpression(
            start.str(), stop.str(), days,
            compiler->getCachedFwOpt()->getBool("use_kerneltz"));
    }
    catch (const std::invalid_argument &e)
    {
        compiler->abort(r, string("Invalid native nftables time interval: ") + e.what());
        return "";
    }
}

PolicyCompiler_nft::PrintRule::PrintRule(const std::string &name) :
    PolicyRuleProcessor(name) 
{ 
    init = true; 
    print_once_on_top = true;
    resetSetTracking();
    // use delayed initialization for ipt_comp->minus_n_commands
    // because it requires pointer to the compiler which has not been
    // initialized yet when this constructor is executed.
    minus_n_tracker_initialized = false;
}

/*
 * Initialize some internal variables. Need to do this in a separate
 * method because pointer to the compiler object is set by
 * RuleProcessor::setContext and is not available in constructor.
 */
void PolicyCompiler_nft::PrintRule::initialize()
{
    // retrieve and save version for _printSingleOptionWithNegation and others
    version = compiler->fw->getStr("version");
}

bool  PolicyCompiler_nft::PrintRule::processNext()
{
    PolicyCompiler_nft *ipt_comp=dynamic_cast<PolicyCompiler_nft*>(compiler);
    PolicyRule         *rule    =getNext(); 
    if (rule==nullptr) return false;

    string chain = rule->getStr("ipt_chain");
    if (ipt_comp->chain_usage_counter[chain] > 0)
    {
        tmp_queue.push_back(rule);

        compiler->output << _printRuleLabel(rule);
        compiler->output << _createChain(rule->getStr("ipt_chain"));

        string target = rule->getStr("ipt_target");
        if (target[0] != '.') compiler->output << _createChain(target);

        compiler->output 
            << dynamic_cast<OSConfigurator_linux24*>(
                compiler->osconfigurator)->printRunTimeWrappers(
                    rule, PolicyRuleToString(rule), ipt_comp->ipv6);
    }
    return true;
}

string PolicyCompiler_nft::PrintRule::PolicyRuleToString(PolicyRule *rule)
{
    FWOptions *ruleopt = rule->getOptionsObject();
    FWObject    *ref;

    if (rule->getBool("nft_verdict_map"))
    {
        std::ostringstream command_line;
        command_line << _startRuleLine();
        command_line << _printChain(rule);
        command_line << _printDirectionAndInterface(rule);
        command_line << " " << rule->getStr("nft_vmap_expression") << " ";
        command_line << _endRuleLine();
        return command_line.str();
    }

    RuleElementSrc *srcrel=rule->getSrc();
    Address        *src=nullptr;
    if (!srcrel->isAny())
    {
        ref=srcrel->front();
        src=Address::cast(FWReference::cast(ref)->getPointer());
        if(src==nullptr)
            compiler->abort(rule, string("Broken SRC in ") + rule->getLabel());
    }

    RuleElementDst *dstrel=rule->getDst();
    Address        *dst=nullptr;
    if (!dstrel->isAny())
    {
        ref=dstrel->front();
        dst=Address::cast(FWReference::cast(ref)->getPointer());
        if(dst==nullptr)
            compiler->abort(rule, string("Broken DST in ") + rule->getLabel());
    }

    RuleElementSrv *srvrel=rule->getSrv();
    ref=srvrel->front();
    Service        *srv=Service::cast(FWReference::cast(ref)->getPointer());
    if(srv==nullptr)
        compiler->abort(rule, string("Broken SRV in ") + rule->getLabel());


    std::ostringstream  command_line;

    have_m_iprange = false;
    resetSetTracking();

    command_line << _startRuleLine();

    command_line << _printChain(rule);
    command_line << _printDirectionAndInterface(rule);
    command_line << _printProtocol(srv);
    command_line << _printMultiport(rule);

    if (src!=nullptr && !omit_src_addr_for_concat) 
    {
        if (physAddress::isA(src) || combinedAddress::isA(src))
        {
            string physaddress = "";

            if (physAddress::isA(src))
            {
                physaddress = physAddress::cast(src)->getPhysAddress();
                if (physaddress.empty())
                {
                    compiler->warning(
                        rule, 
                        "Empty MAC address in rule");
                    physaddress = "00:00:00:00:00:00";
                }
            }

            if (combinedAddress::isA(src))
                physaddress = combinedAddress::cast(src)->getPhysAddress();

/* physAddress component of combinedAddress can be empty.  For example
 * this happens when an object with both IP and MAC addresses is found
 * in "source" and rule is determined to go into OUTPUT chain. On the
 * other hand, if physAddress object has no MAC address, it is always
 * an error.
 */
            if (!physaddress.empty())
            {
                try
                {
                    command_line << " " << nft_utils::macSourceMatchExpression(
                        physaddress, srcrel->getBool("single_object_negation")) << " ";
                }
                catch (const std::invalid_argument &e)
                {
                    compiler->abort(rule, string("Invalid source MAC match: ") + e.what());
                }
            }

/*
 * fool-proof: this is last resort check for situation when user
 * created IPv4 object for the interface but left it with empty
 * address ( 0.0.0.0 ).
 *
 * note that combinedAddress inherits IPv4 and therefore
 * combinedAddress::hasInetAddress returns true;
 *
 */
            if (src->hasInetAddress() && !src->getAddressPtr()->isAny())
                command_line << _printSrcAddr(srcrel, src);

        } else
            command_line << _printSrcAddr(srcrel, src);

    }
    if (!omit_src_port_for_concat)
        command_line << _printSrcService(srvrel);

    if (dst!=nullptr && !omit_dst_addr_for_concat) 
	command_line << _printDstAddr(dstrel, dst);

    if (!omit_dst_port_for_concat)
        command_line << _printDstService(srvrel);

/* keeping state does not apply to deny/reject 
   however some rules need state check even if action is Deny


   autoupgrade transformation 2.1.11 -> 2.1.12 adds rule option
   'stateless=True' for rules with action NOT 'Accept', 'Tag' or
   'Route'. No need to check action here, just rely on this option
   and internal flag 'force_state_check'  (05/07/07 --vk)
*/
    if (!ruleopt->getBool("stateless") || rule->getBool("force_state_check") )
    {
        if (command_line.str().find("ct state", 0) == string::npos)
            command_line << " " << nft_utils::conntrackStateExpression("new", false) << " ";
    }

    command_line << _printTimeInterval(rule);

    command_line << _printModules(rule);
    command_line << _printTarget(rule);

    command_line << _endRuleLine();

//    command_line << "\n";

    return command_line.str();
}

string PolicyCompiler_nft::PrintRule::_declareTable()
{
    return "";
}

string PolicyCompiler_nft::PrintRule::_commit()
{
    return "";
}

string PolicyCompiler_nft::PrintRule::_clampTcpToMssRule()
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    ostringstream res;

    if ( compiler->getCachedFwOpt()->getBool("clamp_mss_to_mtu"))
    {
        bool ipforw;
        if (ipt_comp->ipv6)
        {
            string s = compiler->getCachedFwOpt()->getStr("linux24_ipv6_forward");
            ipforw = (s.empty() || s=="1" || s=="On" || s=="on");
            // bug #2477775: target TCPMSS is not available in ip6tables
            // before 1.4.0 In fact I am not sure of the minimal required
            // version. According to the netfilter git log, it was added in
            // 1.3.8
            if (XMLTools::version_compare(version, "1.3.8")<0)
            {
                if (ipforw)
                {
                    res << "target TCPMSS is not supported by ip6tables before v1.3.8";
                    compiler->warning(res.str());
                    return "# " + res.str() + "\n\n";
                } else return "";
            }
        } else
        {
            string s = compiler->getCachedFwOpt()->getStr("linux24_ip_forward");
            ipforw = (s.empty() || s=="1" || s=="On" || s=="on");
        }

        if (ipforw)
        {
            res << _startRuleLine()
                << "FORWARD tcp flags syn tcp option maxseg size set rt mtu"
                << _endRuleLine();
            res << "\n";
        }
    }
    return res.str();
}

string PolicyCompiler_nft::PrintRule::_printOptionalGlobalRules()
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    ostringstream res;
    bool isIPv6 = ipt_comp->ipv6;
    string state_module_option;

    string s = compiler->getCachedFwOpt()->getStr("linux24_ip_forward");
    bool ipforward= (s.empty() || s=="1" || s=="On" || s=="on");
    s = compiler->getCachedFwOpt()->getStr("linux24_ipv6_forward");
    bool ip6forward= (s.empty() || s=="1" || s=="On" || s=="on");
    bool ipforw = ((!ipt_comp->ipv6 && ipforward) ||
                   (ipt_comp->ipv6 && ip6forward));

    Configlet configlet(compiler->fw, "nftables", "nft_automatic_rules");
    configlet.removeComments();
    configlet.collapseEmptyStrings(true);

    configlet.setVariable("begin_rule", _startRuleLine().c_str());
    configlet.setVariable("addr_family", isIPv6 ? "ip6" : "ip");
    configlet.setVariable("end_rule", _endRuleLine().c_str());

    configlet.setVariable("ipforw", ipforw);
                              
    configlet.setVariable("accept_established", 
                          compiler->getCachedFwOpt()->getBool("accept_established") &&
                          ipt_comp->my_table=="filter");

    if (XMLTools::version_compare(version, "1.4.4")>=0)
        state_module_option = "conntrack --ctstate";
    else
        state_module_option = "state --state";

    configlet.setVariable("state_module_option", state_module_option.c_str());

    list<FWObject*> ll = compiler->fw->getByTypeDeep(Interface::TYPENAME);
    for (FWObject::iterator i=ll.begin(); i!=ll.end(); i++)
    {
        Interface *intf = Interface::cast( *i );
        if (intf->isManagement())
        {
            configlet.setVariable("management_interface", intf->getName().c_str());
            break;
        }
    }

    _printBackupSSHAccessRules(&configlet);

    configlet.setVariable(
        "drop_new_tcp_with_no_syn",
        ! compiler->getCachedFwOpt()->getBool("accept_new_tcp_with_no_syn")); 

    configlet.setVariable(
        "bridging_firewall",
        compiler->getCachedFwOpt()->getBool("bridging_fw"));

    configlet.setVariable(
        "add_rules_for_ipv6_neighbor_discovery",
        isIPv6 && 
        compiler->getCachedFwOpt()->getBool("add_rules_for_ipv6_neighbor_discovery")); 


    configlet.setVariable("drop_invalid",
                          compiler->getCachedFwOpt()->getBool("drop_invalid") &&
                          !compiler->getCachedFwOpt()->getBool("log_invalid"));

    configlet.setVariable("drop_invalid_and_log",
                          compiler->getCachedFwOpt()->getBool("drop_invalid") &&
                          compiler->getCachedFwOpt()->getBool("log_invalid"));

    configlet.setVariable("create_drop_invalid_chain",
                          _createChain("drop_invalid").c_str());


    if (compiler->getCachedFwOpt()->getBool("log_invalid") &&
        !isIPv6 &&
        compiler->getCachedFwOpt()->getBool("use_ULOG"))
    {  
        configlet.setVariable("use_ulog", 1);

        string s = compiler->getCachedFwOpt()->getStr("ulog_nlgroup");
        const bool custom_nlgroup = !s.empty();
        if (s.empty()) s = "0";
        configlet.setVariable("use_nlgroup", custom_nlgroup);
        configlet.setVariable("nlgroup", s.c_str());

        int r = compiler->getCachedFwOpt()->getInt("ulog_cprange");
        configlet.setVariable("use_cprange", r!=0);
        configlet.setVariable("cprange", r);

        r = compiler->getCachedFwOpt()->getInt("ulog_qthreshold");
        configlet.setVariable("use_qthreshold", r!=0);
        configlet.setVariable("qthreshold", r);

        std::ostringstream nflog_options;
        const int snaplen = compiler->getCachedFwOpt()->getInt("ulog_cprange");
        const int threshold = compiler->getCachedFwOpt()->getInt("ulog_qthreshold");
        if (snaplen > 0) nflog_options << " snaplen " << snaplen;
        if (threshold > 0) nflog_options << " queue-threshold " << threshold;
        configlet.setVariable("nflog_options", nflog_options.str().c_str());
    } else
        configlet.setVariable("not_use_ulog", 1);

    configlet.setVariable("invalid_match_log_prefix",
                          _printLogPrefix("-1",
                                          "DENY",
                                          "global",
                                          "drop_invalid",
                                          "Policy",
                                          "BLOCK INVALID",
                                          "INVALID state -- DENY ").c_str());

    return configlet.expand().toStdString();
}

void PolicyCompiler_nft::PrintRule::_printBackupSSHAccessRules(Configlet *conf)
{
    PolicyCompiler_nft *ipt_comp = dynamic_cast<PolicyCompiler_nft*>(compiler);
    bool isIPv6 = ipt_comp->ipv6;
    if ( compiler->getCachedFwOpt()->getBool("mgmt_ssh") &&
         ! compiler->getCachedFwOpt()->getStr("mgmt_addr").empty() )
    {
        string addr_str = compiler->getCachedFwOpt()->getStr("mgmt_addr");
        InetAddrMask *inet_addr = nullptr;
        bool addr_is_good = true;
        if (isIPv6)
        {
            // check if given address is ipv6
            try
            {
                inet_addr = new Inet6AddrMask(addr_str);
            } catch(const FWException &ex)  {
                // address does not parse as ipv6, skip this rule.
                addr_is_good = false;
                QString err("Backup ssh access rule could not be added "
                            "to IPv6 policy because specified address "
                            "'%1' is invalid");
                compiler->warning(err.arg(addr_str.c_str()).toStdString());
            }
        } else
        {
            // check if given address parses as ipv4
            try
            {
                inet_addr = new InetAddrMask(addr_str);
            } catch(const FWException &ex)  {
                // address does not parse
                addr_is_good = false;
                QString err("Backup ssh access rule could not be added "
                            "to IPv4 policy because specified address "
                            "'%1' is invalid");
                compiler->warning(err.arg(addr_str.c_str()).toStdString());
            }
        }
        if (addr_is_good)
        {
            conf->setVariable("begin_rule", _startRuleLine().c_str());
            conf->setVariable("end_rule", _endRuleLine().c_str());
            conf->setVariable("mgmt_access", 1);
            conf->setVariable("ssh_management_address",
                              inet_addr->toString().c_str());
            // The block action covers both families. Do not reuse an IPv4
            // management address in an IPv6 rule (or vice versa).
            conf->setVariable(isIPv6 ? "mgmt_access_ipv6" : "mgmt_access_ipv4", 1);
            conf->setVariable(isIPv6 ? "ssh_management_address_ipv6" :
                           "ssh_management_address_ipv4",
                              inet_addr->toString().c_str());
        }
    }
}

string PolicyCompiler_nft::PrintRule::_quote(const string &s)
{
    return "\"" + s + "\"";
}
