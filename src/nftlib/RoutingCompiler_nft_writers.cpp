/* 

                  Firewall Builder Routing add-on

                 Copyright (C) 2004 Compal GmbH, Germany

  Author:  Tidei Maurizio     <fwbuilder-routing at compal.de>
  Modified: Vadim Kurland     vadim@vk.crocodile.org

  Permission is hereby granted, free of charge, to any person
  obtaining a copy of this software and associated documentation files
  (the "Software"), to deal in the Software without restriction,
  including without limitation the rights to use, copy, modify, merge,
  publish, distribute, sublicense, and/or sell copies of the Software,
  and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.

*/

#include "RoutingCompiler_nft.h"
#include "Configlet.h"

#include "fwbuilder/RuleElement.h"
#include "fwbuilder/Routing.h"
#include "fwbuilder/FWReference.h"
#include "fwbuilder/AddressRange.h"
#include "fwbuilder/Cluster.h"
#include "fwbuilder/Group.h"
#include "fwbuilder/InetAddrMask.h"
#include "fwbuilder/RuleSet.h"
#include "fwbuilder/TagService.h"
#include "fwbuilder/Network.h"
#include "fwbuilder/FWObjectDatabase.h"
#include "fwbuilder/RuleElement.h"
#include "fwbuilder/Routing.h"
#include "fwbuilder/Interface.h"
#include "fwbuilder/IPv4.h"
#include "fwbuilder/IPv6.h"
#include "fwbuilder/Host.h"
#include "fwbuilder/Firewall.h"
#include "fwbuilder/FWOptions.h"
#include "fwbuilder/Resources.h"

#include <QString>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>

#include <assert.h>
#include <list>
#include <vector>
#include <string>

using namespace libfwbuilder;
using namespace fwcompiler;
using namespace std;



/**
 *-----------------------------------------------------------------------
 *                    Methods for printing
 */
string RoutingCompiler_nft::PrintRule::_printAddr(Address  *o)
{
    ostringstream  ostr;

    if (Interface::cast(o)!=nullptr)
    {
        Interface *iface=Interface::cast(o);
        if (iface->isDyn())
            ostr << "$interface_" << iface->getName() << " ";
        return ostr.str();
    }

    const InetAddr *addr;
    const InetAddr *mask;
    RoutingCompiler_nft *nft_compiler =
        static_cast<RoutingCompiler_nft*>(compiler);
    if (nft_compiler->compilingIPv6() &&
        (Host::cast(o) != nullptr || Interface::cast(o) != nullptr))
    {
        list<FWObject*> interfaces;
        if (Interface::cast(o) != nullptr)
            interfaces.push_back(o);
        else
            interfaces = o->getByTypeDeep(Interface::TYPENAME);
        addr = nullptr;
        mask = nullptr;
        for (list<FWObject*>::iterator it = interfaces.begin();
             it != interfaces.end(); ++it)
        {
            list<FWObject*> addresses = (*it)->getByType(IPv6::TYPENAME);
            if (addresses.empty()) continue;
            Address *selected = Address::cast(addresses.front());
            addr = selected->getAddressPtr();
            mask = selected->getNetmaskPtr();
            break;
        }
    }
    else
    {
        addr = o->getAddressPtr();
        mask = o->getNetmaskPtr();
    }

    if (addr==nullptr)
    {
        FWObject *obj=o;
/*
 * check if this is object of class Address. since we want to
 * distinguish between Host, Interface and Address, and both Host and
 * Interface are inherited from Address, we can't use cast. Use isA
 * instead
 */
        while (obj!=nullptr && 
               !Host::isA(obj) && 
               !Firewall::isA(obj)  && 
               !Network::isA(obj))  obj=obj->getParent();

        compiler->abort(
            "Problem with address or netmask in the object or "
            "one of its interfaces: '" + obj->getName() + "'");
    }


    bool unspecified_v6_prefix = false;
    if (addr->isV6() && mask->isV6())
    {
        const uint32_t *words =
            reinterpret_cast<const uint32_t *>(mask->getV6());
        unspecified_v6_prefix =
            words[0] == 0 && words[1] == 0 && words[2] == 0 && words[3] == 0 &&
            addr->toString() == "::";
    }
    // InetAddr::getLength() reports 128 for an all-zero IPv6 mask, so a
    // ::/0 network cannot be recognized from that length.
    if ((addr->isAny() && mask->isAny()) || unspecified_v6_prefix)
    {
        ostr << "default ";
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



RoutingCompiler_nft::PrintRule::PrintRule(const std::string &name) : RoutingRuleProcessor(name) 
{ 
    print_once_on_top=true;
}


bool RoutingCompiler_nft::PrintRule::processNext()
{
    RoutingRule *rule = getNext(); 
    if (rule==nullptr) return false;

    tmp_queue.push_back(rule);
    
    // Routing shell functions are emitted once by the driver, for both
    // address families. Printing them here would initialize them twice
    // and would delete routes this script does not own.
    
    // TODO: convert this into virtual function RoutingCompiler_nft::printComment()
    string rl = rule->getLabel();
    string comm = rule->getComment();
    string::size_type c1,c2;
    c1=0;
    
    if (!compiler->inSingleRuleCompileMode() && rl!=current_rule_label)
    {
        compiler->output << "# " << "\n";
        compiler->output << "# Rule " << rl << "\n";
        //compiler->output << "# " << rule->getRuleTypeAsString() << "\n";
        compiler->output << "# " << "\n";
        compiler->output << "echo \"Routing rule " << rl << "\"" << "\n";
        compiler->output << "# " << "\n";
    }
    
    if( rule->getRuleType() != RoutingRule::MultiPath )
    {
        if (!compiler->inSingleRuleCompileMode() && rl!=current_rule_label)
        {
            while ( (c2=comm.find('\n',c1))!=string::npos )
            {
                compiler->output << "# " << comm.substr(c1,c2-c1) << "\n";
                c1=c2+1;
            }
            compiler->output << "# " << comm.substr(c1) << "\n";
            compiler->output << "# " << "\n";

            string err = compiler->getErrorsForRule(rule, "# ");
            if (!err.empty()) compiler->output << err << "\n";

            current_rule_label = rl;
        }
        
//        string err = rule->getCompilerMessage();
//        if (!err.empty()) compiler->output << "# " << err << "\n";

        string  command_line = RoutingRuleToString(rule);
        compiler->output << command_line;
    
    } else
    {
        // the ecmp_id contains the table, the rule label and the metric. These are the properties the ecmp rules are distinguished
        string metric = rule->getMetricAsString();
        string ecmp_id = rule->getSortedDstIds() + "#" + metric;
                    
        if (rl!=current_rule_label)
        {
            compiler->output << "# Some sub rules belonging to an ECMP (Equal Cost Multi Path) rule were placed in the ECMP section below." << "\n";
            current_rule_label=rl;
        }
        
        map< string, string>& ecmp_rules_buffer =
            ((RoutingCompiler_nft*)compiler)->ecmp_rules_buffer;
        map< string, string>& ecmp_comments_buffer =
            ((RoutingCompiler_nft*)compiler)->ecmp_comments_buffer;

        map< string, string>::iterator ecmp_rules_buffer_it;
        ecmp_rules_buffer_it = ecmp_rules_buffer.find(ecmp_id);
        if( ecmp_rules_buffer_it == ecmp_rules_buffer.end() )
        {
            // ECMP Dst not seen so far. The shell prefix is added when
            // the completed nexthop list is activated.
            ecmp_comments_buffer[ecmp_id] = "#\n# Multipath Rule "
                " derived from the following routing rules:\n#\n";

            string spec = _printRDst(rule);
            while (!spec.empty() && spec[spec.size() - 1] == ' ')
                spec.erase(spec.size() - 1);
            if (rule->getMetricAsString() != "0")
                spec += " metric " + metric;
            ecmp_rules_buffer[ecmp_id] = spec;
        }
        
        ecmp_comments_buffer[ecmp_id] += "# Rule " + rl + "\n";
        
        while ( (c2=comm.find('\n',c1))!=string::npos )
        {
            ecmp_comments_buffer[ecmp_id] +=
                "#    " + comm.substr(c1,c2-c1) + "\n";
            c1=c2+1;
        }
        ecmp_comments_buffer[ecmp_id] += "#    " + comm.substr(c1) + "\n";
        
        // Collect the nexthop information for the multipath rules, indexed by the sorted dst ids
        string nexthop = string("nexthop ") + _printRGtw(rule) + _printRItf(rule);
        while (!nexthop.empty() && nexthop[nexthop.size() - 1] == ' ')
            nexthop.erase(nexthop.size() - 1);
        FWObject *onlink_obj = rule->getFirstByType(RoutingRuleOptions::TYPENAME);
        RoutingRuleOptions *onlink = RoutingRuleOptions::cast(onlink_obj);
        if (onlink && onlink->getBool("use_onlink_option"))
            nexthop += " onlink";
        ecmp_rules_buffer[ecmp_id] += " " + nexthop;
        
        
    }
    return true;
}


string RoutingCompiler_nft::PrintRule::RoutingRuleToString(RoutingRule *rule)
{
    FWObject    *ref;

    RuleElementRDst *dstrel=rule->getRDst();
    ref=dstrel->front();
    Address *dst=Address::cast(FWReference::cast(ref)->getPointer());
    if(dst==nullptr)
        compiler->abort(rule, "Broken DST");
        
    string spec = _printRDst(rule);
    while (!spec.empty() && spec[spec.size() - 1] == ' ')
        spec.erase(spec.size() - 1);
    if (rule->getMetricAsString() != "0")
        spec += " metric " + rule->getMetricAsString();
    string gateway = _printRGtw(rule);
    string interface_name = _printRItf(rule);
    while (!gateway.empty() && gateway[gateway.size() - 1] == ' ')
        gateway.erase(gateway.size() - 1);
    while (!interface_name.empty() && interface_name[interface_name.size() - 1] == ' ')
        interface_name.erase(interface_name.size() - 1);
    if (!gateway.empty()) spec += " " + gateway;
    if (!interface_name.empty()) spec += " " + interface_name;
    // Same opt-in as the iptables routing compiler. Absent option
    // leaves the historical command unchanged.
    FWObject *onlink_obj = rule->getFirstByType(RoutingRuleOptions::TYPENAME);
    RoutingRuleOptions *onlink = RoutingRuleOptions::cast(onlink_obj);
    if (onlink && onlink->getBool("use_onlink_option"))
        spec += " onlink";

    RoutingCompiler_nft *nft = static_cast<RoutingCompiler_nft*>(compiler);

    // no_fail still has to report the failure without rolling the
    // whole routing table back. The shared activation wrapper does
    // that rollback; no_fail only suppresses the fatal exit.
    FWObject *opt_dummy = rule->getFirstByType(RoutingRuleOptions::TYPENAME);
    RoutingRuleOptions *opt = opt_dummy ? RoutingRuleOptions::cast(opt_dummy) : 0;
    if (opt && opt->getBool("no_fail") && !compiler->inSingleRuleCompileMode())
    {
        return nft->routeAddPrefix() + spec +
            " || echo \"*** Warning: routing rule " +
            rule->getLabel() + " failed. ignored. ***\"\n";
    }
    return nft->activationCommand(spec, rule->getLabel());
}

string RoutingCompiler_nft::PrintRule::_printRGtw(RoutingRule *rule)
{
    FWObject    *ref;
    
    RuleElementRGtw *gtwrel = rule->getRGtw();
    ref = gtwrel->front();
    Address *gtw = Address::cast(FWReference::cast(ref)->getPointer());
    if(gtw==nullptr)
        compiler->abort(rule, "Broken GTW");
    
    string gateway = _printAddr(gtw);
    
    if( gateway != "default ") return "via " + gateway;
    else return "";
}
    
string RoutingCompiler_nft::PrintRule::_printRItf(RoutingRule *rule)
{
    FWObject    *ref;
    
    RuleElementRItf *itfrel=rule->getRItf();
    ref=itfrel->front();
    Interface *itf=Interface::cast(FWReference::cast(ref)->getPointer());
    
    if(itf != nullptr) return "dev " + itf->getName() + " ";
    else return "";
}

string RoutingCompiler_nft::PrintRule::_printRDst(RoutingRule *rule)
{
    FWObject    *ref;
    
    RuleElementRDst *dstrel=rule->getRDst();
    ref=dstrel->front();
    Address *dst=Address::cast(FWReference::cast(ref)->getPointer());
    if(dst==nullptr)
        compiler->abort(rule, "Broken DST");
    
    return _printAddr(dst);
}

/**
 * RoutingCompiler_nft::processIPRules
 *
 * Defined in RoutingCompiler_nft.cpp and RoutingCompiler_nft.h.
 */
std::string shellQuote(const std::string &value);
void noteRouteFamily(libfwbuilder::FWObject *object, bool &ipv4, bool &ipv6);

namespace {

void collectIPRuleObjects(libfwbuilder::FWObject *obj,
                          std::list<libfwbuilder::FWObject*> &out)
{
    using namespace libfwbuilder;
    if (obj == nullptr) return;
    if (obj->getId() == FWObjectDatabase::ANY_ADDRESS_ID) return;
    if (obj->getId() == FWObjectDatabase::ANY_SERVICE_ID) return;
    Group *grp = Group::cast(obj);
    if (grp)
    {
        for (FWObject::iterator it = grp->begin(); it != grp->end(); ++it)
        {
            if (FWReference::cast(*it) == nullptr) continue;
            collectIPRuleObjects(FWReference::getObject(*it), out);
        }
        return;
    }
    out.push_back(obj);
}

// Converts atomic address objects into ip rule selector strings.
// The objects come from collectIPRuleObjects (groups are already
// resolved). An empty list means "match everything": the selector is
// then simply omitted from the ip rule command. AddressRange objects
// are converted to the minimal set of prefixes, mirroring
// Compiler::_expandAddressRanges, but without creating synthetic
// objects.
void collectIPRuleSelectors(fwcompiler::Compiler *compiler,
                            libfwbuilder::Rule *rule,
                            const std::list<libfwbuilder::FWObject*> &objects,
                            std::list<std::string> &selectors)
{
    using namespace libfwbuilder;
    for (std::list<FWObject*>::const_iterator it = objects.begin();
         it != objects.end(); ++it)
    {
        FWObject *obj = *it;

        AddressRange *range = AddressRange::cast(obj);
        if (range)
        {
            std::vector<InetAddrMask> prefixes = convertAddressRange(
                range->getRangeStart(), range->getRangeEnd());
            if (prefixes.empty())
            {
                compiler->abort(rule,
                    "Address Range object '" + range->getName() +
                    "' can not be converted to set of addresses");
                continue;
            }
            for (std::vector<InetAddrMask>::iterator p = prefixes.begin();
                 p != prefixes.end(); ++p)
            {
                if (p->getAddressPtr() == nullptr ||
                    p->getNetmaskPtr() == nullptr) continue;
                std::ostringstream selector;
                selector << p->getAddressPtr()->toString();
                if (!p->getNetmaskPtr()->isHostMask())
                    selector << "/" << p->getNetmaskPtr()->getLength();
                selectors.push_back(selector.str());
            }
            continue;
        }

        Interface *iface = Interface::cast(obj);
        if (iface)
        {
            compiler->abort(rule,
                "Interface '" + iface->getName() +
                "' is not supported in the address fields of IP rule " +
                rule->getLabel() + "; use network or host objects");
            continue;
        }

        Address *address = Address::cast(obj);
        if (address == nullptr)
        {
            compiler->abort(rule,
                "IP rule " + rule->getLabel() +
                " uses object '" + obj->getName() +
                "' which is not an address");
            continue;
        }
        const InetAddr *addr = address->getAddressPtr();
        const InetAddr *mask = address->getNetmaskPtr();
        if (addr == nullptr || mask == nullptr)
        {
            compiler->abort(rule,
                "IP rule " + rule->getLabel() +
                " uses object '" + obj->getName() +
                "' which has no address");
            continue;
        }
        std::ostringstream selector;
        selector << addr->toString();
        if (address->dimension() > 1 && !mask->isHostMask())
            selector << "/" << mask->getLength();
        selectors.push_back(selector.str());
    }
}

// W4.3: a runtime variable name comes from the free-form
// IPRuleOptions and is interpolated into the generated shell script,
// so it must be a strict POSIX shell identifier: one leading letter
// or underscore, then letters, digits or underscores. Anything else
// (whitespace, quotes, shell metacharacters) is rejected.
bool isShellVarNameChar(char c, bool first)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_')
        return true;
    if (!first && c >= '0' && c <= '9') return true;
    return false;
}

bool isValidShellVarName(const std::string &name)
{
    if (name.empty()) return false;
    for (std::string::size_type i = 0; i < name.size(); ++i)
        if (!isShellVarNameChar(name[i], i == 0)) return false;
    return true;
}

// The variable may be typed with or without the leading '$' in the
// GUI; accept both and work with the bare name.
std::string stripShellVarPrefix(std::string name)
{
    if (!name.empty() && name[0] == '$') name.erase(0, 1);
    return name;
}

// The guard runs before any spec variable of the rule is expanded: an
// empty or IPv6-shaped value must fail the activation instead of
// producing a broken or silently overmatching ip rule (the shell
// drops the empty "from" word, so the rule would match everything).
void printRuntimeVarGuard(std::ostringstream &text,
                          const std::string &var_name,
                          const std::string &label)
{
    text << "case \"$" << var_name << "\" in \"\"|*:*) "
         << "route_command_error \"" << label
         << ": runtime variable " << var_name
         << " is empty or not an IPv4 address\" ;; esac\n";
}

} // namespace

bool RoutingCompiler_nft::processIPRules::processNext()
{
    using namespace libfwbuilder;

    Rule *rule = prev_processor->getNextRule();
    if (rule == nullptr) return false;

    IPRule *iprule = IPRule::cast(rule);
    if (iprule == nullptr)
    {
        tmp_queue.push_back(rule);
        return true;
    }

    RoutingCompiler_nft *nft = static_cast<RoutingCompiler_nft*>(compiler);

    RuleElement *elements[5] = { iprule->getSrc(), iprule->getDst(),
                                 iprule->getSrv(), iprule->getItfInb(),
                                 iprule->getItfOutb() };

    // Negation is fail-closed: silently ignoring a negated selector
    // would silently narrow what the ip rule matches.
    for (int index = 0; index < 5; ++index)
    {
        RuleElement *element = elements[index];
        if (element != nullptr && element->getNeg())
        {
            compiler->abort(rule,
                "Negation is not supported in IP rules");
            return true;
        }
    }

    // Time intervals would be silently ignored by ip rule, reject them.
    FWObject *when = iprule->getFirstByType("When");
    if (when != nullptr && when->size() > 0)
    {
        compiler->abort(rule,
            "Time intervals are not supported in IP rules");
        return true;
    }

    int priority = iprule->getPriority();
    if (priority < 0 || priority > 32767)
    {
        compiler->abort(rule,
            "IP rule priority must be a number between 0 and 32767");
        return true;
    }

    // Address family of the rule comes from the atomic address
    // objects; pure rules stay in their pass, family-less rules
    // (fwmark and/or interfaces only) compile in both passes.
    std::list<FWObject*> src_objects;
    std::list<FWObject*> dst_objects;
    for (FWObject::iterator it = iprule->getSrc()->begin();
         it != iprule->getSrc()->end(); ++it)
    {
        if (FWReference::cast(*it) == nullptr) continue;
        collectIPRuleObjects(FWReference::getObject(*it), src_objects);
    }
    for (FWObject::iterator it = iprule->getDst()->begin();
         it != iprule->getDst()->end(); ++it)
    {
        if (FWReference::cast(*it) == nullptr) continue;
        collectIPRuleObjects(FWReference::getObject(*it), dst_objects);
    }

    // W4.3 runtime-variable selectors: the rule options may name a
    // shell variable that the prolog fills at activation time, e.g.
    // the dynamic provider address behind a modem on the WAN
    // interface. The variable replaces all address objects of that
    // selector; mixing both in one field is rejected below because
    // one ip rule can not express the union.
    FWOptions *iprule_options = iprule->getOptionsObject();
    std::string src_runtime_var = iprule_options != nullptr
        ? iprule_options->getStr("ip_rule_src_runtime_var") : "";
    std::string dst_runtime_var = iprule_options != nullptr
        ? iprule_options->getStr("ip_rule_dst_runtime_var") : "";
    src_runtime_var = stripShellVarPrefix(src_runtime_var);
    dst_runtime_var = stripShellVarPrefix(dst_runtime_var);
    const bool uses_runtime_var =
        !src_runtime_var.empty() || !dst_runtime_var.empty();
    for (int index = 0; index < 2; ++index)
    {
        const std::string &var_name =
            (index == 0) ? src_runtime_var : dst_runtime_var;
        if (var_name.empty()) continue;
        const std::list<FWObject*> &objects =
            (index == 0) ? src_objects : dst_objects;
        const char *option_name = (index == 0)
            ? "ip_rule_src_runtime_var" : "ip_rule_dst_runtime_var";
        const char *selector_name =
            (index == 0) ? "source" : "destination";
        if (!isValidShellVarName(var_name))
        {
            compiler->abort(rule,
                std::string("IP rule ") + rule->getLabel() +
                " option " + option_name + " '" + var_name +
                "' is not a valid shell variable name");
            return true;
        }
        if (!objects.empty())
        {
            compiler->abort(rule,
                std::string("IP rule ") + rule->getLabel() +
                " combines static " + selector_name +
                " addresses with runtime variable '" + var_name +
                "'; use either the variable or address objects");
            return true;
        }
    }

    bool has_ipv4 = false;
    bool has_ipv6 = false;
    for (int index = 0; index < 2; ++index)
    {
        const std::list<FWObject*> &objects =
            (index == 0) ? src_objects : dst_objects;
        for (std::list<FWObject*>::const_iterator it = objects.begin();
             it != objects.end(); ++it)
        {
            FWObject *obj = *it;
            AddressRange *range = AddressRange::cast(obj);
            if (range)
            {
                if (range->getRangeStart().isV6()) has_ipv6 = true;
                else has_ipv4 = true;
                continue;
            }
            noteRouteFamily(obj, has_ipv4, has_ipv6);
        }
    }
    // A runtime variable holds an IPv4 address at activation time (the
    // guard in the script also refuses a value containing ':'), so
    // these rules compile in the IPv4 pass only and never in both
    // passes like family-less fwmark rules.
    if (uses_runtime_var) has_ipv4 = true;
    if (has_ipv4 && has_ipv6)
    {
        compiler->abort(rule, "IP rule mixes IPv4 and IPv6 addresses");
        return true;
    }
    if (nft->compilingIPv6())
    {
        if (has_ipv4 && !has_ipv6) return true;
    } else
    {
        if (has_ipv6 && !has_ipv4) return true;
    }

    // Address selectors.
    std::list<std::string> from_selectors;
    std::list<std::string> to_selectors;
    collectIPRuleSelectors(compiler, rule, src_objects, from_selectors);
    collectIPRuleSelectors(compiler, rule, dst_objects, to_selectors);
    // The runtime-variable selector expands at activation time; it
    // replaces all address objects of that field.
    if (!src_runtime_var.empty())
        from_selectors.push_back("$" + src_runtime_var);
    if (!dst_runtime_var.empty())
        to_selectors.push_back("$" + dst_runtime_var);

    // The service element holds the fwmark: exactly 0 or 1 TagService.
    std::string fwmark;
    {
        std::list<FWObject*> srv_objects;
        for (FWObject::iterator it = iprule->getSrv()->begin();
             it != iprule->getSrv()->end(); ++it)
        {
            if (FWReference::cast(*it) == nullptr) continue;
            collectIPRuleObjects(FWReference::getObject(*it), srv_objects);
        }
        for (std::list<FWObject*>::iterator it = srv_objects.begin();
             it != srv_objects.end(); ++it)
        {
            TagService *tag = TagService::cast(*it);
            if (tag == nullptr)
            {
                compiler->abort(rule,
                    "Only Tag/Mark services are supported in IP rule " +
                    rule->getLabel());
                return true;
            }
            if (!fwmark.empty())
            {
                compiler->abort(rule,
                    "IP rule " + rule->getLabel() +
                    " can use at most one tag service");
                return true;
            }
            fwmark = tag->getCode();
            if (fwmark.empty())
            {
                compiler->abort(rule,
                    "Tag service '" + tag->getName() +
                    "' used in IP rule " + rule->getLabel() +
                    " has no mark code");
                return true;
            }
        }
    }

    // Interface selectors: 0 or 1 firewall interface each.
    std::string iif_name;
    std::string oif_name;
    const char *itf_names[2] = { "iif", "oif" };
    RuleElement *itf_elements[2] = { iprule->getItfInb(),
                                     iprule->getItfOutb() };
    std::string *itf_result[2] = { &iif_name, &oif_name };
    for (int index = 0; index < 2; ++index)
    {
        std::list<FWObject*> itf_objects;
        for (FWObject::iterator it = itf_elements[index]->begin();
             it != itf_elements[index]->end(); ++it)
        {
            if (FWReference::cast(*it) == nullptr) continue;
            collectIPRuleObjects(FWReference::getObject(*it), itf_objects);
        }
        if (itf_objects.size() > 1)
        {
            compiler->abort(rule,
                std::string("IP rule ") + rule->getLabel() +
                " can use at most one interface in " + itf_names[index]);
            return true;
        }
        if (itf_objects.empty()) continue;
        Interface *iface = Interface::cast(itf_objects.front());
        if (iface == nullptr)
        {
            compiler->abort(rule,
                std::string("Object '") + itf_objects.front()->getName() +
                "' used in " + itf_names[index] + " of IP rule " +
                rule->getLabel() + " is not an interface");
            return true;
        }
        // Mirror rItfChildOfFw: the interface must belong to this
        // firewall (directly or through a cluster this firewall is a
        // member of).
        FWObject *parent_host = Host::getParentHost(iface);
        if (parent_host != nullptr && parent_host->getId() == nft->fw->getId())
        {
            *itf_result[index] = iface->getName();
            continue;
        }
        Cluster *cluster = Cluster::cast(parent_host);
        bool member = false;
        if (cluster)
        {
            std::list<Firewall*> members;
            cluster->getMembersList(members);
            for (std::list<Firewall*>::iterator m = members.begin();
                 m != members.end(); ++m)
                if ((*m)->getId() == nft->fw->getId()) member = true;
        }
        if (!member)
        {
            compiler->abort(rule,
                "Interface '" + iface->getName() +
                "' used in IP rule " + rule->getLabel() +
                " is not a child of the firewall the rule belongs to");
            return true;
        }
        *itf_result[index] = iface->getName();
    }

    // Resolve the lookup target: a Routing rule set of this firewall.
    // The target may keep the main table (empty table options).
    // iprule_options was already read above (runtime variables);
    // IPRule::getOptionsObject() always returns the same object.
    std::string lookup_id = iprule_options != nullptr
        ? iprule_options->getStr("ip_rule_lookup_id") : "";
    std::string lookup_name = iprule_options != nullptr
        ? iprule_options->getStr("ip_rule_lookup_name") : "";
    RuleSet *target = nullptr;
    if (!lookup_id.empty())
    {
        target = RuleSet::cast(
            rule->getRoot()->findInIndex(FWObjectDatabase::getIntId(lookup_id)));
    }
    if (target == nullptr && !lookup_name.empty())
    {
        target = RuleSet::cast(nft->fw->findObjectByName(
            Routing::TYPENAME, lookup_name));
    }
    if (target == nullptr)
    {
        compiler->abort(rule,
            "IP rule " + rule->getLabel() +
            " needs a routing rule set (lookup target)");
        return true;
    }
    if (target->getParent() == nullptr ||
        target->getParent()->getId() != nft->fw->getId())
    {
        compiler->abort(rule,
            "Routing rule set '" + target->getName() +
            "' used as lookup target of IP rule " + rule->getLabel() +
            " does not belong to the firewall the rule belongs to");
        return true;
    }
    FWOptions *target_options = target->getOptionsObject();
    std::string table_name = target_options != nullptr
        ? target_options->getStr("routing_table_name") : "";
    std::string table_id = target_options != nullptr
        ? target_options->getStr("routing_table_id") : "";
    const bool manage_rt_tables =
        nft->fw->getOptionsObject() != nullptr &&
        nft->fw->getOptionsObject()->getBool("manage_rt_tables");
    std::string lookup_token;
    if (table_name.empty()) lookup_token = "main";
    else if (manage_rt_tables) lookup_token = table_name;
    else lookup_token = table_id;
    if (lookup_token.empty())
    {
        compiler->abort(rule,
            "Routing rule set '" + target->getName() +
            "' used as lookup target of IP rule " + rule->getLabel() +
            " needs a numeric table id");
        return true;
    }

    // Atomar expansion: one ip rule per (from, to) combination.
    std::list<std::string> combos;
    if (from_selectors.empty() && to_selectors.empty())
    {
        combos.push_back("");
    } else
    {
        std::list<std::string>::const_iterator from_it;
        std::list<std::string>::const_iterator to_it;
        if (from_selectors.empty())
        {
            for (to_it = to_selectors.begin(); to_it != to_selectors.end(); ++to_it)
                combos.push_back("to " + *to_it);
        } else
        {
            for (from_it = from_selectors.begin();
                 from_it != from_selectors.end(); ++from_it)
            {
                if (to_selectors.empty())
                {
                    combos.push_back("from " + *from_it);
                } else
                {
                    for (to_it = to_selectors.begin();
                         to_it != to_selectors.end(); ++to_it)
                        combos.push_back("from " + *from_it +
                                         " to " + *to_it);
                }
            }
        }
    }

    // Runtime-variable rules resolve their selector at activation time
    // through one dedicated shell variable per combination, so the
    // kernel command references that variable instead of the literal
    // spec. The single-rule compile keeps the literal form because
    // its output is never executed.
    const std::string family_char = nft->compilingIPv6() ? "6" : "4";
    const bool command_uses_spec_var =
        uses_runtime_var && !compiler->inSingleRuleCompileMode();

    std::list<std::string> commands;
    std::list<std::string> specs;
    int combo_counter = 0;
    for (std::list<std::string>::iterator combo = combos.begin();
         combo != combos.end(); ++combo)
    {
        std::string spec = *combo;
        if (!fwmark.empty()) spec += (spec.empty() ? "" : " ") + std::string("fwmark ") + fwmark;
        if (!iif_name.empty()) spec += (spec.empty() ? "" : " ") + std::string("iif ") + iif_name;
        if (!oif_name.empty()) spec += (spec.empty() ? "" : " ") + std::string("oif ") + oif_name;
        spec += (spec.empty() ? "" : " ") + std::string("lookup ") + lookup_token;

        std::ostringstream command;
        command << (nft->compilingIPv6() ? "$IP -6 rule add pref "
                                          : "$IP rule add pref ")
                << priority << " ";
        if (command_uses_spec_var)
            command << "$fwb_rule_spec_" << family_char << "_"
                    << priority << "_" << combo_counter;
        else
            command << spec;
        commands.push_back(command.str());
        specs.push_back(spec);
        ++combo_counter;
    }

    if (compiler->inSingleRuleCompileMode())
    {
        for (std::list<std::string>::iterator cmd = commands.begin();
             cmd != commands.end(); ++cmd)
            compiler->output << *cmd << "\n";
        return true;
    }

    // The rule never reaches the shared route printers, so the route
    // output stays byte-identical. The text lands in printed_ip_rules
    // and the driver emits one sorted ip rule section.
    std::ostringstream text;
    const std::string label = rule->getLabel();
    text << "# \n";
    text << "# Rule " << label << "\n";
    text << "# \n";
    text << "echo \"IP rule " << label << "\"\n";
    text << "# \n";

    std::string comment = iprule->getComment();
    std::string::size_type c1 = 0, c2;
    while ((c2 = comment.find('\n', c1)) != std::string::npos)
    {
        text << "# " << comment.substr(c1, c2 - c1) << "\n";
        c1 = c2 + 1;
    }
    if (!comment.empty())
        text << "# " << comment.substr(c1) << "\n";

    const std::string errors = compiler->getErrorsForRule(rule, "# ");
    if (!errors.empty()) text << errors << "\n";

    if (uses_runtime_var)
    {
        // Fail closed before any spec variable is expanded: an empty
        // or non-IPv4 value would otherwise become a broken or
        // silently overmatching ip rule. route_command_error rolls
        // back everything committed so far and exits the script.
        if (!src_runtime_var.empty())
            printRuntimeVarGuard(text, src_runtime_var, label);
        if (!dst_runtime_var.empty())
            printRuntimeVarGuard(text, dst_runtime_var, label);

        int combo_index = 0;
        std::list<std::string>::iterator cmd = commands.begin();
        std::list<std::string>::iterator spec = specs.begin();
        for (; cmd != commands.end(); ++cmd, ++spec, ++combo_index)
        {
            // The spec is assigned with the variable UNEXPANDED, then
            // passed double-quoted: the shell resolves it before
            // fwb_rule_prepare compares the state, so the state file
            // records the resolved address and a changed provider
            // address retires and re-adds the kernel rule on the
            // next run.
            std::ostringstream spec_var_name;
            spec_var_name << "fwb_rule_spec_" << family_char << "_"
                          << priority << "_" << combo_index;
            text << spec_var_name.str() << "=\"" << *spec << "\" && \\\n"
                 << "fwb_rule_prepare " << family_char << " " << priority
                 << " \"$" << spec_var_name.str() << "\" && \\\n"
                 << *cmd << " && \\\n"
                 << "fwb_rule_committed " << family_char << " " << priority
                 << " \"$" << spec_var_name.str() << "\" \\\n"
                 << "|| route_command_error \"" << label << "\"\n";
        }
    }
    else
    {
        std::list<std::string>::iterator cmd = commands.begin();
        std::list<std::string>::iterator spec = specs.begin();
        for (; cmd != commands.end(); ++cmd, ++spec)
        {
            // The quoted spec is the retire key: identical specs match
            // exactly, changed specs retire the outdated kernel rule.
            const std::string quoted_spec = shellQuote(*spec);
            text << "fwb_rule_prepare " << family_char << " " << priority << " "
                 << quoted_spec << " && \\\n" << *cmd << " && \\\n"
                 << "fwb_rule_committed " << family_char << " " << priority
                 << " " << quoted_spec << " \\\n"
                 << "|| route_command_error \"" << label << "\"\n";
        }
    }

    PrintedIPRule printed;
    printed.family = nft->compilingIPv6() ? 6 : 4;
    printed.priority = priority;
    printed.ruleset = compiler->getRuleSetName();
    printed.label = label;
    printed.text = text.str();
    printed.uses_runtime_var = uses_runtime_var;
    nft->printed_ip_rules.push_back(printed);

    return true;
}
