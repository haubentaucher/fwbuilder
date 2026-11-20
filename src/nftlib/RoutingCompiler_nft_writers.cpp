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
