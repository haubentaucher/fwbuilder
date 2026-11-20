/* 

                  Firewall Builder Routing add-on

                 Copyright (C) 2004 Compal GmbH, Germany

  Author:  Tidei Maurizio     <fwbuilder-routing at compal.de>
  
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

#include "fwbuilder/Resources.h"
#include "fwbuilder/FWObjectDatabase.h"
#include "fwbuilder/RuleElement.h"
#include "fwbuilder/Routing.h"
#include "fwbuilder/Interface.h"
#include "fwbuilder/IPv4.h"
#include "fwbuilder/IPv6.h"
#include "fwbuilder/Firewall.h"
#include "fwbuilder/Host.h"
#include "fwbuilder/Network.h"
#include "fwbuilder/NetworkIPv6.h"
#include "fwbuilder/InetAddrMask.h"

#include <assert.h>
#include <sstream>
#include <list>

using namespace libfwbuilder;
using namespace fwcompiler;
using namespace std;

static std::map<std::string,int> tmp_chain_no;

string RoutingCompiler_nft::myPlatformName() { return "nftables"; }


void RoutingCompiler_nft::verifyPlatform()
{
    //TODO: Routing based on the 'ip' command is independent from iptables
    string family = Resources::platform_res[fw->getStr("platform")]->
        getResourceStr("/FWBuilderResources/Target/family");

    if (family != myPlatformName()) 
	abort("Unsupported platform " + fw->getStr("platform") +
              " (family " + family + ")");
}

int RoutingCompiler_nft::prolog()
{
    int n = RoutingCompiler::prolog();    

    verifyPlatform(); 

    return n;
}


/*
 *  this processor eliminates duplicate routing rules, generated from the same
 *  rule in the GUI
 */
bool RoutingCompiler_nft::optimize3::processNext()
{
    RoutingRule *rule;
    rule=getNext(); if (rule==nullptr) return false;

    if (rule->isFallback() || rule->isHidden())
    {
        tmp_queue.push_back(rule);
        return true;
    }

    if (printRule==nullptr)
    {
        printRule = new PrintRule("");
        printRule->setContext(compiler);
    }
    
    string thisRule = rule->getLabel() + " " + printRule->RoutingRuleToString(rule);
    
    if (rules_seen_so_far.count(thisRule)!=0) return true;

    tmp_queue.push_back(rule);
    rules_seen_so_far[thisRule] = true;

    return true;
}

/*
 *  this processor eliminates duplicate atomic routing rules in one routing table
 */
bool RoutingCompiler_nft::eliminateDuplicateRules::processNext()
{
    RoutingRule *rule;
    rule = getNext(); if (rule==nullptr) return false;

    if (rule->isFallback() || rule->isHidden())
    {
        tmp_queue.push_back(rule);
        return true;
    }

    if (printRule==nullptr)
    {
        printRule = new PrintRule("");
        printRule->setContext(compiler);
    }
    
    string label = rule->getLabel();
    int bracepos = label.find("(");
    label.erase(0, bracepos);
    
    string thisRule = label + " " + printRule->RoutingRuleToString(rule);
    
    rules_it = rules_seen_so_far.find(thisRule);
            
    if (rules_it != rules_seen_so_far.end())
    {
        string msg;
        msg = "Two of the sub rules created from the gui routing rules " +
            rules_it->second + " and " + rule->getLabel() +
            " are identical, skipping the second. " +
            "Revise them to avoid this warning";
        compiler->warning(rule,  msg.c_str());
        return true;
    }

    tmp_queue.push_back(rule);
    rules_seen_so_far[thisRule] = rule->getLabel();
    return true;
}

bool RoutingCompiler_nft::addressRangesInDst::processNext()
{
    RoutingRule *rule;
    rule=getNext(); if (rule==nullptr) return false;

    RuleElementRDst *dstrel = rule->getRDst();
    compiler->_expandAddressRanges(rule, dstrel);

    tmp_queue.push_back(rule);
    return true;
}


bool RoutingCompiler_nft::FindDefaultRoute::processNext()
{
    RoutingCompiler_nft *nft_comp =
        static_cast<RoutingCompiler_nft*>(compiler);
    RoutingRule *rule;
    rule=getNext(); if (rule==nullptr) return false;

    RuleElementRDst *dstrel = rule->getRDst();
    FWObject *ref = dstrel->front();
    Address *dst = Address::cast(FWReference::cast(ref)->getPointer());
    if (dst->isAny()) nft_comp->have_default_route = true;

    tmp_queue.push_back(rule);
    return true;
}


/**
 *-----------------------------------------------------------------------
 */
void RoutingCompiler_nft::compile()
{
    string banner = " Compiling routing rules for " + fw->getName() +
        (ipv6 ? " (IPv6)" : " (IPv4)");
    info(banner);

    Compiler::compile();
    //bool check_for_recursive_groups=true;

    add(new RoutingCompiler::Begin());
    add(new printTotalNumberOfRules());
        
    add( new singleRuleFilter());

    add(new recursiveGroupsInRDst("Check for recursive Groups in RDst"));
    add(new emptyGroupsInRDst("Check for empty Groups in RDst"));
    add(new emptyRDstAndRItf("Check if RDst and RItf are both empty"));
    add(new rItfChildOfFw("Check if RItf is an Iterface of this firewall"));

    // Classify before ExpandGroups/ExpandMultipleAddresses. Both expanders
    // call MatchesAddressFamily and clear non-matching objects from rule
    // elements, which would turn a mixed rule into a silent empty rule
    // and would discard the other family before keepMatching can see it.
    add(new rejectMixedAddressFamilies(
            "Reject routing rules that mix IPv4 and IPv6"));
    // Do not use DropIPv4Rules/DropIPv6Rules here: they remove dual-stack
    // interfaces from RItf and silently discard every IPv6 route that
    // names an interface.
    add(new keepMatchingAddressFamily(
            "Keep routing rules for this address family", ipv6));
    add(new ExpandGroups("Expand groups in DST"));
    add(new ExpandMultipleAddresses(
            "Expand objects with multiple addresses in DST"));
    add(new dropRuleWithEmptyRE("drop rules with empty rule elements"));

    // Each address family is compiled by its own pass. IPv6 rules are
    // not reported as unsupported: the IPv6 pass compiles them.
    if (ipv6)
    {
        add(new validateIPv6Route(
                "Validate IPv6 destination, gateway and interface"));
    }
    else
    {
        add(new singleAdressInRGtw(
                "Check if RGtw object has exactly one IP adress"));
        add(new validateNetwork("Validate network addresses"));
        add(new reachableAddressInRGtw(
                "Check if RGtw is reachable via local networks"));
        add(new contradictionRGtwAndRItf(
                "Check if RGtw is in a network of RItf"));
    }

    add(new addressRangesInDst("process address ranges"));

    add(new eliminateDuplicatesInDST("Eliminate duplicates in DST"));
        
    add(new FindDefaultRoute("Find rules that install default route"));

    add(new createSortedDstIdsLabel(
            "Create label with a sorted dst-id-list for 'competingRules'"));
    add(new competingRules("Check for competing rules"));

    add(new ConvertToAtomicForDST(
            "Convert to atomic rules by dst address elements"));

    add(new createSortedDstIdsLabel(
            "Create label with a sorted dst-id-list for 'classifyRoutingRules'"));
    add(new classifyRoutingRules(
            "Classify into single path or part of a multi path rule"));
        
    add(new optimize3(
            "Eliminate duplicate rules generated from a single gui-rule"));
    add(new eliminateDuplicateRules(
            "Eliminate duplicate rules over the whole table"));
        
    add( new checkForObjectsWithErrors(
             "check if we have objects with errors in rule elements"));

    add(new PrintRule("generate ip code"));
    add(new simplePrintProgress());

    runRuleProcessors();

}

string RoutingCompiler_nft::debugPrintRule(Rule *r)
{
    RoutingRule *rule=RoutingRule::cast(r);

    string s= RoutingCompiler::debugPrintRule(rule);

    return s;
}

void RoutingCompiler_nft::epilog()
{
    ///int total = ecmp_comments_buffer.size();
    int nb = 0;
    
    // ecmp roules can only be generated after all the rules have been
    // parsed, that is the reason for putting this code in the epilog
    // function
    if (ecmp_rules_buffer.size() > 0)
    {
        output << "\n#\n# ============== EQUAL COST MULTI PATH ============\n#"
               << endl;
        
        output << "echo \"Activating ecmp routing rules...\"" << endl;
                
        for (map<string,string>::iterator
                 ecmp_comments_buffer_it = ecmp_comments_buffer.begin();
             ecmp_comments_buffer_it != ecmp_comments_buffer.end();
             ++ecmp_comments_buffer_it)
        {
            output << ecmp_comments_buffer_it->second << "#\n" << flush;

            ostringstream label;
            label << ++nb;
            output << activationCommand(
                ecmp_rules_buffer[ecmp_comments_buffer_it->first],
                label.str());

            //echo \"Error: The ECMP routing rule #" << ++nb <<" couldn't be activated! Please make sure your kernel is compiled with the CONFIG_IP_ROUTE_MULTIPATH option.\"" << endl;
            
        }
    }
    
}

namespace {

bool isLinkLocalV6(const InetAddr *addr)
{
    if (addr == nullptr || !addr->isV6()) return false;
    const unsigned char *bytes =
        reinterpret_cast<const unsigned char *>(addr->getV6());
    return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
}

void noteRouteFamily(FWObject *object, bool &ipv4, bool &ipv6)
{
    if (object == nullptr) return;
    if (object->getId() == FWObjectDatabase::ANY_ADDRESS_ID) return;
    if (Interface::cast(object) != nullptr) return;
    if (NetworkIPv6::cast(object) != nullptr || IPv6::cast(object) != nullptr)
    {
        ipv6 = true;
        return;
    }
    if (Network::cast(object) != nullptr || IPv4::cast(object) != nullptr)
    {
        ipv4 = true;
        return;
    }
    Address *address = Address::cast(object);
    if (address == nullptr || address->isAny()) return;
    const InetAddr *ip = address->getAddressPtr();
    if (ip == nullptr)
    {
        // Host/Firewall without a preferred address: look at typed children.
        if (!object->getByType(IPv6::TYPENAME).empty() ||
            !object->getByTypeDeep(IPv6::TYPENAME).empty())
            ipv6 = true;
        if (!object->getByType(IPv4::TYPENAME).empty() ||
            !object->getByTypeDeep(IPv4::TYPENAME).empty())
            ipv4 = true;
        return;
    }
    if (ip->isV6()) ipv6 = true;
    if (ip->isV4()) ipv4 = true;
}

bool gatewayInIPv6Network(Interface *iface, const InetAddr *gateway)
{
    for (FWObjectTypedChildIterator addresses = iface->findByType(IPv6::TYPENAME);
         addresses != addresses.end(); ++addresses)
    {
        Address *local = Address::cast(*addresses);
        if (local == nullptr || local->getAddressPtr() == nullptr ||
            local->getNetmaskPtr() == nullptr)
            continue;
        InetAddrMask network(*local->getAddressPtr(), *local->getNetmaskPtr());
        if (network.belongs(*gateway)) return true;
    }
    return false;
}

string shellQuote(const string &value)
{
    string quoted = "'";
    for (string::size_type i = 0; i < value.size(); ++i)
    {
        if (value[i] == '\'') quoted += "'\\''";
        else quoted += value[i];
    }
    quoted += "'";
    return quoted;
}

}


bool RoutingCompiler_nft::rejectMixedAddressFamilies::processNext()
{
    RoutingRule *rule = getNext();
    if (rule == nullptr) return false;

    bool ipv4 = false;
    bool ipv6_object = false;
    RuleElement *elements[2] = { rule->getRDst(), rule->getRGtw() };
    for (int index = 0; index < 2; ++index)
    {
        RuleElement *element = elements[index];
        if (element == nullptr) continue;
        for (FWObject::iterator it = element->begin(); it != element->end(); ++it)
            noteRouteFamily(FWReference::getObject(*it), ipv4, ipv6_object);
    }
    if (ipv4 && ipv6_object)
    {
        compiler->abort(rule, "Routing rule mixes IPv4 and IPv6");
        return true;
    }
    tmp_queue.push_back(rule);
    return true;
}

bool RoutingCompiler_nft::keepMatchingAddressFamily::processNext()
{
    RoutingRule *rule = getNext();
    if (rule == nullptr) return false;

    bool has_ipv4 = false;
    bool has_ipv6 = false;
    RuleElementRDst *destination = rule->getRDst();
    if (destination != nullptr && destination->isAny())
        has_ipv4 = true;
    RuleElement *elements[2] = { rule->getRDst(), rule->getRGtw() };
    for (int index = 0; index < 2; ++index)
    {
        RuleElement *element = elements[index];
        if (element == nullptr || element->isAny()) continue;
        for (FWObject::iterator it = element->begin(); it != element->end(); ++it)
            noteRouteFamily(FWReference::getObject(*it), has_ipv4, has_ipv6);
    }

    // Drop only rules that clearly belong to the other family. Rules with
    // no detectable family still go through ExpandGroups / validators so a
    // missed type check cannot silently discard every IPv6 route.
    if (want_ipv6)
    {
        if (has_ipv4 && !has_ipv6) return true;
    }
    else
    {
        if (has_ipv6 && !has_ipv4) return true;
    }

    tmp_queue.push_back(rule);
    return true;
}

bool RoutingCompiler_nft::validateIPv6Route::processNext()
{
    RoutingRule *rule = getNext();
    if (rule == nullptr) return false;
    tmp_queue.push_back(rule);

    FWObject *destination_object = FWReference::getObject(rule->getRDst()->front());
    Address *destination = Address::cast(destination_object);
    if (destination == nullptr)
    {
        compiler->abort(rule, "Broken DST");
        return true;
    }
    NetworkIPv6 *network = NetworkIPv6::cast(destination_object);
    if (network != nullptr && !network->isValidRoutingNet())
    {
        compiler->abort(
            rule,
            "Object \"" + destination_object->getName() +
            "\" used as destination in the routing rule " +
            rule->getLabel() + " has invalid netmask");
        return true;
    }

    FWObject *gateway_object = FWReference::getObject(rule->getRGtw()->front());
    if (gateway_object->getId() == FWObjectDatabase::ANY_ADDRESS_ID ||
        (Address::cast(gateway_object) != nullptr &&
         Address::cast(gateway_object)->isAny()))
        return true;

    const InetAddr *gateway = nullptr;
    if (IPv6::cast(gateway_object) != nullptr)
    {
        gateway = Address::cast(gateway_object)->getAddressPtr();
    }
    else if (Interface::cast(gateway_object) != nullptr ||
             Host::cast(gateway_object) != nullptr)
    {
        list<FWObject*> addresses;
        if (Interface::cast(gateway_object) != nullptr)
            addresses = gateway_object->getByType(IPv6::TYPENAME);
        else
        {
            list<FWObject*> interfaces =
                gateway_object->getByType(Interface::TYPENAME);
            if (interfaces.size() != 1)
            {
                compiler->abort(
                    rule,
                    "Object \"" + gateway_object->getName() +
                    "\" used as a gateway in the routing rule " +
                    rule->getLabel() + " has multiple ip adresses");
                return true;
            }
            addresses = interfaces.front()->getByType(IPv6::TYPENAME);
        }
        if (addresses.size() != 1)
        {
            compiler->abort(
                rule,
                "Object \"" + gateway_object->getName() +
                "\" used as a gateway in the routing rule " +
                rule->getLabel() + " has multiple ip adresses");
            return true;
        }
        gateway = Address::cast(addresses.front())->getAddressPtr();
    }
    if (gateway == nullptr || !gateway->isV6())
    {
        compiler->abort(rule, "IPv6 routing gateway must be a single IPv6 address");
        return true;
    }

    FWObject *interface_object = FWReference::getObject(rule->getRItf()->front());
    // Avoid identifier name "interface": Windows headers #define it to struct.
    Interface *iface = Interface::cast(interface_object);
    bool interface_any = rule->getRItf()->isAny() || iface == nullptr;
    if (isLinkLocalV6(gateway))
    {
        if (interface_any)
            compiler->abort(rule, "Link-local IPv6 gateway requires an interface");
        return true;
    }

    if (!interface_any)
    {
        if (!gatewayInIPv6Network(iface, gateway))
        {
            compiler->abort(
                rule,
                "Object \"" + gateway_object->getName() +
                "\" used as gateway in the routing rule " +
                rule->getLabel() +
                " is not in the same local network as interface " +
                iface->getName());
        }
        return true;
    }

    bool reachable = false;
    list<FWObject*> interfaces = compiler->fw->getByTypeDeep(Interface::TYPENAME);
    for (list<FWObject*>::iterator it = interfaces.begin();
         it != interfaces.end(); ++it)
    {
        if (gatewayInIPv6Network(Interface::cast(*it), gateway))
        {
            reachable = true;
            break;
        }
    }
    if (!reachable)
    {
        compiler->abort(
            rule,
            "Object \"" + gateway_object->getName() +
            "\" used as gateway in the routing rule " +
            rule->getLabel() +
            " is not in any local IPv6 network of the firewall");
    }
    return true;
}

string RoutingCompiler_nft::routeAddPrefix() const
{
    return ipv6 ? "$IP -6 route add " : "$IP route add ";
}

string RoutingCompiler_nft::activationCommand(const string &spec,
                                              const string &label)
{
    string command = routeAddPrefix() + spec;
    if (inSingleRuleCompileMode())
        return command + "\n";

    string destination = spec;
    string::size_type space = destination.find(' ');
    if (space != string::npos) destination.erase(space);

    ostringstream out;
    out << "fwb_route_prepare " << (ipv6 ? "6" : "4") << " "
        << shellQuote(destination) << " && \\\n"
        << command << " && \\\n"
        << "fwb_route_committed " << (ipv6 ? "6" : "4") << " "
        << shellQuote(destination) << " " << shellQuote(spec) << " \\\n"
        << "|| route_command_error \"" << label << "\"\n";
    return out.str();
}
