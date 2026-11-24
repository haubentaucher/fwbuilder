/* 

                          Firewall Builder Routing add-on

                 Copyright (C) 2004 Compal GmbH, Germany

  Author:  Tidei Maurizio  <fwbuilder-routing at compal.de>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions: 

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software. 

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
  PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
  OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

*/


#ifndef __ROUTING_HH_FLAG__
#define __ROUTING_HH_FLAG__

#include "fwbuilder/FWObject.h"
#include "fwbuilder/RuleSet.h"

namespace libfwbuilder
{

class Routing : public RuleSet  
{
    public:
    
    Routing();
    virtual ~Routing();
    
    DECLARE_FWOBJECT_SUBTYPE(Routing);

    DECLARE_DISPATCH_METHODS(Routing);
    
/* the following methods provide proper typization */
    RoutingRule* getRuleByNum(int n) { return RoutingRule::cast(RuleSet::getRuleByNum(n)); }
    RoutingRule* insertRuleAtTop() { return RoutingRule::cast(RuleSet::insertRuleAtTop()); }
    RoutingRule* insertRuleBefore(int n){ return RoutingRule::cast(RuleSet::insertRuleBefore(n));}
    RoutingRule* appendRuleAfter(int n){ return RoutingRule::cast(RuleSet::appendRuleAfter(n));}
    RoutingRule* appendRuleAtBottom(){ return RoutingRule::cast(RuleSet::appendRuleAtBottom());}
    
    virtual Rule*   createRule();
};

/*
 * The per-firewall rule set for policy-based routing ("ip rule" on
 * Linux). IP rules select which iproute2 routing table a packet
 * consults; they do not live in any routing table themselves, so they
 * get their own rule set next to the routing rule sets (W4). The
 * compiler collects IPRule objects from these rule sets into the
 * single "ip rule" script section.
 */
class IPRules : public RuleSet
{
    public:

    IPRules();
    virtual ~IPRules();

    DECLARE_FWOBJECT_SUBTYPE(IPRules);

    DECLARE_DISPATCH_METHODS(IPRules);

    virtual Rule*   createRule();
};

}

#endif //__ROUTING_HH_FLAG__

