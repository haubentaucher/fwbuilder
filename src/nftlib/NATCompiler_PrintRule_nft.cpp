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

#include "NATCompiler_nft.h"
#include "OSConfigurator_linux24.h"

#include "fwbuilder/AddressRange.h"
#include "fwbuilder/RuleElement.h"
#include "fwbuilder/IPService.h"
#include "fwbuilder/ICMPService.h"
#include "fwbuilder/ICMP6Service.h"
#include "fwbuilder/TCPService.h"
#include "fwbuilder/UDPService.h"
#include "fwbuilder/UserService.h"
#include "fwbuilder/CustomService.h"
#include "fwbuilder/TagService.h"
#include "fwbuilder/Policy.h"
#include "fwbuilder/Interface.h"
#include "fwbuilder/IPv4.h"
#include "fwbuilder/Firewall.h"
#include "fwbuilder/Resources.h"
#include "fwbuilder/DNSName.h"
#include "fwbuilder/AddressTable.h"
#include "fwbuilder/XMLTools.h"

#include "combinedAddress.h"

#include "nft_utils.h"
#include "nftables_options.h"

#include <assert.h>
#include <stdexcept>

#include <QString>
#include <QStringList>

using namespace libfwbuilder;
using namespace fwcompiler;
using namespace std;



/**
 *-----------------------------------------------------------------------
 *                    Methods for printing
 */

/*
 * Prints single --option with argument and negation "!"
 * taking into account the change that happened in iptables 1.4.3.1
 * that causes warning
 * Using intrapositioned negation (`--option ! this`) is deprecated in favor of extrapositioned (`! --option this`).
 */
string NATCompiler_nft::PrintRule::_printSingleOptionWithNegation(
    const string &option, RuleElement *rel, const string &arg)
{
    if (rel->getBool("single_object_negation"))
        return option + " != " + arg + " ";
    return option + " " + arg + " ";
}

void NATCompiler_nft::PrintRule::initializeMinusNTracker()
{
    NATCompiler_nft *ipt_comp = dynamic_cast<NATCompiler_nft*>(compiler);
    for (list<string>::const_iterator i =
             NATCompiler_nft::getStandardChains().begin();
         i != NATCompiler_nft::getStandardChains().end(); ++i)
    {
        (*(ipt_comp->minus_n_commands))[*i] = true;
    }
    minus_n_tracker_initialized = true;
}

/*
 * Initialize some internal variables. Need to do this in a separate
 * method because pointer to the compiler object is set by
 * RuleProcessor::setContext and is not available in constructor.
 */
void NATCompiler_nft::PrintRule::initialize()
{
    // retrieve and save version for _printSingleOptionWithNegation and others
    version = compiler->fw->getStr("version");
}

/*
 *  check and create new chain if needed
 */
string NATCompiler_nft::PrintRule::_createChain(const string &chain)
{
    NATCompiler_nft *ipt_comp = dynamic_cast<NATCompiler_nft*>(compiler);
    ostringstream  res;

    if (!minus_n_tracker_initialized) initializeMinusNTracker();

    if ( ipt_comp->minus_n_commands->count(chain)==0 )
    {
        bool atomic = useNftablesAtomic(compiler->getCachedFwOpt());
        string prefix = nft_utils::commandPrefix(atomic);
        string base_chain = nft_utils::baseChainDefinition(
            "nat", chain, ipt_comp->ipv6, "");
        if (!base_chain.empty())
        {
            res << prefix << base_chain << "\n";
        } else
        {
            res << prefix << "add chain " << nft_utils::familyName(ipt_comp->ipv6)
                << " " << nft_utils::managedTableName("nat") << " " << chain << "\n";
        }
	(*(ipt_comp->minus_n_commands))[chain] = true;
    }
    return res.str();
}

string NATCompiler_nft::PrintRule::_startRuleLine()
{
    NATCompiler_nft *ipt_comp = dynamic_cast<NATCompiler_nft*>(compiler);
    bool atomic = useNftablesAtomic(compiler->getCachedFwOpt());
    string prefix = nft_utils::commandPrefix(atomic);
    return prefix + "add rule " + nft_utils::familyName(ipt_comp->ipv6) + " " + nft_utils::managedTableName("nat") + " ";
}

string NATCompiler_nft::PrintRule::_endRuleLine()
{
    return string("\n");
}

string NATCompiler_nft::PrintRule::_printRuleLabel(NATRule *rule)
{
    ostringstream res;

    bool nocomm =
        Resources::os_res[compiler->fw->getStr("host_OS")]->Resources::getResourceBool("/FWBuilderResources/Target/options/suppress_comments");

    // TODO: convert this into virtual function NATCompiler_nft::printComment()
    string rl=rule->getLabel();
    if (rl != current_rule_label)
    {
        if (!compiler->inSingleRuleCompileMode() && !nocomm)
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
        current_rule_label=rl;
    }

//    string err = rule->getCompilerMessage();
//    if (!err.empty()) res << "# " << err << "\n";

    return res.str();
}

/*
 *  check and create new chain if needed
 */

QString NATCompiler_nft::PrintRule::getInterfaceName(RuleElement *itf_re)
{
    if (itf_re->isAny()) return "";
    FWObject *iface = FWObjectReference::getObject(itf_re->front());
    QString iface_name = iface->getName().c_str();
    // FWB projects may store iptables-style prefix matches such as eth+.
    // nftables uses eth* instead.  A bare '+' becomes '*' and is omitted
    // (unless negated, which is explicitly rejected by the caller).
    if (iface_name.endsWith("+"))
    {
        iface_name.chop(1);
        iface_name += "*";
    }
    return iface_name;
}

/**
 *-----------------------------------------------------------------------
 */
string NATCompiler_nft::PrintRule::_printChainDirectionAndInterface(NATRule *rule)
{
    QStringList res;

    RuleElementItfInb *itf_in_re = rule->getItfInb(); assert(itf_in_re!=nullptr);
    RuleElementItfOutb *itf_out_re = rule->getItfOutb(); assert(itf_out_re!=nullptr);

    QString iface_in_name = getInterfaceName(itf_in_re);
    QString iface_out_name = getInterfaceName(itf_out_re);

    if (rule->getStr(".iface_in") == "nil") iface_in_name = "";
    if (rule->getStr(".iface_out") == "nil") iface_out_name = "";

    res << rule->getStr("ipt_chain").c_str();

    if (iface_in_name == "*" &&
        (itf_in_re->getNeg() || itf_in_re->getBool("single_object_negation")))
        compiler->abort(rule, "Negated any-interface match is not supported by native nftables");
    if (iface_out_name == "*" &&
        (itf_out_re->getNeg() || itf_out_re->getBool("single_object_negation")))
        compiler->abort(rule, "Negated any-interface match is not supported by native nftables");

    if ( ! iface_in_name.isEmpty() && iface_in_name != "*")
    {
        string iface_literal = "\"" + iface_in_name.toStdString() + "\"";
        res << _printSingleOptionWithNegation(
            "iifname", itf_in_re, iface_literal).c_str();
    }

    if ( ! iface_out_name.isEmpty() && iface_out_name != "*")
    {
        string iface_literal = "\"" + iface_out_name.toStdString() + "\"";
        res << _printSingleOptionWithNegation(
            "oifname", itf_out_re, iface_literal).c_str();
    }

    res << "";

    return res.join(" ").toStdString();
}

string NATCompiler_nft::PrintRule::_printProtocol(Service *srv)
{
    std::ostringstream  ostr;
    NATCompiler_nft *ipt_comp = dynamic_cast<NATCompiler_nft*>(compiler);
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
            if (ICMPService::isA(srv) && !ICMP6Service::isA(srv))
                compiler->abort("Can not use ICMPService in ipv6 NAT rule; use ICMP6Service instead");
            ostr << "meta l4proto "
                 << (ICMP6Service::isA(srv) ? "icmpv6" : pn) << " ";
        }
        else
        {
            if (ICMP6Service::isA(srv))
                compiler->abort("Can not use ICMP6Service in ipv4 NAT rule; use ICMPService instead");
            ostr << "ip protocol " << pn << " ";
        }
    }
    return ostr.str();
}

string NATCompiler_nft::PrintRule::_printMultiport(NATRule *rule)
{
    (void)rule;
    return "";
}


string NATCompiler_nft::PrintRule::_printOPorts(int rs,int re)
{
    std::ostringstream  ostr;

    if (rs<0) rs=0;
    if (re<0) re=0;

    if (rs>0 || re>0) {
	if (rs==re)  ostr << rs;
	else
	    if (rs==0 && re!=0)      ostr << "0-" << re;
	    else
                ostr << rs << "-" << re;
    }
    return ostr.str();
}

string NATCompiler_nft::PrintRule::_printTPorts(int rs,int re)
{
    std::ostringstream  ostr;

    if (rs<0) rs=0;
    if (re<0) re=0;

    if (rs>0 || re>0) {
	if (rs==re)  ostr << rs;
	else
	    if (rs==0 && re!=0)      ostr << "-" << re;
	    else
                ostr << rs << "-" << re;
    }
    return ostr.str();
}

string NATCompiler_nft::PrintRule::_printICMP(ICMPService *srv)
{
    return nft_utils::icmpMatchExpression(srv->getInt("type"),
                                          srv->getInt("code"),
                                          ICMP6Service::isA(srv));
}

string NATCompiler_nft::PrintRule::_printIP(IPService *srv, NATRule *rule)
{
    NATCompiler_nft *nft_comp = dynamic_cast<NATCompiler_nft*>(compiler);
    std::ostringstream result;

    // An IPService on a NAT rule must never fall through to legacy xtables
    // flags. Reuse the exact native expressions used by policy compilation.
    if (srv->getBool("fragm") || srv->getBool("short_fragm"))
        result << nft_utils::fragmentMatchExpression(nft_comp->ipv6) << " ";

    const string tos = srv->getTOSCode();
    if (!tos.empty())
        compiler->abort(rule, "Native nftables NAT TOS matching is not supported");

    const string dscp = srv->getDSCPCode();
    if (!dscp.empty())
    {
        try
        {
            result << nft_utils::dscpMatchExpression(dscp, nft_comp->ipv6) << " ";
        }
        catch (const std::invalid_argument &e)
        {
            compiler->abort(rule, string("Invalid native nftables NAT DSCP: ") + e.what());
        }
    }

    if (srv->hasIpOptions())
        compiler->abort(rule, "Native nftables NAT IP option matching is not supported");

    // Inverting a conjunction would require De Morgan's transformation.
    // Silently ignoring service negation could widen the NAT translation.
    if (!result.str().empty() && rule->getOSrv()->getBool("single_object_negation"))
        compiler->abort(rule, "Negated native nftables NAT IP service match is not supported");

    return result.str();
}

string NATCompiler_nft::PrintRule::_printSrcPorts(Service *srv)
{
    std::ostringstream  ostr;
    if (TCPService::isA(srv) || UDPService::isA(srv)) {
	int rs=TCPUDPService::cast(srv)->getSrcRangeStart();
	int re=TCPUDPService::cast(srv)->getSrcRangeEnd();
	ostr << _printOPorts(rs,re);
    }
    return ostr.str();
}

string NATCompiler_nft::PrintRule::_printDstPorts(Service *srv)
{
    std::ostringstream  ostr;
    if (TCPService::isA(srv) || UDPService::isA(srv)) {
	int rs=TCPUDPService::cast(srv)->getDstRangeStart();
	int re=TCPUDPService::cast(srv)->getDstRangeEnd();
	ostr << _printOPorts(rs,re);
    }
    return ostr.str();
}

string NATCompiler_nft::PrintRule::_printSNATPorts(Service *srv)
{
    std::ostringstream  ostr;
    if (TCPService::isA(srv) || UDPService::isA(srv)) {
	int rs=TCPUDPService::cast(srv)->getSrcRangeStart();
	int re=TCPUDPService::cast(srv)->getSrcRangeEnd();
	ostr << _printTPorts(rs,re);
    }
    return ostr.str();
}

string NATCompiler_nft::PrintRule::_printDNATPorts(Service *srv)
{
    std::ostringstream  ostr;
    if (TCPService::isA(srv) || UDPService::isA(srv)) {
	int rs=TCPUDPService::cast(srv)->getDstRangeStart();
	int re=TCPUDPService::cast(srv)->getDstRangeEnd();
	ostr << _printTPorts(rs,re);
    }
    return ostr.str();
}

/*
 * we made sure that all services in rel  represent the same protocol
 */
string NATCompiler_nft::PrintRule::_printSrcService(RuleElementOSrv  *rel)
{
    std::ostringstream  ostr;

/* I do not want to use rel->getFirst because it traverses the tree to
 * find the object. I'd rather use a cached copy in the compiler
 */
    FWObject *o=rel->front();
    if (o && FWReference::cast(o)!=nullptr)
        o=FWReference::cast(o)->getPointer();

    Service *srv= Service::cast(o);

    if (rel->size()==1) {
        if (UDPService::isA(srv) || TCPService::isA(srv)) {
            string str=_printSrcPorts( srv );
            if (! str.empty() )
            {
                string proto = TCPService::isA(srv) ? "tcp" : "udp";
                ostr << proto << " sport " << str << " ";
            }
        }
    } else {
        string str;
        bool  first=true;
        for (FWObject::iterator i=rel->begin(); i!=rel->end(); i++) {
            FWObject *o= *i;
            if (FWReference::cast(o)!=nullptr) o=FWReference::cast(o)->getPointer();

            Service *s=Service::cast( o );
            assert(s);
            if (UDPService::isA(srv) || TCPService::isA(srv)) {
                if (!first) str+=",";
                str+= _printSrcPorts( s );
                if (!str.empty()) first=false;
            }
        }
        if ( !str.empty() )
        {
            string proto = TCPService::isA(srv) ? "tcp" : "udp";
            ostr << proto << " sport { " << str << " } ";
        }
    }
    return ostr.str();
}

string NATCompiler_nft::PrintRule::_printDstService(RuleElementOSrv  *rel)
{
    std::ostringstream  ostr;

    FWObject *o=rel->front();
    if (o && FWReference::cast(o)!=nullptr)
        o=FWReference::cast(o)->getPointer();

    Service *srv= Service::cast(o);

    if (rel->size()==1)
    {
        if (UDPService::isA(srv) || TCPService::isA(srv))
        {
            string str=_printDstPorts( srv );
            if (! str.empty() )
            {
                string proto = TCPService::isA(srv) ? "tcp" : "udp";
                ostr << proto << " dport " << str << " ";
            }
        }
        if (ICMPService::isA(srv) || ICMP6Service::isA(srv))
        {
            string str=_printICMP( ICMPService::cast(srv) );
            if (! str.empty() ) ostr << str << " ";
        }
        if (IPService::isA(srv))
        {
            string str=_printIP(IPService::cast(srv), NATRule::cast(rel->getParent()));
            if (! str.empty() ) ostr << str << " ";
        }
        if (CustomService::isA(srv))
        {
            ostr << CustomService::cast(srv)->getCodeForPlatform( compiler->myPlatformName() ) << " ";
        }
        if (TagService::isA(srv))
        {
            ostr << nft_utils::markMatchExpression(
                TagService::constcast(srv)->getCode(), false) << " ";
        }

    } else {
        string str;
        bool   first=true;
        for (FWObject::iterator i=rel->begin(); i!=rel->end(); i++)
        {
            FWObject *o= *i;
            if (FWReference::cast(o)!=nullptr) o=FWReference::cast(o)->getPointer();

            Service *s=Service::cast( o );
            assert(s);
            if (UDPService::isA(srv) || TCPService::isA(srv))
            {
                if (!first) str+=",";
                str+= _printDstPorts( s );
                if (!str.empty()) first=false;
            }
        }
        if ( !str.empty() )
        {
            string proto = TCPService::isA(srv) ? "tcp" : "udp";
            ostr << proto << " dport { " << str << " } ";
        }
    }
    return ostr.str();
}

string NATCompiler_nft::PrintRule::_printIpSetMatch(Address  *o, RuleElement *rel)
{
    NATCompiler_nft *ipt_comp=dynamic_cast<NATCompiler_nft*>(compiler);
    string set_name =
        dynamic_cast<OSConfigurator_linux24*>(ipt_comp->osconfigurator)->normalizeSetName(o->getName());
    string direction = "daddr";
    if (RuleElementOSrc::isA(rel)) direction = "saddr";
    if (RuleElementODst::isA(rel)) direction = "daddr";

    return nft_utils::setMatchExpression(
        ipt_comp->ipv6 ? "ip6" : "ip",
        direction,
        set_name,
        rel->getBool("single_object_negation")) + " ";
}

// Note print_mask is true by default, print_range is false by default.
string NATCompiler_nft::PrintRule::_printAddr(Address  *o,
                                              bool ,
                                              bool print_range)
{
    NATCompiler_nft *ipt_comp=dynamic_cast<NATCompiler_nft*>(compiler);
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
        // at this time we only support two types of MultiAddress
        // objects: AddressTable and DNSName. Both should be converted
        // to MultiAddressRunTime at this point. If we get some other
        // kind of MultiAddressRunTime object, we do not know what to do
        // with it so we stop.
        assert(atrt==nullptr);
    }

    if (print_range && AddressRange::cast(o)!=nullptr)
    {
	InetAddr a1 = AddressRange::cast(o)->getRangeStart();
	InetAddr a2 = AddressRange::cast(o)->getRangeEnd();
	ostr << a1.toString() << "-" << a2.toString();
    } else
    {
        Interface *iface = Interface::cast(o);
        if (iface!=nullptr && iface->isDyn() && iface->getBool("use_var_address"))
        {
            ostr << "$" << ipt_comp->getInterfaceVarName(iface, ipt_comp->ipv6)
                 << " ";
            return ostr.str();
        }

        const InetAddr* addr = o->getAddressPtr();
        const InetAddr* mask = o->getNetmaskPtr();

        if (addr==nullptr)
        {
            compiler->warning(
                    string("Empty inet address in object ") +
                    FWObjectDatabase::getStringId(o->getId()));
            return ostr.str();
        }

        if (addr->isAny() && mask->isAny())
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
            // do not add space after address because there might be
            // :port spec coming right after it.
        }
    }
    return ostr.str();
}

string NATCompiler_nft::PrintRule::_printSingleObjectNegation(
    RuleElement *rel)
{
    if (rel->getBool("single_object_negation"))   return "not ";
    else return "";
}

NATCompiler_nft::PrintRule::PrintRule(const std::string &name) :
    NATRuleProcessor(name)
{
    init = true;
    print_once_on_top = true;
    minus_n_tracker_initialized = false;
}

bool NATCompiler_nft::PrintRule::processNext()
{
    NATCompiler_nft *ipt_comp = dynamic_cast<NATCompiler_nft*>(compiler);
    NATRule *rule=getNext();
    if (rule==nullptr) return false;

    FWOptions *ropt = rule->getOptionsObject();

    string chain = rule->getStr("ipt_chain");
    if (ipt_comp->chain_usage_counter[chain] == 0)
    {
        return true;
    }

    tmp_queue.push_back(rule);

    compiler->output << _printRuleLabel(rule);

    string s;
    std::ostringstream  cmdout;

    compiler->output << _createChain(rule->getStr("ipt_chain"));
    compiler->output << _createChain(rule->getStr("ipt_target"));


    RuleElementOSrc *osrcrel = rule->getOSrc();
    Address  *osrc = compiler->getFirstOSrc(rule);  assert(osrc);
    RuleElementODst *odstrel = rule->getODst();
    Address  *odst = compiler->getFirstODst(rule);  assert(odst);
    RuleElementOSrv *osrvrel=rule->getOSrv();
    Service  *osrv = compiler->getFirstOSrv(rule);  assert(osrv);

    Address  *tsrc = compiler->getFirstTSrc(rule);  assert(tsrc);
    Address  *tdst = compiler->getFirstTDst(rule);  assert(tdst);
    Service  *tsrv = compiler->getFirstTSrv(rule);  assert(tsrv);

    cmdout << _startRuleLine();

    cmdout << _printChainDirectionAndInterface(rule);

    if (! osrv->isAny() )
	cmdout << _printProtocol(osrv);

    cmdout << _printMultiport(rule);

    if (!osrc->isAny())
    {
        string physaddress="";

        if (physAddress::isA(osrc))
            physaddress= physAddress::cast(osrc)->getPhysAddress();

        if (combinedAddress::isA(osrc))
            physaddress= combinedAddress::cast(osrc)->getPhysAddress();

        if ( ! physaddress.empty())
        {
	    cmdout << " ether saddr " << physaddress;
        }

        const InetAddr *osrc_addr = osrc->getAddressPtr();
        if (osrc_addr==nullptr || !osrc_addr->isAny())
        {
            MultiAddressRunTime *atrt = MultiAddressRunTime::cast(osrc);
            if (atrt!=nullptr && atrt->getSubstitutionTypeName()==AddressTable::TYPENAME &&
                ipt_comp->using_ipset)
            {
                cmdout << _printIpSetMatch(osrc, osrcrel);
            } else
            {
                string osrc_out = _printAddr(osrc);
                if (!osrc_out.empty())
                    cmdout << _printSingleOptionWithNegation(ipt_comp->ipv6 ? "ip6 saddr" : "ip saddr", osrcrel, osrc_out);
            }
        }

//	cmdout << " -s ";
//	cmdout << _printAddr(osrc);
    }

    if (!osrv->isAny())
    {
	cmdout << " ";
	cmdout << _printSrcService(osrvrel);
    }

    if (!odst->isAny())
    {
        MultiAddressRunTime *atrt = MultiAddressRunTime::cast(odst);
        if (atrt!=nullptr && atrt->getSubstitutionTypeName()==AddressTable::TYPENAME &&
            ipt_comp->using_ipset)
        {
            cmdout << _printIpSetMatch(odst, odstrel);
        } else
            cmdout << _printSingleOptionWithNegation(ipt_comp->ipv6 ? "ip6 daddr" : "ip daddr", odstrel, _printAddr(odst));
    }

    cmdout << " ";
    cmdout << _printDstService(osrvrel);

    // nftables verdict/translation syntax is not iptables -j syntax.
    // Unsupported translation modes must fail rather than generate
    // a deployable firewall policy with changed semantics.
    switch (rule->getRuleType())
    {
    case NATRule::Masq:
        cmdout << "masquerade ";
        break;
    case NATRule::SNAT:
        if (rule->getStr("ipt_target") != "SNAT")
            compiler->abort(rule, "Unsupported native nftables SNAT target");
        cmdout << "snat to ";
        break;
    case NATRule::DNAT:
        if (rule->getStr("ipt_target") != "DNAT")
            compiler->abort(rule, "Unsupported native nftables DNAT target");
        cmdout << "dnat to ";
        break;
    case NATRule::Redirect:
        cmdout << "redirect ";
        break;
    case NATRule::NATBranch:
        cmdout << "jump " << rule->getStr("ipt_target") << " ";
        break;
    default:
        compiler->abort(rule, "Unsupported native nftables NAT rule type");
        break;
    }


    switch (rule->getRuleType())
    {
    case NATRule::Masq:
        if (ropt->getBool("ipt_nat_random"))
            compiler->abort(rule, "Native nftables masquerade random option is not supported");
        break;

    case NATRule::SNAT:
	if (rule->getStr("ipt_target")=="SNAT")
        {
	    /* native "snat to" prefix already emitted */
            // if TSrc is "any" and this is SNAT rule, then this rule only
            // translates source port. Skip address part.
            // Note for #1693: _printAddr() returns string that ends with a space,
            // but there should be no space if the address is followed by port
            // spec.
            QString addr_part;
            if (!tsrc->isAny())
            {
                addr_part = _printAddr(tsrc, false, true).c_str();
            }
	    string ports = _printSNATPorts(tsrv);
	    if (!ports.empty())
            {
                // Without [] the port is parsed as the final IPv6 hextet.
                const bool ipv6 = !tsrc->isAny() && tsrc->hasInetAddress() &&
                                  tsrc->getAddressPtr()->isV6();
                cmdout << (ipv6 ? "[" : "")
                       << addr_part.trimmed().toStdString()
                       << (ipv6 ? "]" : "")
                       << ":" << ports;
            } else
                cmdout << addr_part.toStdString();

            if (ropt->getBool("ipt_nat_random") ||
                ropt->getBool("ipt_nat_persistent"))
                compiler->abort(rule, "Unsupported native nftables SNAT options");
	}
	break;
/*
 *  if rule type is DNAT and TDst is any, this rule only does port
 *  translation and does not change addresses. Iptables accepts
 *  "--to-destination :80" (no address in front of the ':') and seems
 *  to do the right thing.
 */
    case NATRule::DNAT:
	if (rule->getStr("ipt_target")=="DNAT")
        {
	    /* native "dnat to" prefix already emitted */
            // if TDst is "any" and this is DNAT rule, then this rule only
            // translates source port. Skip address part.
            QString addr_part;
            const string lb_map = rule->getStr("nft_lb_addr_map");
            if (!lb_map.empty())
            {
                // A port-translation suffix cannot safely be appended to
                // the generated address map. Fail closed, never drop ports.
                if (!_printDNATPorts(tsrv).empty())
                    compiler->abort(rule,
                        "Native nftables load-balancing address maps cannot translate ports");
                addr_part = lb_map.c_str();
            }
            else if (!tdst->isAny())
                addr_part = _printAddr(tdst, false, true).c_str();

	    string ports = _printDNATPorts(tsrv);
	    if (!ports.empty())
            {
                bool ipv6 = tdst->hasInetAddress() && tdst->getAddressPtr()->isV6();

                cmdout << (ipv6 ? "[" : "")
                       << addr_part.trimmed().toStdString()
                       << (ipv6 ? "]" : "")
                       << ":" << ports;
            } else
            {
                cmdout << addr_part.toStdString();
            }

            if (ropt->getBool("ipt_nat_random") ||
                ropt->getBool("ipt_nat_persistent"))
                compiler->abort(rule, "Unsupported native nftables DNAT options");
	}
	break;


    case NATRule::Redirect:
	if (rule->getStr("ipt_target")=="REDIRECT")
        {
	    string ports=_printDNATPorts(tsrv);
	    if (!ports.empty()) cmdout << "to :" << ports;
	}
	break;

    case NATRule::NATBranch:
	break;

    default:	break;
    }
    cmdout << " ";

    cmdout << _endRuleLine();

//    cmdout  << "\n";

    compiler->output
        << dynamic_cast<OSConfigurator_linux24*>(compiler->osconfigurator)->
        printRunTimeWrappers( rule, cmdout.str(), ipt_comp->ipv6);

    return true;
}

string NATCompiler_nft::PrintRule::_declareTable()
{
    return "";
}

string NATCompiler_nft::PrintRule::_commit()
{
    return "";
}


string NATCompiler_nft::PrintRule::_quote(const string &s)
{
    return "\"" + s + "\"";
}
