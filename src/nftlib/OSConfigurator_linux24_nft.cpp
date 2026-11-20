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

#include "fwbuilder/Firewall.h"

#include "Configlet.h"
#include "fwbuilder/FWOptions.h"
#include "fwbuilder/Resources.h"

#include <QStringList>
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

    configlet.setVariable("load_modules", options->getBool("load_modules"));

    if (options->getBool("load_modules") ||
        options->getBool("configure_vlan_interfaces") ||
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
