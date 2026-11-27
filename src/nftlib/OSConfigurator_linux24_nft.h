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

#ifndef _OSCONFIGURATOR_LINUX24_NFT_HH
#define _OSCONFIGURATOR_LINUX24_NFT_HH

#include "OSConfigurator_linux24.h"
#include "OSData_nft.h"

#include <map>

namespace fwcompiler {

    class OSConfigurator_linux24_nft : public OSConfigurator_linux24 {

        OSData_nft os_data;

        // shell variable name -> DNS name it was registered for
        std::map<std::string, std::string> run_time_dns_names;

        // W4.4: placeholder name ("rv_<name>") -> user shell variable
        // filled by the prolog at activation time
        std::map<std::string, std::string> run_time_rule_vars;

        std::string getPathForATool(const std::string &os_variant,
                                    OSData_nft::tools tool_name);

    public:
        OSConfigurator_linux24_nft(libfwbuilder::FWObjectDatabase *_db,
                                   libfwbuilder::Firewall *fw,
                                   bool ipv6_policy);

        virtual std::string printShellFunctions(bool have_ipv6);
        virtual std::string printPathForAllTools(const std::string &os);
        virtual std::string printRunTimeAddressTablesCode();

        virtual std::string printRunTimeWrappers(libfwbuilder::FWObject *rule,
                                                 const std::string &command,
                                                 bool ipv6);

        // Returns the stable shell variable name (without the "$") that
        // the activation script assigns one resolved address of a
        // run-time DNSName per loop iteration. Registering the same DNS
        // name again returns the original variable.
        std::string registerRunTimeDNSName(const std::string &hostname);

        // W4.4: registers a rule-level runtime shell variable (filled by
        // the user prolog, e.g. provider_ip from fwb_get_provider_ip)
        // and returns the sanitized placeholder name ("rv_<name>",
        // without the "$") the compiled rule text references. The
        // wrapper block binds that placeholder to the user variable at
        // activation time.
        std::string registerRunTimeRuleVar(const std::string &name);
        bool hasRunTimeRuleVars() const
        { return !run_time_rule_vars.empty(); }
    };
};

#endif
