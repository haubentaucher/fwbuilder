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

namespace fwcompiler {

    class OSConfigurator_linux24_nft : public OSConfigurator_linux24 {

        OSData_nft os_data;

        std::string getPathForATool(const std::string &os_variant,
                                    OSData_nft::tools tool_name);

    public:
        OSConfigurator_linux24_nft(libfwbuilder::FWObjectDatabase *_db,
                                   libfwbuilder::Firewall *fw,
                                   bool ipv6_policy);

        virtual std::string printShellFunctions(bool have_ipv6);
        virtual std::string printPathForAllTools(const std::string &os);
        virtual std::string printRunTimeAddressTablesCode();
    };
};

#endif
