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

#include "OSData_nft.h"

using namespace std;

OSData_nft::OSData_nft(const std::string &ho)
{
    host_os = ho;

    attribute_names[LSMOD] = "path_lsmod";
    attribute_names[MODPROBE] = "path_modprobe";
    attribute_names[NFT] = "nftables_path";
    attribute_names[IP] = "path_ip";
    attribute_names[IFCONFIG] = "path_ifconfig";
    attribute_names[VCONFIG] = "path_vconfig";
    attribute_names[BRCTL] = "path_brctl";
    attribute_names[IFENSLAVE] = "path_ifenslave";
    attribute_names[IPSET] = "path_ipset";
    attribute_names[LOGGER] = "path_logger";

    variable_names[LSMOD] = "LSMOD";
    variable_names[MODPROBE] = "MODPROBE";
    variable_names[NFT] = "NFT";
    variable_names[IP] = "IP";
    variable_names[IFCONFIG] = "IFCONFIG";
    variable_names[VCONFIG] = "VCONFIG";
    variable_names[BRCTL] = "BRCTL";
    variable_names[IFENSLAVE] = "IFENSLAVE";
    variable_names[IPSET] = "IPSET";
    variable_names[LOGGER] = "LOGGER";

    all_tools.push_back(LSMOD);
    all_tools.push_back(MODPROBE);
    all_tools.push_back(NFT);
    all_tools.push_back(IP);
    all_tools.push_back(IFCONFIG);
    all_tools.push_back(VCONFIG);
    all_tools.push_back(BRCTL);
    all_tools.push_back(IFENSLAVE);
    all_tools.push_back(IPSET);
    all_tools.push_back(LOGGER);
}
