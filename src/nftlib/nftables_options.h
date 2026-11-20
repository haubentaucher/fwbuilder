/*

                          Firewall Builder

                 Copyright (C) 2024 NetCitadel, LLC

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

#ifndef _NFTABLES_OPTIONS_HH
#define _NFTABLES_OPTIONS_HH

#include "fwbuilder/FWOptions.h"

namespace fwcompiler {

inline bool useNftablesAtomic(const libfwbuilder::FWOptions *options)
{
    if (options == nullptr) return false;
    return options->getBool("use_nftables_atomic") ||
        options->getBool("use_iptables_restore");
}

}

#endif
