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

#include "fwbuilder/Firewall.h"
#include "fwbuilder/Rule.h"
#include "fwbuilder/Resources.h"

#include <assert.h>

using namespace libfwbuilder;
using namespace fwcompiler;
using namespace std;



/**
 *-----------------------------------------------------------------------
 *                    Methods for printing
 */
/*
 *  check and create new chain if needed
 */
string NATCompiler_nft::PrintRuleIptRstEcho::_createChain(const string &chain)
{
    string res;
    NATCompiler_nft *ipt_comp = dynamic_cast<NATCompiler_nft*>(compiler);

    if (!minus_n_tracker_initialized) initializeMinusNTracker();

    if ( ipt_comp->minus_n_commands->count(chain)==0 )
    {
        if ( ! compiler->inSingleRuleCompileMode())
            res = "echo \":" + chain + " - [0:0]\"\n";
	(*(ipt_comp->minus_n_commands))[chain] = true;
    }
    return res;
}

string NATCompiler_nft::PrintRuleIptRstEcho::_startRuleLine()
{            
    return string("echo \"-A ");
}

string NATCompiler_nft::PrintRuleIptRstEcho::_endRuleLine()
{            
    return string("\"\n");
}

bool  NATCompiler_nft::PrintRuleIptRstEcho::processNext()
{
    if (print_once_on_top)
    {

        print_once_on_top=false;
    }

    return NATCompiler_nft::PrintRuleIptRst::processNext();
}

string NATCompiler_nft::PrintRuleIptRstEcho::_declareTable()
{
    ostringstream res;
    res << "echo '*nat'" << endl;
    return res.str();
}

string NATCompiler_nft::PrintRuleIptRstEcho::_commit()
{
    return "echo COMMIT\n";
}


string NATCompiler_nft::PrintRuleIptRstEcho::_quote(const string &s)
{
    return "\\\"" + s + "\\\"";
}

