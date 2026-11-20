/*

                          Firewall Builder

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

#ifndef __NFT_UTILS_HH__
#define __NFT_UTILS_HH__

#include <string>

namespace fwcompiler {
namespace nft_utils {

std::string commandPrefix(bool atomic_mode);
std::string familyName(bool ipv6);
// Only native nftables backend tables are managed by Firewall Builder.
std::string managedTableName(const std::string &logical_table);
std::string baseChainDefinition(const std::string &table,
                                const std::string &chain,
                                bool ipv6,
                                const std::string &policy);
std::string markMatchExpression(const std::string &mark, bool negated);
std::string markSetExpression(const std::string &mark);
// Save or restore a packet mark to/from conntrack; reject unsupported xt actions.
std::string connmarkActionExpression(const std::string &action);
std::string setMatchExpression(const std::string &family,
                               const std::string &direction,
                               const std::string &set_name,
                               bool negated);
std::string conntrackStateExpression(const std::string &states, bool negated);
std::string rejectWithExpression(const std::string &reject_with, bool ipv6);
std::string tcpFlagsExpression(const std::string &mask,
                               const std::string &comp);
// Native nftables expressions for formerly iptables-specific match options.
// Invalid values fail closed; callers report the error on the originating rule.
// Match the complete IPv4 TOS octet (including ECN bits), not only DSCP.
std::string tosMatchExpression(const std::string &code, bool ipv6);
std::string dscpMatchExpression(const std::string &code, bool ipv6);
std::string fragmentMatchExpression(bool ipv6);
std::string macSourceMatchExpression(const std::string &mac, bool negated);
// ICMP type/code are separate nftables payload expressions; each field
// requires its protocol prefix (icmp or icmpv6).
std::string icmpMatchExpression(int type, int code, bool ipv6);
std::string timeMatchExpression(const std::string &start_time,
                                const std::string &stop_time,
                                const std::string &days_of_week,
                                bool use_kernel_tz);

}
}

#endif
