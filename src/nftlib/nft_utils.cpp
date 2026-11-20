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

#include "nft_utils.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <stdexcept>
#include <sstream>
#include <vector>

namespace fwcompiler {
namespace nft_utils {

namespace {
std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::vector<std::string> split(const std::string &value, char sep)
{
    std::vector<std::string> parts;
    std::string current;
    for (char ch : value)
    {
        if (ch == sep)
        {
            if (!current.empty())
            {
                parts.push_back(current);
                current.clear();
            }
        } else
        {
            current.push_back(ch);
        }
    }
    if (!current.empty()) parts.push_back(current);
    return parts;
}
}

std::string icmpMatchExpression(int type, int code, bool ipv6)
{
    if (type == -1 && code == -1) return "";
    if (type < 0 || type > 255 || code < -1 || code > 255)
        throw std::invalid_argument("ICMP type/code must be in 0..255; code requires a type");

    const char *protocol = ipv6 ? "icmpv6" : "icmp";
    std::ostringstream result;
    result << protocol << " type " << type;
    if (code >= 0)
        result << " " << protocol << " code " << code;
    return result.str();
}

std::string commandPrefix(bool atomic_mode)
{
    return atomic_mode ? std::string() : std::string("$NFT ");
}

std::string familyName(bool ipv6)
{
    return ipv6 ? "ip6" : "ip";
}

std::string managedTableName(const std::string &logical_table)
{
    if (logical_table == "filter" || logical_table == "nat" ||
        logical_table == "mangle")
        return "fwb_" + logical_table;
    return logical_table;
}

std::string baseChainDefinition(const std::string &table,
                                const std::string &chain,
                                bool ipv6,
                                const std::string &policy)
{
    static const std::map<std::string, std::map<std::string, std::string>> hooks = {
        {"filter",
         { {"INPUT", "type filter hook input priority 0"},
           {"FORWARD", "type filter hook forward priority 0"},
           {"OUTPUT", "type filter hook output priority 0"} }},
        {"mangle",
         { {"PREROUTING", "type filter hook prerouting priority -150"},
           {"INPUT", "type filter hook input priority -150"},
           {"FORWARD", "type filter hook forward priority -150"},
           {"OUTPUT", "type filter hook output priority -150"},
           {"POSTROUTING", "type filter hook postrouting priority -150"} }},
        {"nat",
         { {"PREROUTING", "type nat hook prerouting priority -100"},
           {"INPUT", "type nat hook input priority -100"},
           {"OUTPUT", "type nat hook output priority -100"},
           {"POSTROUTING", "type nat hook postrouting priority 100"} }}
    };

    auto table_it = hooks.find(table);
    if (table_it == hooks.end()) return "";

    auto chain_it = table_it->second.find(chain);
    if (chain_it == table_it->second.end()) return "";

    std::ostringstream output;
    output << "add chain " << familyName(ipv6) << " " << managedTableName(table) << " " << chain
           << " { " << chain_it->second;
    if (!policy.empty()) output << "; policy " << policy;
    output << "; }";
    return output.str();
}

std::string markMatchExpression(const std::string &mark, bool negated)
{
    auto parts = split(mark, '/');
    std::ostringstream output;
    output << "meta mark";
    if (parts.size() == 2)
    {
        output << " & " << parts[1] << (negated ? " != " : " == ") << parts[0];
    } else
    {
        output << (negated ? " != " : " == ") << mark;
    }
    return output.str();
}

std::string markSetExpression(const std::string &mark)
{
    return "meta mark set " + mark;
}

std::string connmarkActionExpression(const std::string &action)
{
    if (action == "--save-mark") return "ct mark set meta mark";
    if (action == "--restore-mark") return "meta mark set ct mark";
    throw std::invalid_argument("unsupported CONNMARK action");
}

std::string setMatchExpression(const std::string &family,
                               const std::string &direction,
                               const std::string &set_name,
                               bool negated)
{
    std::ostringstream output;
    output << family << " " << direction;
    if (negated) output << " != "; else output << " ";
    output << "@" << set_name;
    return output.str();
}

std::string conntrackStateExpression(const std::string &states, bool negated)
{
    std::string normalized = toLower(states);
    std::replace(normalized.begin(), normalized.end(), ',', ' ');
    std::ostringstream output;
    output << "ct state";
    if (negated) output << " != "; else output << " { ";
    if (negated)
        output << normalized;
    else
        output << normalized << " }";
    return output.str();
}

std::string rejectWithExpression(const std::string &reject_with, bool ipv6)
{
    static const std::map<std::string, std::string> map = {
        {"tcp-reset", "reject with tcp reset"},
        {"icmp-net-unreachable", "reject with icmp type net-unreachable"},
        {"icmp-host-unreachable", "reject with icmp type host-unreachable"},
        {"icmp-port-unreachable", "reject with icmp type port-unreachable"},
        {"icmp-proto-unreachable", "reject with icmp type protocol-unreachable"},
        {"icmp-net-prohibited", "reject with icmp type net-prohibited"},
        {"icmp-host-prohibited", "reject with icmp type host-prohibited"},
        {"icmp-admin-prohibited", "reject with icmp type admin-prohibited"},
        {"icmp6-addr-unreachable", "reject with icmpv6 type addr-unreachable"},
        {"icmp6-port-unreachable", "reject with icmpv6 type port-unreachable"},
        {"icmp6-adm-prohibited", "reject with icmpv6 type admin-prohibited"}
    };

    auto it = map.find(reject_with);
    if (it != map.end()) return it->second;

    if (ipv6)
        return "reject with icmpv6 type admin-prohibited";

    return "reject with icmp type admin-prohibited";
}

std::string tcpFlagsExpression(const std::string &mask, const std::string &comp)
{
    auto mask_parts = split(toLower(mask), ',');
    auto comp_parts = split(toLower(comp), ',');

    if (mask_parts.empty() || comp_parts.empty()) return "";

    std::ostringstream mask_stream;
    for (size_t i = 0; i < mask_parts.size(); ++i)
    {
        if (i > 0) mask_stream << "|";
        mask_stream << mask_parts[i];
    }

    std::ostringstream comp_stream;
    for (size_t i = 0; i < comp_parts.size(); ++i)
    {
        if (i > 0) comp_stream << "|";
        comp_stream << comp_parts[i];
    }

    std::ostringstream output;
    output << "tcp flags & (" << mask_stream.str() << ") == "
           << comp_stream.str();
    return output.str();
}

std::string tosMatchExpression(const std::string &code, bool ipv6)
{
    // IPv4 TOS is the full 8-bit octet: DSCP (6 bits) plus ECN (2 bits).
    // nft has no "ip tos" token. IPv4 byte 1 is at @nh bit offset 8;
    // raw payload matching preserves DSCP and ECN in one 8-bit equality.
    // The caller is an IPv4-only nftables rule; raw payloads do not
    // automatically constrain network family.
    if (ipv6) throw std::invalid_argument("IPv4 TOS match on IPv6 policy");
    if (code.empty()) throw std::invalid_argument("empty IPv4 TOS value");

    size_t pos = 0;
    unsigned int base = 10;
    if (code.size() > 2 && code[0] == '0' &&
        (code[1] == 'x' || code[1] == 'X'))
    {
        pos = 2;
        base = 16;
    }
    if (pos == code.size()) throw std::invalid_argument("empty IPv4 TOS hex value");

    unsigned int value = 0;
    for (; pos < code.size(); ++pos)
    {
        const char ch = code[pos];
        const int digit = ch >= '0' && ch <= '9' ? ch - '0' :
            base == 16 && ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 :
            base == 16 && ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
        if (digit < 0 || static_cast<unsigned int>(digit) >= base)
            throw std::invalid_argument("invalid IPv4 TOS value");
        value = value * base + static_cast<unsigned int>(digit);
        if (value > 255) throw std::invalid_argument("IPv4 TOS outside 0..255");
    }

    std::ostringstream output;
    output << "@nh,8,8 0x" << std::hex << std::setw(2) << std::setfill('0')
           << value;
    return output.str();
}

std::string dscpMatchExpression(const std::string &code, bool ipv6)
{
    std::string value = toLower(code);
    // The iptables DSCP module accepts BE; nftables names this CS0.
    if (value == "be") value = "cs0";
    bool recognized = value == "ef" ||
        (value.size() == 3 && value.substr(0, 2) == "cs" &&
         value[2] >= '0' && value[2] <= '7') ||
        (value.size() == 4 && value.substr(0, 2) == "af" &&
         value[2] >= '1' && value[2] <= '4' &&
         value[3] >= '1' && value[3] <= '3');
    if (!recognized && !value.empty())
    {
        // Numeric DSCP must be exactly 0..63; reject whitespace, signs,
        // punctuation and strings that would alter the nftables grammar.
        size_t i = 0;
        int base = 10;
        if (value.size() > 2 && value.substr(0, 2) == "0x")
        {
            i = 2;
            base = 16;
        }
        if (i == value.size()) throw std::invalid_argument("empty DSCP value");
        unsigned int number = 0;
        for (; i < value.size(); ++i)
        {
            char ch = value[i];
            int digit = (ch >= '0' && ch <= '9') ? ch - '0' :
                        (base == 16 && ch >= 'a' && ch <= 'f') ? ch - 'a' + 10 : -1;
            if (digit < 0 || digit >= base) throw std::invalid_argument("invalid DSCP value");
            number = number * base + static_cast<unsigned int>(digit);
            if (number > 63) throw std::invalid_argument("DSCP value outside 0..63");
        }
        recognized = true;
    }
    if (!recognized) throw std::invalid_argument("empty DSCP value");
    return std::string(ipv6 ? "ip6 dscp " : "ip dscp ") + value;
}

std::string fragmentMatchExpression(bool ipv6)
{
    // iptables -f means a noninitial IPv4 fragment. The IPv6 legacy
    // --fragmore option tests the IPv6 fragment-header M flag.
    return ipv6 ? "frag more-fragments 1" : "ip frag-off & 0x1fff != 0";
}

std::string macSourceMatchExpression(const std::string &mac, bool negated)
{
    if (mac.size() != 17) throw std::invalid_argument("invalid MAC address length");
    for (size_t i = 0; i < mac.size(); ++i)
    {
        if (i % 3 == 2)
        {
            if (mac[i] != ':') throw std::invalid_argument("invalid MAC separator");
        } else if (!std::isxdigit(static_cast<unsigned char>(mac[i])))
        {
            throw std::invalid_argument("invalid MAC octet");
        }
    }
    return std::string("ether saddr") + (negated ? " != " : " ") + mac;
}

std::string timeMatchExpression(const std::string &start_time,
                                const std::string &stop_time,
                                const std::string &days_of_week,
                                bool use_kernel_tz)
{
    // nftables meta hour is not the xt_time --kerneltz option. Never
    // quietly change the caller's requested timezone semantics.
    if (use_kernel_tz)
        throw std::invalid_argument("xt_time kernel timezone mode is not supported by native nftables");

    if (start_time.empty() != stop_time.empty())
        throw std::invalid_argument("incomplete time interval");

    auto minutesOfDay = [](const std::string &value) -> int {
        if (value.size() != 5 || value[2] != ':' ||
            !std::isdigit(static_cast<unsigned char>(value[0])) ||
            !std::isdigit(static_cast<unsigned char>(value[1])) ||
            !std::isdigit(static_cast<unsigned char>(value[3])) ||
            !std::isdigit(static_cast<unsigned char>(value[4])))
            throw std::invalid_argument("invalid HH:MM time");
        int hour = (value[0] - '0') * 10 + (value[1] - '0');
        int minute = (value[3] - '0') * 10 + (value[4] - '0');
        if (hour > 23 || minute > 59)
            throw std::invalid_argument("time outside 00:00..23:59");
        return hour * 60 + minute;
    };

    std::ostringstream output;
    if (!start_time.empty())
    {
        if (minutesOfDay(start_time) > minutesOfDay(stop_time))
            throw std::invalid_argument("overnight time interval requires explicit splitting");
        output << "meta hour \"" << start_time << "\"-\"" << stop_time << "\"";
    }

    if (!days_of_week.empty())
    {
        // FWB Interval stores Sunday as 0 (or 7). nftables meta day uses
        // 0..6 with 0 = Sunday. Parse numeric tokens, never inject raw text.
        const std::vector<std::string> days = split(days_of_week, ',');
        if (days.empty() || days_of_week.front() == ',' ||
            days_of_week.back() == ',' || days_of_week.find(",,") != std::string::npos)
            throw std::invalid_argument("empty weekday in interval");
        if (!output.str().empty()) output << ' ';
        output << "meta day { ";
        for (size_t i = 0; i < days.size(); ++i)
        {
            if (days[i].size() != 1 || days[i][0] < '0' || days[i][0] > '7')
                throw std::invalid_argument("invalid numeric weekday");
            if (i) output << ", ";
            output << (days[i] == "7" ? "0" : days[i]);
        }
        output << " }";
    }
    return output.str();
}

}
}
