/* 

                          Firewall Builder

                 Copyright (C) 2009 NetCitadel, LLC

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


#include <fstream>
#include <iostream>
#include <algorithm>
#include <functional>
#include <stdexcept>

#include <ctype.h>
#include <cctype>
#include <assert.h>
#include <cstring>
#include <iomanip>
#include <future>
#include <memory>
#include <mutex>
#include <vector>

#include "../../config.h"
#include "CompilerDriver_nft.h"
#include "PolicyCompiler_nft.h"
#include "NATCompiler_nft.h"
#include "MangleTableCompiler_nft.h"
#include "RoutingCompiler_nft.h"
#include "Preprocessor_ipt.h"
#include "OSConfigurator_linux24.h"
#include "OSConfigurator_linux24_nft.h"
#include "OSConfigurator_secuwall.h"
#include "OSConfigurator_ipcop.h"
#include "nftables_options.h"
#include "combinedAddress.h"
#include "AutomaticRules_ipt.h"

#include "Configlet.h"
#include "CentralHooks.h"


#include "fwbuilder/FWObjectDatabase.h"
#include "fwbuilder/FWException.h"
#include "fwbuilder/Cluster.h"
#include "fwbuilder/ClusterGroup.h"
#include "fwbuilder/Firewall.h"
#include "fwbuilder/Interface.h"
#include "fwbuilder/Policy.h"
#include "fwbuilder/NAT.h"
#include "fwbuilder/Routing.h"
#include "fwbuilder/IPv4.h"
#include "fwbuilder/IPv6.h"
#include "fwbuilder/Resources.h"
#include "fwbuilder/StateSyncClusterGroup.h"
#include "fwbuilder/FailoverClusterGroup.h"
#include "fwbuilder/Library.h"
#include "fwbuilder/Constants.h"

#include <QString>
#include <QStringList>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QTextStream>
#include <QIODevice>
#include <QtDebug>
#include <QTime>

#ifdef _WIN64
#define tzname _tzname
#endif

using namespace std;
using namespace libfwbuilder;
using namespace fwcompiler;

extern QString user_name;

namespace
{
    std::string buildAutomaticMangleRules(
        libfwbuilder::FWObjectDatabase *objdb,
        libfwbuilder::Firewall *fw,
        libfwbuilder::Library *persistent_objects,
        bool ipv6_policy,
        fwcompiler::OSConfigurator_linux24 *oscnf,
        std::map<const std::string, bool> &minus_n_commands_mangle,
        const std::string &single_rule_id,
        int dl,
        bool rule_debug_on,
        int drp,
        int verbose,
        bool have_dynamic_interfaces,
        bool in_test_mode,
        bool in_embedded_mode,
        bool have_connmark,
        bool have_connmark_in_output,
        std::vector<std::string> &errors)
    {
        std::unique_ptr<MangleTableCompiler_nft> mangle_compiler(
            new MangleTableCompiler_nft(
                objdb, fw, ipv6_policy, oscnf, &minus_n_commands_mangle));

        mangle_compiler->setSingleRuleCompileMode(single_rule_id);
        mangle_compiler->setDebugLevel(dl);
        if (rule_debug_on) mangle_compiler->setDebugRule(drp);
        mangle_compiler->setVerbose((bool)(verbose));
        mangle_compiler->setHaveDynamicInterfaces(have_dynamic_interfaces);
        if (in_test_mode) mangle_compiler->setTestMode();
        if (in_embedded_mode) mangle_compiler->setEmbeddedMode();
        if (persistent_objects != nullptr)
            mangle_compiler->setPersistentObjects(persistent_objects);

        std::string automatic_rules =
            mangle_compiler->printAutomaticRulesForMangleTable(
                have_connmark, have_connmark_in_output);

        if (mangle_compiler->haveErrorsAndWarnings())
        {
            errors.push_back(mangle_compiler->getErrors(""));
            mangle_compiler->clearErrors();
        }

        return automatic_rules;
    }
}

static FWObject* create_combinedAddress(int id)
{
    FWObject *nobj = new combinedAddress();
    if (id > -1) nobj->setId(id);
    return nobj;
}


/*
 * Go through paces to compile firewall which may be a member of a
 * cluster.  Note that both firewall and cluster are defined by their
 * unique string IDs.  This is necessary because CompilerDriver
 * operates with a copy of the object database which is not exposed
 * outside, so the caller can not provide pointers to these obejcts.
 */
QString CompilerDriver_nft::run(const std::string &cluster_id,
                                const std::string &firewall_id,
                                const std::string &single_rule_id)
{

    FWObjectDatabase::registerObjectType(combinedAddress::TYPENAME,
                                         &create_combinedAddress);

    // see #2212 Create temporary copy of the firewall and cluster
    // objects and pass them to the compilers.

    Cluster *cluster = nullptr;
    Firewall *fw = nullptr;

    getFirewallAndClusterObjects(cluster_id, firewall_id, &cluster, &fw);

    string generated_script;

    try
    {
        clearReadOnly(fw);

        // Copy rules from the cluster object
        populateClusterElements(cluster, fw);

        commonChecks2(cluster, fw);

        string fw_version = fw->getStr("version");
        if (fw_version.empty()) fw_version = "(any version)";
        string platform = fw->getStr("platform");
        string host_os = fw->getStr("host_OS");

        FWOptions* options = fw->getOptionsObject();
        if (options->getBool("use_iptables_restore") &&
            !options->getBool("use_nftables_atomic"))
        {
            options->setBool("use_nftables_atomic", true);
        }
        // Standalone $NFT commands do not yet initialize native base chains
        // or load IPv4 and IPv6 together.  Refuse that mode instead of
        // generating a script that may start without its firewall policy.
        if (!useNftablesAtomic(options))
            abort("Native nftables requires atomic mode; non-atomic shell "
                  "mode is not supported");
        string s;

        // Note that fwobjectname may be different from the name of the
        // firewall fw This happens when we compile a member of a cluster
        current_firewall_name = fw->getName().c_str();

        if (fw->getOptionsObject()->getStr("prolog_place") == "after_flush" &&
            useNftablesAtomic(fw->getOptionsObject()))
        {
            abort("Prolog place \"after policy reset\" can not be used"
                  " when policy is activated with nftables in atomic mode");
        }

        string firewall_dir = options->getStr("firewall_dir");
        if (firewall_dir=="") firewall_dir="/etc";

        bool debug=options->getBool("debug");
        QString shell_dbg = (debug)?"set -x":"" ;

        std::unique_ptr<OSConfigurator_linux24> oscnf;

        string platform_family = Resources::platform_res[platform]->
            getResourceStr("/FWBuilderResources/Target/family");
        string os_family = Resources::os_res[host_os]->
            getResourceStr("/FWBuilderResources/Target/family");

        bool supports_prolog_epilog = Resources::getTargetCapabilityBool(
            platform, "supports_prolog_epilog");

        if (!supports_prolog_epilog)
        {
            prolog_done = true;
            epilog_done = true;
        }

        string os_variant = Constants::getDistro();

/* minimal sanity checking */
        if (os_family == "ipcop")
        {
            os_variant = "ipcop";

            oscnf = std::unique_ptr<OSConfigurator_linux24>(
                new OSConfigurator_linux24_nft(objdb , fw, false));
        }

        if (os_family == "linux24" ||
            os_family == "linux317" ||
            os_family == "openwrt" ||
            os_family == "dd-wrt-nvram" ||
            os_family == "dd-wrt-jffs" ||
            os_family == "sveasoft")
            oscnf = std::unique_ptr<OSConfigurator_linux24>(
                new OSConfigurator_linux24_nft(objdb , fw, false));

        if (os_family == "secuwall")
            oscnf = std::unique_ptr<OSConfigurator_linux24>(
                new OSConfigurator_linux24_nft(objdb , fw, false));

        if (oscnf.get()==nullptr)
        {
            abort("Unrecognized host OS " + fw->getStr("host_OS") +
                  "  (family " + os_family+")");
            return "";
        }

        if (inTestMode()) oscnf->setTestMode();
        if (inEmbeddedMode()) oscnf->setEmbeddedMode();

        oscnf->validateInterfaces();
        oscnf->prolog();

        list<FWObject*> all_policies = fw->getByType(Policy::TYPENAME);
        list<FWObject*> all_nat = fw->getByType(NAT::TYPENAME);

        int routing_rules_count = 0;
        bool have_ipv4 = false;
        bool have_ipv6 = false;

        // track chains in each table separately. Can we have the same
        // chain in filter and mangle tables ? Would it be the same
        // chain, i.e. do we need to create it only once or do we create
        // it twice, in each table separately ? 
        // Using separate trackers we track and create chain in each
        // table separately.
        std::map<const std::string, bool> minus_n_commands_filter;
        std::map<const std::string, bool> minus_n_commands_mangle;
        std::map<const std::string, bool> minus_n_commands_nat;

        vector<int> ipv4_6_runs;
        bool enable_parallel_compilation =
            options->getBool("enable_parallel_compilation");
        std::mutex compilation_mutex;

        findImportedRuleSets(fw, all_policies);
        findBranchesInMangleTable(fw, all_policies);
        findImportedRuleSets(fw, all_nat);

        try
        {
            AutomaticRules_ipt auto_rules(fw, persistent_objects);
            auto_rules.addConntrackRule();
            auto_rules.addFailoverRules();
        } catch (FWException &ex)
        {
            abort(ex.toString());
        }

        // assign unique rule ids that later will be used to generate
        // chain names.  This should be done after calls to
        // findImportedRuleSets()

        assignUniqueRuleIds(all_policies);
        assignUniqueRuleIds(all_nat);

        // command line options -4 and -6 control address family for which
        // script will be generated. If "-4" is used, only ipv4 part will 
        // be generated. If "-6" is used, only ipv6 part will be generated.
        // If neither is used, both parts will be done.

        if (options->getStr("ipv4_6_order").empty() ||
            options->getStr("ipv4_6_order") == "ipv4_first")
        {
            if (ipv4_run) ipv4_6_runs.push_back(AF_INET);
            if (ipv6_run) ipv4_6_runs.push_back(AF_INET6);
        }

        if (options->getStr("ipv4_6_order") == "ipv6_first")
        {
            if (ipv6_run) ipv4_6_runs.push_back(AF_INET6);
            if (ipv4_run) ipv4_6_runs.push_back(AF_INET);
        }

        for (vector<int>::iterator i=ipv4_6_runs.begin(); i!=ipv4_6_runs.end(); ++i)
        {
            int policy_af = *i;
            bool ipv6_policy = (policy_af == AF_INET6);

            /*
              clear chain tracker map only between ipv4/ipv6 runs
              Don't clear it between compiler runs for different
              policy or nat objects for the same address family.
            */
            minus_n_commands_filter.clear();
            minus_n_commands_mangle.clear();
            minus_n_commands_nat.clear();

            /*
              We need to create and run preprocessor for this address
              family before nat and policy compilers, but if there are
              no nat / policy rules for this address family, we do not
              need preprocessor either.
            */

            // Count rules for each address family
            int nat_count = 0;
            int policy_count = 0;

            for (list<FWObject*>::iterator p=all_nat.begin();
                 p!=all_nat.end(); ++p)
            {
                NAT *nat = NAT::cast(*p);
                if (nat->matchingAddressFamily(policy_af)) nat_count++;
            }

            for (list<FWObject*>::iterator p=all_policies.begin();
                 p!=all_policies.end(); ++p)
            {
                Policy *policy = Policy::cast(*p);
                if (policy->matchingAddressFamily(policy_af)) policy_count++;
            }

            if (nat_count || policy_count)
            {
                Preprocessor_ipt* prep = new Preprocessor_ipt(
                    objdb , fw, ipv6_policy);
                prep->setSingleRuleCompileMode(single_rule_id);
                if (inTestMode()) prep->setTestMode();
                if (inEmbeddedMode()) prep->setEmbeddedMode();
                prep->compile();
                delete prep;
            }

            ostringstream automaitc_rules_stream;
            ostringstream automaitc_mangle_stream;
            ostringstream filter_rules_stream;
            ostringstream mangle_rules_stream;
            ostringstream nat_rules_stream;

            bool empty_output = true;
            bool have_connmark = false;
            bool have_connmark_in_output = false;
            bool have_top_policy = false;

            // First, process branch NAT rulesets, then top NAT ruleset

            NAT *top_nat = nullptr;
            vector<NAT*> nat_rulesets;
            nat_rulesets.reserve(all_nat.size());
            for (list<FWObject*>::iterator p=all_nat.begin();
                 p!=all_nat.end(); ++p)
            {
                NAT *nat = NAT::cast(*p);
                if (!nat->matchingAddressFamily(policy_af)) continue;
                if (nat->isTop())
                {
                    top_nat = nat;
                    continue;
                }
                nat_rulesets.push_back(nat);
            }
            if (top_nat) nat_rulesets.push_back(top_nat);

            vector<CompilerDriver_nft::NatRuleSetResult> nat_results;
            nat_results.resize(nat_rulesets.size());
            if (enable_parallel_compilation && nat_rulesets.size() > 1)
            {
                vector<std::future<CompilerDriver_nft::NatRuleSetResult>> futures;
                futures.reserve(nat_rulesets.size());
                for (size_t idx = 0; idx < nat_rulesets.size(); ++idx)
                {
                    NAT *nat = nat_rulesets[idx];
                    futures.push_back(std::async(std::launch::async, [&, nat]() {
                        std::lock_guard<std::mutex> lock(compilation_mutex);
                        return processNatRuleSet(
                            fw,
                            nat,
                            single_rule_id,
                            oscnf.get(),
                            policy_af,
                            minus_n_commands_nat);
                    }));
                }
                for (size_t idx = 0; idx < futures.size(); ++idx)
                    nat_results[idx] = futures[idx].get();
            } else
            {
                for (size_t idx = 0; idx < nat_rulesets.size(); ++idx)
                {
                    nat_results[idx] = processNatRuleSet(
                        fw,
                        nat_rulesets[idx],
                        single_rule_id,
                        oscnf.get(),
                        policy_af,
                        minus_n_commands_nat);
                }
            }

            for (size_t idx = 0; idx < nat_results.size(); ++idx)
            {
                const CompilerDriver_nft::NatRuleSetResult &result =
                    nat_results[idx];
                if (!result.nat_rules.empty())
                    nat_rules_stream << result.nat_rules;
                if (!result.empty_output) empty_output = false;
                if (result.nat_rules_count > 0) have_nat = true;
                if (result.has_mapping_update)
                {
                    branch_ruleset_to_chain_mapping[result.branch_name] =
                        result.used_chains;
                }
                for (size_t e = 0; e < result.errors.size(); ++e)
                    all_errors.push_back(result.errors[e].c_str());
            }

            // first process all non-top rule sets, then all top rule sets
            vector<Policy*> policy_rulesets;
            policy_rulesets.reserve(all_policies.size());
            for (int all_top = 0; all_top < 2; ++all_top)
            {
                for (list<FWObject*>::iterator p=all_policies.begin();
                     p!=all_policies.end(); ++p )
                {
                    Policy *policy = Policy::cast(*p);
                    if (!policy->matchingAddressFamily(policy_af)) continue;

                    if (policy->isTop() && all_top == 0) continue;
                    if (!policy->isTop() && all_top == 1) continue;

                    policy_rulesets.push_back(policy);
                }
            }

            vector<CompilerDriver_nft::PolicyRuleSetResult> policy_results;
            policy_results.resize(policy_rulesets.size());
            if (enable_parallel_compilation && policy_rulesets.size() > 1)
            {
                vector<std::future<CompilerDriver_nft::PolicyRuleSetResult>> futures;
                futures.reserve(policy_rulesets.size());
                for (size_t idx = 0; idx < policy_rulesets.size(); ++idx)
                {
                    Policy *policy = policy_rulesets[idx];
                    futures.push_back(std::async(std::launch::async, [&, policy]() {
                        std::lock_guard<std::mutex> lock(compilation_mutex);
                        return processPolicyRuleSet(
                            fw,
                            policy,
                            single_rule_id,
                            oscnf.get(),
                            policy_af,
                            minus_n_commands_filter,
                            minus_n_commands_mangle);
                    }));
                }
                for (size_t idx = 0; idx < futures.size(); ++idx)
                    policy_results[idx] = futures[idx].get();
            } else
            {
                for (size_t idx = 0; idx < policy_rulesets.size(); ++idx)
                {
                    policy_results[idx] = processPolicyRuleSet(
                        fw,
                        policy_rulesets[idx],
                        single_rule_id,
                        oscnf.get(),
                        policy_af,
                        minus_n_commands_filter,
                        minus_n_commands_mangle);
                }
            }

            for (size_t idx = 0; idx < policy_results.size(); ++idx)
            {
                const CompilerDriver_nft::PolicyRuleSetResult &result =
                    policy_results[idx];

                have_connmark |= result.have_connmark;
                have_connmark_in_output |= result.have_connmark_in_output;
                if (result.is_top) have_top_policy = true;

                if (!result.mangle_rules.empty())
                    mangle_rules_stream << result.mangle_rules;
                if (!result.filter_rules.empty())
                    filter_rules_stream << result.filter_rules;
                if (!result.automatic_filter_rules.empty() &&
                    automaitc_rules_stream.tellp() <= 0)
                {
                    automaitc_rules_stream << result.automatic_filter_rules;
                }
                if (!result.empty_output) empty_output = false;
                for (size_t e = 0; e < result.errors.size(); ++e)
                    all_errors.push_back(result.errors[e].c_str());
            }

            if (have_top_policy && automaitc_mangle_stream.tellp() <= 0)
            {
                std::vector<std::string> mangle_errors;
                std::string auto_mangle_rules = buildAutomaticMangleRules(
                    objdb,
                    fw,
                    persistent_objects,
                    ipv6_policy,
                    oscnf.get(),
                    minus_n_commands_mangle,
                    single_rule_id,
                    dl,
                    rule_debug_on,
                    drp,
                    verbose,
                    have_dynamic_interfaces,
                    inTestMode(),
                    inEmbeddedMode(),
                    have_connmark,
                    have_connmark_in_output,
                    mangle_errors);

                if (!auto_mangle_rules.empty())
                {
                    if (!single_rule_compile_on)
                    {
                        automaitc_mangle_stream
                            << "# ================ Table 'mangle', "
                            << "automatic rules\n";
                    }
                    automaitc_mangle_stream << auto_mangle_rules;
                }
                for (size_t e = 0; e < mangle_errors.size(); ++e)
                    all_errors.push_back(mangle_errors[e].c_str());
            }

            if (!empty_output && !single_rule_compile_on)
            {
                if (ipv6_policy)
                {
                    have_ipv6 = true;
                    generated_script += "\n\n";
                    generated_script += "# ================ IPv6\n";
                    generated_script += "\n\n";
                } else
                {
                    have_ipv4 = true;
                    generated_script += "\n\n";
                    generated_script += "# ================ IPv4\n";
                    generated_script += "\n\n";
                }
            }

            // Hashlimit dynamic sets must be declared exactly once for each
            // managed nftables table, before any rule can use update @set.
            // Keep declarations out of per-rule runtime wrappers: those
            // wrappers are intended for executable rules, not nft objects.
            // The maps are scoped to this address-family run and shared
            // across all policy rulesets for the corresponding table.
            auto nftSetDeclarations = [](const std::map<const std::string, bool> &tracker) {
                const std::string prefix = "__fwb_nft_setdef:";
                std::string declarations;
                for (const auto &entry : tracker)
                    if (entry.first.compare(0, prefix.size(), prefix) == 0)
                        declarations += entry.first.substr(prefix.size());
                return declarations;
            };

            generated_script += dumpScript(fw,
                                           automaitc_rules_stream.str(),
                                           automaitc_mangle_stream.str(),
                                           nat_rules_stream.str(),
                                           nftSetDeclarations(minus_n_commands_mangle) + mangle_rules_stream.str(),
                                           nftSetDeclarations(minus_n_commands_filter) + filter_rules_stream.str(),
                                           ipv6_policy);
            if (single_rule_compile_on)
                generated_script += "\n\n";
        }

        // IPv4 and IPv6 routing are separate compiler passes. The shared
        // shell preamble is emitted once later, after both passes.
        std::string routing_script;
        bool routing_installs = false;
        RuleSet *routing = RuleSet::cast(fw->getFirstByType(Routing::TYPENAME));
        if (routing)
        {
            for (int pass = 0; pass < 2; ++pass)
            {
                const bool routing_ipv6 = (pass == 1);
                std::unique_ptr<RoutingCompiler_nft> routing_compiler(
                    new RoutingCompiler_nft(objdb, fw, routing_ipv6, oscnf.get()));
                routing_compiler->setSourceRuleSet(routing);
                routing_compiler->setRuleSetName(routing->getName());
                routing_compiler->setPersistentObjects(persistent_objects);

                routing_compiler->setSingleRuleCompileMode(single_rule_id);
                routing_compiler->setDebugLevel( dl );
                if (rule_debug_on) routing_compiler->setDebugRule(drr);
                routing_compiler->setVerbose( verbose );
                if (inTestMode()) routing_compiler->setTestMode();
                if (inEmbeddedMode()) routing_compiler->setEmbeddedMode();

                if ( (routing_rules_count=routing_compiler->prolog()) > 0 )
                {
                    routing_compiler->compile();
                    routing_compiler->epilog();
                }

                if (routing_compiler->haveErrorsAndWarnings())
                    all_errors.push_back(routing_compiler->getErrors("").c_str());

                const std::string pass_script = routing_compiler->getCompiledScript();
                if (pass_script.find("route add") != std::string::npos)
                    routing_installs = true;
                routing_script += pass_script;
            }
        }

        /*
         * compilers detach persistent objects when they finish, this
         * means at this point library persistent_objects is not part
         * of any object tree.
         */
        objdb->reparent(persistent_objects);

        if (haveErrorsAndWarnings())
        {
            all_errors.push_front(getErrors("").c_str());
        }

        if (single_rule_compile_on)
        {
            return formSingleRuleCompileOutput(
                QString::fromUtf8(
                    (getErrors("") + 
                     generated_script +
                     routing_script).c_str()));
        }


/*
 * These store generated configuration internally, extract it later using
 * OSConfiguration::getGeneratedFiles();
 */
        oscnf->processFirewallOptions();

/*
 * now write generated scripts to files
 */

        char *timestr = nullptr;
        time_t tm;
        struct tm *stm;

        tm = time(nullptr);
        stm = localtime(&tm);
        timestr = strdup(ctime(&tm));
        timestr[strlen(timestr)-1] = '\0';

        /*
         * assemble the script and then perhaps post-process it if it
         * should run on Linksys device with sveasoft firmware
         */
        // Native nftables reload must not run the Linux24 stop/start cycle.
        // Use an independent skeleton so legacy compiler behavior is unchanged.
        Configlet script_skeleton(fw, "nftables", "nft_script_skeleton");
        script_skeleton.removeComments();

        QString script_buffer;
        QTextStream script(&script_buffer, QIODevice::WriteOnly);

        /*
         * text comes from the compiler in UTF-8 (because all comments
         * and object names are stored in UTF-8 in objects and
         * compilers do not decode). We have a choice: 1) apply
         * QString::fromUtf8() to all strings coming from the compiler
         * to convert to Unicode and rely on QTextStream to convert
         * back to UTF-8 in the generated file, or 2) leavle strings
         * coming from compilers as-is and tell the stream to not
         * covert.
         */

        script_buffer = "";

        script_skeleton.setVariable("shell_debug", shell_dbg);

        script << "PATH=\"/sbin:/usr/sbin:/bin:/usr/bin:${PATH}\"" << "\n";
        script << "export PATH" << "\n";

        script_skeleton.setVariable("path", script_buffer);
        script_buffer = "";

        Configlet script_constants(fw, "linux24", "constants");
        script_skeleton.setVariable("constants", script_constants.expand());

        /*
         * print definitions for variables IPTABLES, IP, LOGGER. Some
         * day we may add a choice of os_variant in the GUI. Right now
         * paths are either default for a given os_variant, or custom
         * strings entered by user in the GUI and stored in firewall
         * options.
         */
        script_skeleton.setVariable("tools",
                                    oscnf->printPathForAllTools(os_variant).c_str());
        script_skeleton.setVariable("shell_functions",
                                    oscnf->printShellFunctions(have_ipv6).c_str());
        script_skeleton.setVariable("run_time_address_tables",
                                    oscnf->printRunTimeAddressTablesCode().c_str());
        script_skeleton.setVariable("using_ipset", oscnf->usingIpSetModule());

        if (supports_prolog_epilog)
        {
            //script_skeleton.setVariable("prolog_epilog",
            //                         oscnf->printPrologEpilogFunctions().c_str());
            string hooks_error;
            QString prolog_merged = CentralHooks::composeOrAbort(
                CentralHooks::Prolog, fw, platform,
                fw->getOptionsObject()->getStr("prolog_script"),
                &hooks_error);
            if (!hooks_error.empty())
            {
                abort(hooks_error);
                return "";
            }
            QString epilog_merged = CentralHooks::composeOrAbort(
                CentralHooks::Epilog, fw, platform,
                fw->getOptionsObject()->getStr("epilog_script"),
                &hooks_error);
            if (!hooks_error.empty())
            {
                abort(hooks_error);
                return "";
            }
            script_skeleton.setVariable("prolog_script", prolog_merged);
            script_skeleton.setVariable("epilog_script", epilog_merged);
        }

        ostringstream ostr;

        ostr << "# Configure interfaces" << "\n";

        if ( options->getBool("configure_bonding_interfaces") ) 
            ostr << oscnf->printBondingInterfaceConfigurationCommands();

        if ( options->getBool("configure_vlan_interfaces")) 
            ostr << oscnf->printVlanInterfaceConfigurationCommands();

        if ( options->getBool("configure_bridge_interfaces") ) 
            ostr << oscnf->printBridgeInterfaceConfigurationCommands();


        if ( options->getBool("configure_interfaces") ||
             options->getBool("manage_virtual_addr"))
        {
            if ( options->getBool("configure_interfaces"))
                ostr << oscnf->printInterfaceConfigurationCommands();
            else
                ostr << oscnf->printVirtualAddressesForNatCommands();
        }

        ostr << oscnf->printCommandsToClearKnownInterfaces();

        ostr << oscnf->printDynamicAddressesConfigurationCommands();

        script_skeleton.setVariable(
            "configure_interfaces", indent(4, QString(ostr.str().c_str())));



        // verify_interfaces checks bridge interfaces so run it
        // after those have been created
        if (options->getBool("verify_interfaces")) 
        {
            list<FWObject*> l2=fw->getByType(Interface::TYPENAME);
            if (l2.empty() )
                script_skeleton.setVariable("verify_interfaces", QString());
            else
                script_skeleton.setVariable("verify_interfaces",
                                            oscnf->printVerifyInterfacesCommands().c_str());
        } else
            script_skeleton.setVariable("verify_interfaces", QString());
    
        string prolog_place = fw->getOptionsObject()->getStr("prolog_place");
        if (prolog_place == "") prolog_place="top";

        /* there is no way to stick prolog commands between nftables
         * reset and nftables rules if we use atomic nftables loading
         * to activate policy. Therefore, if prolog needs to run after
         * nftables flush and we use atomic loading, we run prolog
         * on top of the script.
         */
        if (!prolog_done &&
            (prolog_place == "top" ||
             (prolog_place == "after_flush" &&
              useNftablesAtomic(fw->getOptionsObject()))))
        {
            script_skeleton.setVariable("prolog_top", 1);
            script_skeleton.setVariable("prolog_after_interfaces", 0);
            script_skeleton.setVariable("prolog_after_flush", 0);
            prolog_done = true;
        }

        if (!prolog_done && prolog_place == "after_interfaces")
        {
            script_skeleton.setVariable("prolog_top", 0);
            script_skeleton.setVariable("prolog_after_interfaces", 1);
            script_skeleton.setVariable("prolog_after_flush", 0);
            prolog_done = true;
        }

        if (!prolog_done && prolog_place == "after_flush")
        {
            script_skeleton.setVariable("prolog_top", 0);
            script_skeleton.setVariable("prolog_after_interfaces", 0);
            script_skeleton.setVariable("prolog_after_flush", 1);
            prolog_done = true;
        }

        script_skeleton.setVariable("load_modules",
                                    oscnf->generateCodeForProtocolHandlers().c_str());
        script_skeleton.setVariable("load_modules_with_nat", (have_nat)?"nat":"");
        script_skeleton.setVariable("load_modules_with_ipv6", (have_ipv6)?"ipv6":"");

        script_skeleton.setVariable("ip_forward_commands",
                                    oscnf->printIPForwardingCommands().c_str());

        /*
         * script body begins here
         */
        script_buffer = "";

        if (oscnf->haveErrorsAndWarnings())
        {
            all_errors.push_back(oscnf->getErrors("").c_str());
        }

        // convert from UTF8 to make sure localized comments are shown correctly
        // script << oscnf->getCompiledScript().c_str();
        // script << generated_script.c_str();
        // script << routing_compiler->getCompiledScript().c_str();

        script << QString::fromUtf8(oscnf->getCompiledScript().c_str());
        // IPv4 and IPv6 FWB tables are replaced in ONE atomic transaction.
        // Third-party nftables tables are never flushed or deleted.
        if (useNftablesAtomic(fw->getOptionsObject()) && !generated_script.empty())
        {
            // Fail closed: a rejected nft transaction must not fall through
            // into ip_forward/epilog and report a successful activation.
            script << "fwb_nft_begin_transaction || exit 1\n";
            if (options->getBool("use_nft_sets"))
                script << "fwb_nft_stage_address_tables || exit 1\n";
            script << "cat >> \"$FWB_NFT_TXN\" <<'FWB_NFT_RULESET'\n";
            script << QString::fromUtf8(generated_script.c_str());
            script << "\nFWB_NFT_RULESET\n";
            script << "fwb_nft_commit_transaction || exit 1\n";
        } else
        {
            script << QString::fromUtf8(generated_script.c_str());
        }
        if (routing_installs && !single_rule_compile_on)
        {
            std::string firewall_name = fw->getName();
            for (std::string::size_type i = 0; i < firewall_name.size(); ++i)
            {
                const unsigned char ch =
                    static_cast<unsigned char>(firewall_name[i]);
                if (!std::isalnum(ch) && ch != '.' && ch != '_' && ch != '-')
                    firewall_name[i] = '_';
            }
            // The firewall object is host_OS linux24. The object
            // constructor would load linux24/routing_functions, whose
            // unset {{$proto_filter}} survives as a literal "{{".
            // Load the nftables file by prefix so that file is used.
            Configlet routing_functions("nftables", "routing_functions");
            routing_functions.removeComments("##");
            routing_functions.setVariable(
                "firewall_name", QString::fromStdString(firewall_name));
            script << routing_functions.expand();
            script << "\n";
        }
        script << QString::fromUtf8(routing_script.c_str());
        if (routing_installs && !single_rule_compile_on)
            script << "fwb_routing_finish\n";

        script << '\n';

        script_skeleton.setVariable("script_body", script_buffer);

        script_skeleton.setVariable("timestamp", timestr);
        script_skeleton.setVariable("tz", tzname[stm->tm_isdst]);
        script_skeleton.setVariable("user", user_name);
        script_skeleton.setVariable("database", objdb->getFileName().c_str());

        /*
         * Call reset_all function to flush and reset nftables, but only
         * do this if we do not use atomic nftables loading. Reset is done
         * as part of the atomic load in the latter case and commands are
         * added in PolicyCompiler_nft::flushAndSetDefaultPolicy()
         */
        script_skeleton.setVariable("not_using_iptables_restore",
                                    !useNftablesAtomic(fw->getOptionsObject()));

        script_buffer = "";
        if (have_ipv4 || have_ipv6) script << "  reset_nftables" << '\n';
        script_skeleton.setVariable("reset_all", script_buffer);

        script_buffer = "";

        Configlet block_action(fw, "nftables", "nft_block_action");
        block_action.collapseEmptyStrings(true);
        block_action.setVariable("have_ipv4", have_ipv4);
        block_action.setVariable("have_ipv6", have_ipv6);
        block_action.setVariable("mgmt_access", 0);
        block_action.setVariable("mgmt_access_ipv4", 0);
        block_action.setVariable("mgmt_access_ipv6", 0);

        // the name of the option is historical (including the typo)
        if (fw->getOptionsObject()->getBool("add_mgmt_ssh_rule_when_stoped"))
        {
            // The management option holds one address. Select its actual
            // address family before asking the existing validator to emit it.
            const std::string mgmt_addr =
                fw->getOptionsObject()->getStr("mgmt_addr");
            const bool mgmt_ipv6 = mgmt_addr.find(':') != std::string::npos;
            // 'block' replaces the entire ruleset and protects both families,
            // even if only one was compiled by the normal policy generator.
            std::unique_ptr<PolicyCompiler_nft> policy_compiler =
                createPolicyCompiler(fw, mgmt_ipv6, nullptr, nullptr);
            PolicyCompiler_nft::PrintRule* print_rule =
                policy_compiler->createPrintRuleProcessor();
            print_rule->setContext(policy_compiler.get());
            print_rule->_printBackupSSHAccessRules(&block_action);
            delete print_rule;
        }

        script_skeleton.setVariable("block_action", block_action.expand());


        Configlet stop_action(fw, "nftables", "nft_stop_action");
        stop_action.collapseEmptyStrings(true);
        stop_action.setVariable("have_ipv4", have_ipv4);
        stop_action.setVariable("have_ipv6", have_ipv6);

        script_skeleton.setVariable("stop_action", stop_action.expand());



        Configlet status_action(fw, "nftables", "nft_status_action");
        status_action.collapseEmptyStrings(true);
        script_skeleton.setVariable("status_action", status_action.expand());

        Configlet top_comment(fw, "linux24", "top_comment");

        top_comment.setVariable("version", VERSION);
        top_comment.setVariable("timestamp", timestr);
        top_comment.setVariable("tz", tzname[stm->tm_isdst]);
        top_comment.setVariable("user", user_name);
        top_comment.setVariable("database", objdb->getFileName().c_str());

        determineOutputFileNames(cluster, fw, !cluster_id.empty(),
                                 QStringList(""), QStringList("fw"),
                                 QStringList("script_name_on_firewall"));

        script_buffer = "";
        script << manifestMarker()
               << "* "
               << this->escapeFileName(file_names[FW_FILE]);

        if (!remote_file_names[FW_FILE].isEmpty())
            script << " " << this->escapeFileName(remote_file_names[FW_FILE]);
        script << "\n";

        /* Add additional files to manifest if specified.  Currently there
         * are no GUI controls to let user provide alternative names for
         * these on the firewall. See description of manifest format in
         * comments in src/gui/FirewallInstaller.cpp
         */
        map<string, string> file_list = oscnf->getGeneratedFiles();
        if (!file_list.empty())
        {
            info(" Adding additional files to manifest");
            map<string, string>::const_iterator c_iter = file_list.begin();
            for (; c_iter != file_list.end(); ++c_iter)
            {
                string name = c_iter->first;
                string dest = c_iter->second;
                script << manifestMarker() << this->escapeFileName(name.c_str());
                if (!dest.empty()) script << " " << dest;
                script << "\n";
            }
        }

        top_comment.setVariable("manifest", script_buffer);
        top_comment.setVariable("platform", platform.c_str());
        top_comment.setVariable("fw_version", fw_version.c_str());
        top_comment.setVariable("comment", prepend("# ", fw->getComment().c_str()));

        script_skeleton.setVariable("top_comment", top_comment.expand());
        script_skeleton.setVariable("errors_and_warnings",
                                    prepend("# ", all_errors.join("\n")));

        info("Output file name: " + file_names[FW_FILE].toStdString());

        // Reject legacy commands before writing a deployable firewall script.
        // In particular, a successful CLI exit and a non-empty .fw file must
        // never turn an iptables/nftables hybrid into a successful compilation.
        const QString native_script = script_skeleton.expand();
        const char *legacy_markers[] = {
            "$IPTABLES", "$IP6TABLES", "echo '*filter'",
            "echo '*nat'", "echo '*mangle'", "echo COMMIT",
            " -m state", " --state ", " -j ", " -s ", " -d ",
            "--to-source", "--to-destination", "{{opt_wait}}",
            // Quoted nft heredocs intentionally prevent shell expansion.
            // Refuse dynamic addresses until native substitution is supported.
            "$i_", "$at_", "{{"
        };
        for (const char *marker : legacy_markers)
        {
            if (native_script.contains(QString::fromLatin1(marker)))
                abort(std::string("Native nftables script contains legacy command: ") + marker);
        }

        QFile fw_file(file_names[FW_FILE]);
        if (fw_file.open(QIODevice::WriteOnly))
        {
            QTextStream fw_str(&fw_file);
            fw_str << native_script;
            fw_file.close();
            fw_file.setPermissions(QFile::ReadOwner | QFile::WriteOwner |
                                   QFile::ReadGroup | QFile::ReadOther |
                                   QFile::ExeOwner | 
                                   QFile::ExeGroup |
                                   QFile::ExeOther );

            info(" Compiled successfully");

        } else
        {
            QString err(" Failed to open file %1 for writing: %2; Current dir: %3");
            abort(err.arg(fw_file.fileName())
                  .arg(fw_file.error()).arg(QDir::current().path()).toStdString());
        }

        free(timestr);

        if (!all_errors.isEmpty())
            status = BaseCompiler::FWCOMPILER_WARNING;

    }
    catch (FWException &ex)
    {
        status = BaseCompiler::FWCOMPILER_ERROR;
        return QString::fromUtf8(ex.toString().c_str());
    }
    
    return "";
}
