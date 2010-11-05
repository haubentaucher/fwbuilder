/*

                          Firewall Builder

                 Copyright (C) 2006 NetCitadel, LLC

  Author:  Illiya Yalovoy <yalovoy@gmail.com>

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

#include "../../config.h"
#include "../../definitions.h"
#include "global.h"
#include "utils.h"
#include "platforms.h"

#include "ActionsDialog.h"
#include "FWWindow.h"
#include "FWObjectDropArea.h"
#include "DialogFactory.h"
#include "FWCmdRule.h"

#include "fwbuilder/Library.h"
#include "fwbuilder/Interface.h"
#include "fwbuilder/FWException.h"
#include "fwbuilder/Rule.h"
#include "fwbuilder/RuleSet.h"
#include "fwbuilder/Firewall.h"

#include <memory>

#include <qlineedit.h>
#include <qspinbox.h>
#include <qcheckbox.h>
#include <qradiobutton.h>
#include <qtextedit.h>
#include <qcombobox.h>
#include <qmessagebox.h>
#include <qlabel.h>
#include <qpushbutton.h>
#include <qapplication.h>
#include <QStackedWidget>
#include <qcursor.h>
#include <qregexp.h>
#include <QtDebug>

#include <iostream>
#include <stdlib.h>

using namespace std;
using namespace libfwbuilder;

ActionsDialog::ActionsDialog(QWidget *parent) : BaseObjectDialog(parent)
{
    m_dialog = new Ui::ActionsDialog_q;
    m_dialog->setupUi(this);

    m_dialog->iptBranchDropArea->addAcceptedTypes("Policy");
    //m_dialog->iptBranchDropArea->addAcceptedTypes("NAT");
    //m_dialog->iptBranchDropArea->addAcceptedTypes("Routing");
    m_dialog->iptBranchDropArea->setHelperText("Drop rule set object here");
    connect (m_dialog->iptBranchDropArea,
             SIGNAL(objectDeleted()),this,SLOT(changed()));
    connect (m_dialog->iptBranchDropArea,
             SIGNAL(objectInserted()),this,SLOT(changed()));

    m_dialog->pfBranchDropArea->addAcceptedTypes("Policy");
    //m_dialog->pfBranchDropArea->addAcceptedTypes("NAT");
    //m_dialog->pfBranchDropArea->addAcceptedTypes("Routing");
    m_dialog->pfBranchDropArea->setHelperText("Drop rule set object here");
    connect (m_dialog->pfBranchDropArea,
             SIGNAL(objectDeleted()),this,SLOT(changed()));
    connect (m_dialog->pfBranchDropArea,
             SIGNAL(objectInserted()),this,SLOT(changed()));

    m_dialog->natBranchDropArea->addAcceptedTypes("NAT");
    m_dialog->natBranchDropArea->setHelperText("Drop NAT rule set object here");
    connect (m_dialog->natBranchDropArea,
             SIGNAL(objectDeleted()),this,SLOT(changed()));
    connect (m_dialog->natBranchDropArea,
             SIGNAL(objectInserted()),this,SLOT(changed()));

    m_dialog->pfTagDropArea->addAcceptedTypes("TagService");
    connect (m_dialog->pfTagDropArea,
             SIGNAL(objectDeleted()),this,SLOT(changed()));
    connect (m_dialog->pfTagDropArea,
             SIGNAL(objectInserted()),this,SLOT(changed()));

    m_dialog->iptTagDropArea->addAcceptedTypes("TagService");
    connect (m_dialog->iptTagDropArea,
             SIGNAL(objectDeleted()),this,SLOT(changed()));
    connect (m_dialog->iptTagDropArea,
             SIGNAL(objectInserted()),this,SLOT(changed()));
};

ActionsDialog::~ActionsDialog() 
{ 
    delete m_dialog; 
}

void ActionsDialog::loadFWObject(FWObject *o)
{
    obj = o;
    setRule(Rule::cast(o));
}

void ActionsDialog::getHelpName(QString *str)
{
    *str = help_name;
}

void ActionsDialog::validate(bool *res)
{
    FWOptions *ruleopt =rule->getOptionsObject();

    *res=true;

    if (platform=="iptables")
    {
        /*
         *  http://www.netfilter.org/projects/patch-o-matic/pom-extra.html#pom-extra-ROUTE
         *  says:
         *
         * "Note that --iif, --continue, and --tee, are mutually exclusive."
         */

        string iif  = ruleopt->getStr("ipt_iif");
        int    cont = ruleopt->getBool("ipt_continue");
        int    tee  = ruleopt->getBool("ipt_tee");

        if ( (int(!iif.empty()) + cont + tee) > 1)
        {
            *res=false;
            QMessageBox::critical(this, "Firewall Builder",
                                  tr("'Change inbound interface', 'Continue packet inspection' and 'Make a copy' options are mutually exclusive"),
                                  tr("&Continue"), 0, 0,
                                  0 );
        }
    }
}

void ActionsDialog::applyChanges()
{
    std::auto_ptr<FWCmdRuleChange> cmd( new FWCmdRuleChangeAction(m_project, obj));

    // new_state  is a copy of the rule object
    FWObject* new_state = cmd->getNewState();
    FWOptions* new_rule_options = Rule::cast(new_state)->getOptionsObject();

    if (platform=="iptables" && editor=="AccountingStr")
    {
        QString rn = m_dialog->accountingvalue_str->text();
/* rule name for accounting may contain only alphanumeric characters
 * and no white spaces or spec. characters
 */
        if (rn.contains(QRegExp("[^a-zA-Z0-9_]"))!=0)
        {
            QMessageBox::information(
                this,"Firewall Builder",
                tr("Rule name for accounting is converted to the iptables\nchain name and therefore may not contain white space\nand special characters."),
                tr("&Continue"), QString::null,QString::null,
                0, 1 );

            return;
        }
    }

    data.saveAll(new_rule_options);

    Rule *rule = Rule::cast(new_state);
    PolicyRule *policy_rule = PolicyRule::cast(new_state);

    if (editor=="TagInt")
    {
        FWObject *tag_object = m_dialog->iptTagDropArea->getObject();
        // if tag_object==NULL, setTagObject clears setting in the rule
        policy_rule->setTagObject(tag_object);
    }

    if (editor=="TagStr")
    {
        FWObject *tag_object = m_dialog->pfTagDropArea->getObject();
        // if tag_object==NULL, setTagObject clears setting in the rule
        policy_rule->setTagObject(tag_object);
    }

    if (editor=="BranchChain")
    {
        RuleSet *ruleset = RuleSet::cast(m_dialog->iptBranchDropArea->getObject());
        // if ruleset==NULL, setBranch clears setting in the rule
        rule->setBranch(ruleset);
    }

    if (editor=="BranchAnchor")
    {
        RuleSet *ruleset = RuleSet::cast(m_dialog->pfBranchDropArea->getObject());
        // if ruleset==NULL, setBranch clears setting in the rule
        rule->setBranch(ruleset);
    }

    if (editor=="NATBranch")
    {
        RuleSet *ruleset = RuleSet::cast(m_dialog->natBranchDropArea->getObject());
        // if ruleset==NULL, setBranch clears setting in the rule
        rule->setBranch(ruleset);
    }

    if (m_dialog->useDummyNetPipe->isChecked())
        new_rule_options->setInt("ipfw_classify_method", DUMMYNETPIPE);
    else
        new_rule_options->setInt("ipfw_classify_method", DUMMYNETQUEUE);

    if (!cmd->getOldState()->cmp(new_state, true))
        m_project->undoStack->push(cmd.release());
}

void ActionsDialog::tagvalueChanged(int)
{
    QString buf;
//!!!    buf.setNum(m_dialog->tagvalue_int->value());
//!!!    m_dialog->tagvalue_str->setText(buf);
}

void ActionsDialog::iptRouteContinueToggled()
{
    if (m_dialog->ipt_continue->isChecked())
    {
        m_dialog->ipt_iif->setCurrentIndex(0);
        m_dialog->ipt_tee->setChecked(false);
    }
    m_dialog->ipt_iif->setEnabled( ! m_dialog->ipt_continue->isChecked() );
    m_dialog->ipt_tee->setEnabled( ! m_dialog->ipt_continue->isChecked() );
}

void ActionsDialog::setRule(Rule *r)
{
    rule = r;

    PolicyRule *policy_rule = PolicyRule::cast(r);

    FWObject *o = r;
    while (o!=NULL && Firewall::cast(o)==NULL) o = o->getParent();

    Firewall *f = Firewall::cast(o);
    firewall = f;

    FWOptions *ropt = rule->getOptionsObject();

    string act = getRuleAction(rule).toStdString();

    if (firewall)
    {
        // firewall can be NULL if rule set is in Deleted Objects library
        fillInterfaces(m_dialog->ipt_iif);
        fillInterfaces(m_dialog->ipt_oif);
        fillInterfaces(m_dialog->ipf_route_opt_if);
        fillInterfaces(m_dialog->pf_route_opt_if);

        platform = firewall->getStr("platform");
        help_name = string(platform + "_" + act).c_str();
        editor = DialogFactory::getActionDialogPageName(firewall, r);
    }

    if (fwbdebug)
        qDebug() << "ActionsDialog::setRule"
                 << "Action: " << getRuleAction(rule)
                 << "editor: " << editor.c_str();

    QStringList actionsOnReject = getActionsOnReject( platform.c_str() );
    m_dialog->rejectvalue->clear();
    m_dialog->rejectvalue->addItems( getScreenNames( actionsOnReject ) );

    branchNameInput = NULL;

    if (ropt->getInt("ipfw_classify_method") == DUMMYNETPIPE)
    {
        m_dialog->useDummyNetPipe->setChecked(1);
    } else {
        m_dialog->useDummyNetQueue->setChecked(1);
    }

    if (platform=="iptables")
    {
        m_dialog->classify_terminating->show();
        m_dialog->tag_terminating->show();

        // Keep both variants of this text separate to simplify localization
        QString emu_state;
        if (firewall->getOptionsObject()->getBool("classify_mark_terminating"))
        {
            emu_state = 
                tr("Emulation of terminating behavior for MARK and CLASSIFY "
                   "targets is currently ON, rule will be terminating");
        } else
        {
            emu_state = 
                tr("Emulation of terminating behavior for MARK and CLASSIFY "
                   "targets is currently OFF, rule will not be terminating");
        }
        m_dialog->classify_terminating->setText(emu_state);
        m_dialog->tag_terminating->setText(emu_state);

    } else
    {
        m_dialog->classify_terminating->hide();
        m_dialog->tag_terminating->hide();
    }

    data.clear();

    data.registerOption(m_dialog->ipt_mark_connections, ropt,
                        "ipt_mark_connections");
//    data.registerOption(ipt_mark_prerouting, ropt, "ipt_mark_prerouting");
    data.registerOption(m_dialog->accountingvalue_str, ropt,
                        "rule_name_accounting");
    data.registerOption(m_dialog->usePortNum, ropt, "ipfw_pipe_queue_num");
    data.registerOption(m_dialog->divertPortNum, ropt, "ipfw_pipe_port_num");
    data.registerOption(m_dialog->classify_str, ropt, "classify_str");
    data.registerOption(m_dialog->custom_str, ropt, "custom_str");

    // ROUTE action:

    // build a map for combobox so visible combobox items can be localized
    QStringList route_options = getRouteOptions_pf_ipf(platform.c_str() );
    QStringList route_load_options = getRouteLoadOptions_pf(platform.c_str() );

    // iptables
    data.registerOption(m_dialog->ipt_iif, ropt, "ipt_iif" );
    data.registerOption(m_dialog->ipt_oif, ropt, "ipt_oif" );
    data.registerOption(m_dialog->ipt_gw, ropt, "ipt_gw" );
    data.registerOption(m_dialog->ipt_continue, ropt, "ipt_continue" );
    data.registerOption(m_dialog->ipt_tee, ropt, "ipt_tee");

    // ipfilter
    data.registerOption(m_dialog->ipf_route_option, ropt, "ipf_route_option",
                          route_options);
    data.registerOption(m_dialog->ipf_route_opt_if, ropt, "ipf_route_opt_if");
    data.registerOption(m_dialog->ipf_route_opt_addr, ropt,
                        "ipf_route_opt_addr");

    // pf
    data.registerOption(m_dialog->pf_fastroute, ropt, "pf_fastroute"     );
    data.registerOption(m_dialog->pf_route_load_option, ropt,
                        "pf_route_load_option", route_load_options );
    data.registerOption(m_dialog->pf_route_option, ropt, "pf_route_option",
                          route_options);
    data.registerOption(m_dialog->pf_route_opt_if, ropt, "pf_route_opt_if"  );
    data.registerOption(m_dialog->pf_route_opt_addr, ropt, "pf_route_opt_addr");

    // REJECT action:
    data.registerOption(m_dialog->rejectvalue, ropt, "action_on_reject");

    QWidget *w = m_dialog->NonePage;
    if (editor=="Reject")
    {
        w=m_dialog->RejectPage;
    }
    else if (editor=="TagInt")
    {
        w=m_dialog->TagIntPage;
        FWObject *o = policy_rule->getTagObject();
        m_dialog->iptTagDropArea->setObject(o);
        m_dialog->iptTagDropArea->update();
    }
    else if (editor=="TagStr")
    {
        w=m_dialog->TagStrPage;
        FWObject *o = policy_rule->getTagObject();
        m_dialog->pfTagDropArea->setObject(o);
        m_dialog->pfTagDropArea->update();
    }
    else if (editor=="AccountingStr")
    {
        w=m_dialog->AccountingStrPage;
    }
    else if (editor=="ClassifyArgsIPFW")
    {
        w=m_dialog->ClassifyArgsIPFW;
    }
    else if (editor=="PipeArgsIPFW")
    {
        w=m_dialog->PipeArgsIPFW;
    }
    else if (editor=="ClassifyStr")
    {
        w=m_dialog->ClassifyStrPage;
    }
    else if (editor=="CustomStr")
    {
        w=m_dialog->CustomStrPage;
    }
    else if (editor=="BranchChain")
    {
        w = m_dialog->BranchChainPage;
        RuleSet *ruleset = r->getBranch();
        m_dialog->iptBranchDropArea->setObject(ruleset);

        data.registerOption(
            m_dialog->ipt_branch_in_mangle, ropt, "ipt_branch_in_mangle" );
    }
    else if (editor=="BranchAnchor")
    {
        w=m_dialog->BranchAnchorPage;
        RuleSet *ruleset = r->getBranch();
        m_dialog->pfBranchDropArea->setObject(ruleset);
    }
    else if (editor=="NATBranch")
    {
        w = m_dialog->NATBranchPage;
        RuleSet *ruleset = r->getBranch();
        m_dialog->natBranchDropArea->setObject(ruleset);
    }
    else if (editor=="RouteIPT")
    {
        w=m_dialog->RouteIPTPage;
    }
    else if (editor=="RouteIPF")
    {
        w=m_dialog->RouteIPFPage;
    }
    else if (editor=="RoutePF")
    {
        w=m_dialog->RoutePFPage;
    }

    m_dialog->widgetStack->setCurrentWidget(w);

    //rejectvalue->setCurrentText(ropt->getStr("action_on_reject") );
    data.loadAll();

    iptRouteContinueToggled();
}

void ActionsDialog::fillInterfaces(QComboBox* cb)
{
    cb->clear();
    cb->addItem("");

    FWObjectTypedChildIterator j=firewall->findByType(Interface::TYPENAME);
    for (; j!=j.end(); ++j )
    {
        cb->addItem(QString::fromUtf8((*j)->getName().c_str()) );
    }

}

