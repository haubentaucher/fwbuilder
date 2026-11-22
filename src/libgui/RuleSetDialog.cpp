/*

                          Firewall Builder

                 Copyright (C) 2008 NetCitadel, LLC

  Author:  alek@codeminders.com

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

#include "config.h"
#include "global.h"
#include "utils.h"

#include "FWBTree.h"
#include "RuleSetDialog.h"
#include "ProjectPanel.h"
#include "FWCmdChange.h"

#include "fwbuilder/Library.h"
#include "fwbuilder/Host.h"
#include "fwbuilder/Interface.h"
#include "fwbuilder/Management.h"
#include "fwbuilder/FWException.h"
#include "fwbuilder/RuleSet.h"
#include "fwbuilder/Firewall.h"
#include "fwbuilder/Cluster.h"
#include "fwbuilder/Policy.h"
#include "fwbuilder/Routing.h"

#include <memory>

#include <qlineedit.h>
#include <qspinbox.h>
#include <qcheckbox.h>
#include <qtextedit.h>
#include <qcombobox.h>
#include <qmessagebox.h>
#include <qpushbutton.h>
#include <QUndoStack>
#include <QApplication>

using namespace std;
using namespace libfwbuilder;

RuleSetDialog::RuleSetDialog(QWidget *parent) : BaseObjectDialog(parent)
{
    m_dialog = new Ui::RuleSetDialog_q;
    m_dialog->setupUi(this);
    obj = NULL;
    platform = "";

    connect(m_dialog->nft_own_routing_table, SIGNAL(toggled(bool)),
            this, SLOT(toggleRoutingTableFields(bool)));

    connectSignalsOfAllWidgetsToSlotChange();
}

RuleSetDialog::~RuleSetDialog()
{
    delete m_dialog;
}

void RuleSetDialog::loadFWObject(FWObject *o)
{
    obj = o;
    this->setEnabled(!o->isReadOnly());

    RuleSet *s = dynamic_cast<RuleSet*>(obj);
    assert(s!=NULL);

    init = true;

    m_dialog->obj_name->setText( QString::fromUtf8(s->getName().c_str()) );
    m_dialog->commentKeywords->loadFWObject(o);

    // ipv4_6_rule_set QComboBox:
    // 0 - ipv4
    // 1 - ipv6
    // 2 - dual
    int idx = 0;
    if (s->isV4()) idx = 0;
    if (s->isV6()) idx = 1;
    if (s->isDual()) idx = 2;
    m_dialog->ipv4_6_rule_set->setCurrentIndex(idx);

    m_dialog->top_rule_set->setChecked(s->isTop());

    FWObject *fw = o;
    while (fw && (!Firewall::isA(fw) && !Cluster::isA(fw))) fw = fw->getParent();
    // if rule set object is in DeletedObjects library, it does not have parent
    // firewall
    if (fw!=NULL)
    {
        platform = fw->getStr("platform");
        fwopt = Firewall::cast(fw)->getOptionsObject();
        FWOptions *rulesetopt = s->getOptionsObject();

        if (platform == "iptables" || platform == "nftables")
        {
            if (platform == "iptables")
            {
                m_dialog->top_rule_set->setToolTip(
                    QApplication::translate("RuleSetDialog_q",
                                            "On iptables \"top\" rule set goes into \n"
                                            "the built-in chains INPUT, OUTPUT,\n"
                                            "FORWARD; if this flag is unchecked,\n"
                                            "rules go into user-defined chain \n"
                                            "with the name the same as the name of \n"
                                            "the rule set.",
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
                                            0, QApplication::UnicodeUTF8));
#else
                                            0));
#endif
            } else
            {
                m_dialog->top_rule_set->setToolTip(
                    QApplication::translate("RuleSetDialog_q",
                                            "On nftables a \"top\" rule set feeds\n"
                                            "the base chains of table 'filter'; if\n"
                                            "this flag is unchecked, rules go into\n"
                                            "a regular chain named after the rule\n"
                                            "set (jumped to from other rules).",
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
                                            0, QApplication::UnicodeUTF8));
#else
                                            0));
#endif
            }

            if (Policy::isA(obj))
            {
                // if this attribute is absent, we consider it False, so for
                // backwards compatibility the rule set is considered
                // filter+mangle rather than mangle only.
                m_dialog->iptables_only->show();
                bool f = rulesetopt->getBool("mangle_only_rule_set");
                m_dialog->ipt_filter_table->setChecked(!f);
                m_dialog->ipt_mangle_table->setChecked(f);
            } else
                m_dialog->iptables_only->hide();

            if (platform == "nftables" && Routing::isA(obj))
            {
                // A routing rule set without table options compiles into
                // the main table (historical behavior); the table name/id
                // options move it into its own named iproute2 table.
                m_dialog->nftables_routing->show();
                QString table_name = QString::fromUtf8(
                    rulesetopt->getStr("routing_table_name").c_str());
                bool own_table = !table_name.isEmpty();
                m_dialog->nft_own_routing_table->setChecked(own_table);
                m_dialog->nft_routing_table_name->setText(table_name);
                int table_id = rulesetopt->getInt("routing_table_id");
                if (table_id < 1 || table_id > 252) table_id = 100;
                m_dialog->nft_routing_table_number->setValue(table_id);
                toggleRoutingTableFields(own_table);
            } else
                m_dialog->nftables_routing->hide();

        } else
        {
            m_dialog->iptables_only->hide();
            m_dialog->nftables_routing->hide();
        }


        if (platform == "pf")
            m_dialog->top_rule_set->setToolTip(
                QApplication::translate("RuleSetDialog_q",
                                        "If this flag is unchecked, rules go \n"
                                        "into anchor with the name the same as\n"
                                        "the name of the rule set.",
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
                                        0, QApplication::UnicodeUTF8));
#else
                                        0));
#endif

        if (platform == "ipf" || platform == "ipfw")
            m_dialog->top_rule_set->hide();
        else
            m_dialog->top_rule_set->show();
    }
    init=false;
}

void RuleSetDialog::toggleRoutingTableFields(bool on)
{
    m_dialog->nft_routing_table_name->setEnabled(on);
    m_dialog->nft_routing_table_number->setEnabled(on);
}

void RuleSetDialog::validate(bool *res)
{
    *res = true;
    if (!validateName(this, obj, m_dialog->obj_name->text())) { *res = false; return; }

    // Do not allow ':' in the rule set names because this character is
    // used as a separator in error and warning messages 
    QString pattern("([a-zA-Z0-9_-+=@%^]+)");

    // branch (anchor) names for PF may end with "/*"
    if (platform == "pf")
        pattern = "([a-zA-Z0-9_-+=@%^]+)(/\\*)?";

    QRegExp rx(pattern);

    if (!rx.exactMatch(m_dialog->obj_name->text()))
    {
        *res = false ;
        if (QApplication::focusWidget() != NULL)
        {
            blockSignals(true);
            QMessageBox::critical(
                this,
                "Firewall Builder",
                tr("Rule set name '%1' is invalid. Only '[a-z][A-Z][0-9]_-+=@%^' characters are allowed.").arg( m_dialog->obj_name->text() ),
                tr("&Continue"), 0, 0,
                0 );
            blockSignals(false);
        }
        return ;
    }

    // nftables Routing rule sets: the optional named iproute2 table
    // must carry a well-formed name, a valid numeric table id and
    // neither must already be used by another Routing rule set of
    // this firewall.
    if (platform == "nftables" && Routing::isA(obj) &&
        m_dialog->nft_own_routing_table->isChecked())
    {
        QRegExp trx("[A-Za-z0-9_]+");
        if (!trx.exactMatch(m_dialog->nft_routing_table_name->text()))
        {
            *res = false;
            if (QApplication::focusWidget() != NULL)
            {
                blockSignals(true);
                QMessageBox::critical(
                    this,
                    "Firewall Builder",
                    tr("Routing table name '%1' is invalid. "
                       "Only letters, digits and underscores are allowed.")
                        .arg(m_dialog->nft_routing_table_name->text()),
                    tr("&Continue"), 0, 0, 0);
                blockSignals(false);
            }
            return ;
        }

        QString table_name = m_dialog->nft_routing_table_name->text();
        int table_id = m_dialog->nft_routing_table_number->value();

        FWObject *fw_object = obj->getParent();
        for (std::list<FWObject*>::const_iterator it =
                 fw_object->begin(); it != fw_object->end(); ++it)
        {
            RuleSet *other = RuleSet::cast(*it);
            if (other == NULL || other == obj ||
                other->getTypeName() != Routing::TYPENAME) continue;
            FWOptions *other_opt = other->getOptionsObject();
            if (other_opt == NULL) continue;
            if (QString::fromUtf8(
                    other_opt->getStr("routing_table_name").c_str())
                == table_name)
            {
                *res = false;
                if (QApplication::focusWidget() != NULL)
                {
                    blockSignals(true);
                    QMessageBox::critical(
                        this, "Firewall Builder",
                        tr("Routing table name '%1' is already used by "
                           "rule set '%2'.")
                            .arg(table_name)
                            .arg(QString::fromUtf8(other->getName().c_str())),
                        tr("&Continue"), 0, 0, 0);
                    blockSignals(false);
                }
                return ;
            }
            int other_id = other_opt->getInt("routing_table_id");
            if (other_id == table_id)
            {
                *res = false;
                if (QApplication::focusWidget() != NULL)
                {
                    blockSignals(true);
                    QMessageBox::critical(
                        this, "Firewall Builder",
                        tr("Routing table number '%1' is already used by "
                           "rule set '%2'.")
                            .arg(table_id)
                            .arg(QString::fromUtf8(other->getName().c_str())),
                        tr("&Continue"), 0, 0, 0);
                    blockSignals(false);
                }
                return ;
            }
        }
    }
}



void RuleSetDialog::applyChanges()
{
    std::unique_ptr<FWCmdChange> cmd( new FWCmdChange(m_project, obj));
    FWObject* new_state = cmd->getNewState();

    RuleSet *s = dynamic_cast<RuleSet*>(new_state);
    assert(s!=NULL);

    FWOptions *rulesetopt = s->getOptionsObject();

    string oldname = obj->getName();
    new_state->setName( string(m_dialog->obj_name->text().toUtf8().constData()) );
    m_dialog->commentKeywords->applyChanges(new_state);

    switch (m_dialog->ipv4_6_rule_set->currentIndex())
    {
    case 1: s->setV6(); break;
    case 2: s->setDual(); break;
    default: s->setV4(); break;
    }

    s->setTop(m_dialog->top_rule_set->isChecked());

    if ((platform == "iptables" || platform == "nftables") && Policy::isA(s))
    {
        rulesetopt->setBool("mangle_only_rule_set",
                            m_dialog->ipt_mangle_table->isChecked());
    }

    if (platform == "nftables" && Routing::isA(s))
    {
        if (m_dialog->nft_own_routing_table->isChecked())
        {
            rulesetopt->setStr("routing_table_name",
                m_dialog->nft_routing_table_name->text().toUtf8().constData());
            rulesetopt->setInt("routing_table_id",
                               m_dialog->nft_routing_table_number->value());
        } else
        {
            rulesetopt->setStr("routing_table_name", "");
            rulesetopt->setInt("routing_table_id", 0);
        }
    }

    if (!cmd->getOldState()->cmp(new_state, true))
    {
        if (obj->isReadOnly()) return;
        m_project->undoStack->push(cmd.release());
    }
    
}

