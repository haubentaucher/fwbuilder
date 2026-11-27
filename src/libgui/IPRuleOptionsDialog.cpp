/*

                 Firewall Builder

                 Copyright (C) 2026 haubentaucher

  Author:  haubentaucher

  This program is free software which we release under the GNU General Public
  License. You may redistribute it and/or modify this program under the terms
  of that license as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  To get a copy of the GNU General Public License, write to the Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/


#include "config.h"
#include "global.h"
#include "utils.h"
#include "platforms.h"
#include "ProjectPanel.h"
#include "IPRuleOptionsDialog.h"
#include "RuleSetView.h"
#include "FWWindow.h"
#include "FWCmdRule.h"

#include "fwbuilder/Firewall.h"
#include "fwbuilder/Rule.h"
#include "fwbuilder/Routing.h"
#include "fwbuilder/FWOptions.h"
#include "fwbuilder/FWObjectDatabase.h"

#include <memory>

#include <qstackedwidget.h>
#include <qlineedit.h>
#include <qcombobox.h>
#include <qpushbutton.h>
#include <qspinbox.h>
#include <qcheckbox.h>
#include <qlabel.h>

#include <iostream>

using namespace libfwbuilder;
using namespace std;

IPRuleOptionsDialog::~IPRuleOptionsDialog()
{
    delete m_dialog;
}

IPRuleOptionsDialog::IPRuleOptionsDialog(QWidget *parent) :
    BaseObjectDialog(parent)
{
    m_dialog = new Ui::IPRuleOptionsDialog_q;
    m_dialog->setupUi(this);

    connect(m_dialog->lookup_combo, SIGNAL(currentIndexChanged(int)),
            this, SLOT(changed()));
    connect(m_dialog->src_runtime_var_edit, SIGNAL(textEdited(const QString&)),
            this, SLOT(changed()));
    connect(m_dialog->dst_runtime_var_edit, SIGNAL(textEdited(const QString&)),
            this, SLOT(changed()));
}

void IPRuleOptionsDialog::loadFWObject(FWObject *o)
{
    obj = o;

    IPRule *rule = IPRule::cast(o);
    if (rule == NULL) return;

    FWObject *p = o;
    while (!Firewall::cast(p)) p = p->getParent();
    Firewall *fw = Firewall::cast(p);

    FWOptions *ropt = rule->getOptionsObject();

    // The lookup target must be a routing rule set of this firewall.
    m_dialog->lookup_combo->clear();

    for (FWObjectTypedChildIterator it = fw->findByType(Routing::TYPENAME);
         it != it.end(); ++it)
    {
        RuleSet *ruleset = RuleSet::cast(*it);
        if (ruleset == NULL) continue;

        QString item_text = QString::fromUtf8(ruleset->getName().c_str());

        FWOptions *ruleset_opt = ruleset->getOptionsObject();
        if (ruleset_opt != NULL)
        {
            string table_name = ruleset_opt->getStr("routing_table_name");
            if (!table_name.empty())
                item_text += QString(" (") +
                    QString::fromUtf8(table_name.c_str()) + QString(")");
        }

        m_dialog->lookup_combo->addItem(
            item_text,
            QVariant(QString::fromUtf8(
                FWObjectDatabase::getStringId(ruleset->getId()).c_str())));
    }

    init = true;

    int item = m_dialog->lookup_combo->findData(
        QVariant(QString::fromUtf8(ropt->getStr("ip_rule_lookup_id").c_str())));
    if (item < 0 && m_dialog->lookup_combo->count() > 0)
    {
        // No target chosen yet. Suggest the first routing rule set but
        // do not save anything until the user applies the change.
        item = 0;
    }
    m_dialog->lookup_combo->setCurrentIndex(item);

    m_dialog->src_runtime_var_edit->setText(QString::fromUtf8(
        ropt->getStr("ip_rule_src_runtime_var").c_str()));
    m_dialog->dst_runtime_var_edit->setText(QString::fromUtf8(
        ropt->getStr("ip_rule_dst_runtime_var").c_str()));

    init = false;
}

void IPRuleOptionsDialog::validate(bool *res)
{
    // No GUI-side validation: the compiler diagnoses an unusable
    // lookup target and the rule editor only offers real targets.
    *res = true;
}

void IPRuleOptionsDialog::applyChanges()
{
    std::unique_ptr<FWCmdRuleChange> cmd( new FWCmdRuleChangeOptions(m_project, obj));
    // new_state is a copy of the rule object
    FWObject* new_state = cmd->getNewState();
    FWOptions* new_rule_options = Rule::cast(new_state)->getOptionsObject();

    init = true;

    int item = m_dialog->lookup_combo->currentIndex();
    if (item >= 0)
        new_rule_options->setStr(
            "ip_rule_lookup_id",
            m_dialog->lookup_combo->itemData(item).toString().toStdString());

    // The runtime variable names are stored exactly as typed (the
    // compiler accepts an optional leading '$' and validates the
    // name); an empty field stores an empty string, which the
    // compiler treats as "no runtime variable".
    new_rule_options->setStr(
        "ip_rule_src_runtime_var",
        m_dialog->src_runtime_var_edit->text().trimmed().toStdString());
    new_rule_options->setStr(
        "ip_rule_dst_runtime_var",
        m_dialog->dst_runtime_var_edit->text().trimmed().toStdString());

    init = false;

    if (!cmd->getOldState()->cmp(new_state, true))
    {
        if (obj->isReadOnly()) return;
        m_project->undoStack->push(cmd.release());
    }
}
