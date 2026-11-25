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
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

*/

#ifndef __IPRULEOPTIONSDIALOG_H_
#define __IPRULEOPTIONSDIALOG_H_

#include "config.h"
#include <ui_ipruleoptionsdialog_q.h>
#include "BaseObjectDialog.h"
#include <QWidget>

#include "DialogData.h"

#include "fwbuilder/FWObject.h"

class RuleSetView;
class ProjectPanel;

class IPRuleOptionsDialog : public BaseObjectDialog
{
    Q_OBJECT;

    DialogData                  data;
    RuleSetView                *rsv;
    Ui::IPRuleOptionsDialog_q  *m_dialog;

 public:
    IPRuleOptionsDialog(QWidget *parent);
    ~IPRuleOptionsDialog();

 public slots:
    virtual void applyChanges();
    virtual void loadFWObject(libfwbuilder::FWObject *obj);
    virtual void validate(bool*);
};

#endif // __IPRULEOPTIONSDIALOG_H_
