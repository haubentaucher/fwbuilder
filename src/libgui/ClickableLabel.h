#ifndef CLICKABLELABEL_H
#define CLICKABLELABEL_H

#include <QLabel>

class ClickableLabel : public QLabel
{
    Q_OBJECT
public:
    ClickableLabel(QWidget *parent = 0, Qt::WindowFlags f = Qt::WindowFlags() );
    void mousePressEvent(QMouseEvent *);

signals:
    void clicked();
};

#endif // CLICKABLELABEL_H
