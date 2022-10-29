#ifndef RCRYPT_H
#define RCRYPT_H

#include "qaesencryption.h"
#include "QCryptographicHash"

class RCrypt
{
public:
    static QString EncString(QString);
    static QString DecString(QString);
    static bool DecFile(QString,QString);
    static bool EncFile(QString,QString);
    static QByteArray DecToBuff(QString);
    static QByteArray EncToBuff(QString);
};

#endif // RCRYPT_H
