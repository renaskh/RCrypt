#include "rcrypt.h"
#include "QtCore"

QString key = "0000000000000000";
quint8 iv_16[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

QString RCrypt::EncString(QString input)
{
    QByteArray iv;
    for (int i=0; i<16; i++)
        iv.append(iv_16[i]);

    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);


    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray encodeText = encryption.encode(input.toLocal8Bit(), hashKey, iv);

    return encodeText.toHex().toUpper();
}
QString RCrypt::DecString(QString input)
{
    QByteArray iv;
    for (int i=0; i<16; i++)
        iv.append(iv_16[i]);

    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray encodeText = encryption.decode(QByteArray::fromHex(input.toLocal8Bit()), hashKey, iv);

    return encryption.removePadding(encodeText);
}


bool RCrypt::EncFile(QString fpath,QString spath)
{
    QByteArray iv;
    for (int i=0; i<16; i++)
        iv.append(iv_16[i]);

    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);
    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);

    QFile file(fpath);
    if (!file.open(QFile::ReadOnly))
        return false;

    QByteArray encodeText = encryption.encode(file.readAll(), hashKey, iv);
    file.close();

    QFile save_file(spath);
    if (!save_file.open(QFile::ReadWrite))
        return false;

    save_file.write(encodeText);
    save_file.close();

    return true;
}

bool RCrypt::DecFile(QString fpath,QString spath)
{
    QByteArray iv;
    for (int i=0; i<16; i++)
        iv.append(iv_16[i]);

    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);
    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);

    QFile file(fpath);
    if (!file.open(QFile::ReadOnly))
        return false;

    QByteArray encodeText = encryption.decode(file.readAll(), hashKey, iv);
    file.close();

    QFile save_file(spath);
    if (!save_file.open(QFile::ReadWrite))
        return false;

    save_file.write(encryption.removePadding(encodeText));
    save_file.close();

    return true;
}


QByteArray RCrypt::EncToBuff(QString fpath)
{
    QByteArray iv;
    for (int i=0; i<16; i++)
        iv.append(iv_16[i]);

    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);
    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);

    QFile file(fpath);
    if (!file.open(QFile::ReadOnly))
        return QByteArray();

    QByteArray encodeText = encryption.encode(file.readAll(), hashKey, iv);
    file.close();
    return encodeText;
}

QByteArray RCrypt::DecToBuff(QString fpath)
{
    QByteArray iv;
    for (int i=0; i<16; i++)
        iv.append(iv_16[i]);

    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);
    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);

    QFile file(fpath);
    if (!file.open(QFile::ReadOnly))
        return QByteArray();

    QByteArray encodeText = encryption.decode(file.readAll(), hashKey, iv);
    file.close();

    return encryption.removePadding(encodeText);;
}
