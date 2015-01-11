#include <QtCore/QCoreApplication>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>

#include "NTLMSSP_Protocal.h"

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);
	NTLMSSP_Protocal ntlmsspProtocal;
	ntlmsspProtocal.GetSharePointVersionFromURL("http://demo.infowisesolutions.com/");
	return a.exec();
}
