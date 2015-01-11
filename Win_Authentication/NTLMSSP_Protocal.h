#ifndef __NTLMSSP_PROTOCAL_H__
#define __NTLMSSP_PROTOCAL_H__

#include <QNetworkReply>
#include <string>
#include <Windows.h>

typedef DWORD NegotiateFlags;

struct DomainNameFields
{
	DomainNameFields() : wDomainNameLen(0), wDomainNameMaxLen(0), dwDomainNameBufferOffset(0) {}
	WORD wDomainNameLen;
	WORD wDomainNameMaxLen;
	DWORD dwDomainNameBufferOffset;
};

struct WorkstationFields
{
	WorkstationFields() : wWorkstationLen(0), wWorkstationMaxLen(0), dwWorkstationBufferOffset(0) {}
	WORD wWorkstationLen;
	WORD wWorkstationMaxLen;
	DWORD dwWorkstationBufferOffset;
};

struct NTLMVersion
{
	NTLMVersion(BYTE btMajorVer = 0, BYTE btMinorVer = 0, WORD btBuild = 0, BYTE btNTLMRevision = 0) 
		: btProductMajorVersion(btMajorVer), btProductMinorVersion(btMinorVer), wProductBuild(btBuild), btNTLMRevisionCurrent(btNTLMRevision)
	{
		memset(rgReverse, 0, sizeof(rgReverse));
	}
	BYTE btProductMajorVersion;
	BYTE btProductMinorVersion;
	WORD wProductBuild;
	BYTE rgReverse[3];
	BYTE btNTLMRevisionCurrent;
};

struct TargetNameFields
{
	TargetNameFields() :wTargetNameLen(0), wTargetNameMaxLen(0), dwTargetNameBufferOffset(0) {}
	WORD wTargetNameLen;
	WORD wTargetNameMaxLen;
	DWORD dwTargetNameBufferOffset;
};

struct ServerChallenge
{
	DWORD dwSC1;
	DWORD dwSC2;
};

struct TargetInfoFields
{
	TargetInfoFields() : wTargetInfoLen(0), wTargetInfoMaxLen(0), dwTargetInfoBufferOffset(0) {}
	WORD wTargetInfoLen;
	WORD wTargetInfoMaxLen;
	DWORD dwTargetInfoBufferOffset;
};

struct NTLMMSG_Negotiate
{
	NTLMMSG_Negotiate () : dwMsgType(1), dwMsgFlag(0xa2088207), version(6, 1, 7601, 15)
	{
		memcpy(rgSignature, "NTLMSSP", 8);
	}
	char rgSignature[8]; //'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	DWORD dwMsgType;	//4-bytes
	NegotiateFlags dwMsgFlag;	//4-bytes
	DomainNameFields domainNameFields; //8-bytes
	WorkstationFields workstationFiles; //8-bytes
	NTLMVersion version; //8-bytes
};

struct NTLMMSG_Challenge
{
	char rgSignature[8]; //'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	DWORD dwMsgType;	//4-bytes
	TargetNameFields targetNameFields;	//8-bytes
	NegotiateFlags negotiateFlags; //4-bytes
	ServerChallenge serverChallenge;
	struct Reserve
	{
		DWORD dwReserve1;
		DWORD dwReserve2;
	} reserve; //8-bytes
	TargetInfoFields targetInfoFields; //8-bytes
	NTLMVersion version;//8-bytes
};

struct NTLMMSG_Authenticate
{
	char rgSignature[8]; //'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	DWORD dwMsgType;	//4-bytes
};

class NTLMSSP_Protocal : public QObject
{
	Q_OBJECT

public:
	explicit NTLMSSP_Protocal(QObject* parent = 0);
	~NTLMSSP_Protocal();
	int GetSharePointVersionFromURL(const char* szUrl);

signals:
	void FinishGetSharepointVersion();

private slots:
	void ReplyQuest(QNetworkReply* reply);
	void DealWithAuthRequired(QNetworkReply* reply, QAuthenticator* authenticator);

private:
	void SendHttpRequest();

private:
	QNetworkAccessManager m_NetworkMgr;
	QVariant m_HttpStatusCode;
	std::string m_strUrl;
	std::string m_strVersion;
};


#endif //__NTLMSSP_PROTOCAL_H__