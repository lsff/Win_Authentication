#include "NTLMSSP_Protocal.h"
#include <Windows.h>
#include <QEventLoop>
#include <QNetworkProxy>
#include <QAbstractNetworkCache>
#include <QAuthenticator>
#include <wincred.h>
#include <NTSecAPI.h>
#include <atlconv.h>

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif //SECURITY_WIN32
#include <Sspi.h>
#include <Ntsecpkg.h>
#include <ntstatus.h>

void getCredentials(const char * proxyIp, int proxyPort, char * proxType, QString &user, QString &password);
bool findCredentials(const char * proxyIp, QString &user, QString &password);
bool getNTLM_Authentication(const char * proxyIp);

NTLMSSP_Protocal::NTLMSSP_Protocal(QObject* parent /*= 0*/) 
{
	connect(&m_NetworkMgr, SIGNAL(finished(QNetworkReply*)), this, SLOT(ReplyQuest(QNetworkReply*)));
	connect(&m_NetworkMgr, SIGNAL(authenticationRequired(QNetworkReply*, QAuthenticator*)), this, SLOT(DealWithAuthRequired(QNetworkReply*, QAuthenticator*)));
	m_NetworkMgr.proxyFactory()->setUseSystemConfiguration(true);
}

NTLMSSP_Protocal::~NTLMSSP_Protocal()
{

}

int NTLMSSP_Protocal::GetSharePointVersionFromURL(const char* szUrl)
{
	QEventLoop loop;
	m_strUrl.assign(szUrl);
	connect(this, SIGNAL(FinishGetSharepointVersion()), &loop, SLOT(quit()));
	SendHttpRequest();
	loop.exec();
	int iSharePointVersiong = 0;
	if (m_HttpStatusCode.toInt() == 200)
	{
		//todo: 获取正确的版本号
	}
	return iSharePointVersiong;
}

void NTLMSSP_Protocal::ReplyQuest(QNetworkReply * reply)
{
	m_HttpStatusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
	if (m_HttpStatusCode.toInt() == 200)
	{
		if (reply->hasRawHeader("MicrosoftSharePointTeamServices"))
			m_strVersion = reply->rawHeader("MicrosoftSharePointTeamServices").constData();
	}
	emit FinishGetSharepointVersion();
	return;
}

void NTLMSSP_Protocal::SendHttpRequest()
{
	QNetworkRequest request(QUrl(m_strUrl.c_str()));
	request.setRawHeader("User-Agent", "Kingsoft-WPS-SpreadSheet");
	QNetworkReply* reply = m_NetworkMgr.sendCustomRequest(request, "OPTIONS");
}

void NTLMSSP_Protocal::DealWithAuthRequired(QNetworkReply* reply, QAuthenticator* authenticator)
{
	QString qUser, qPwd;
	getNTLM_Authentication(QUrl(m_strUrl.c_str()).host().toStdString().c_str());
	findCredentials(QUrl(m_strUrl.c_str()).host().toStdString().c_str(), qUser, qPwd);
	getCredentials(QUrl(m_strUrl.c_str()).host().toStdString().c_str(), 0, NULL, qUser, qPwd);
	authenticator->setUser(qUser);
	authenticator->setPassword(qPwd);
}

bool getNTLM_Authentication(const char * proxyIp)
{
	USES_CONVERSION;
	ULONG uSecurityPackages = 0;
	PSecPkgInfo pSecPkgInfo = 0;
	SECURITY_STATUS sStatus = EnumerateSecurityPackages(&uSecurityPackages, &pSecPkgInfo);
	if (pSecPkgInfo)
		FreeContextBuffer(pSecPkgInfo);
	CredHandle credHandle = {0};
	TimeStamp timeStamp = {0};
	sStatus = AcquireCredentialsHandleA(NULL, "NTLM", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &credHandle, &timeStamp);
	if (SEC_E_OK == sStatus)
	{
		TCHAR szTargetName[CREDUI_MAX_DOMAIN_TARGET_LENGTH] = {0};
		swprintf_s(szTargetName, CREDUI_MAX_DOMAIN_TARGET_LENGTH, L"HTTP/%s", A2W(proxyIp));
		CtxtHandle newCtxtHandle = {0};
		SecBufferDesc inputSecBufferDesc = {0};
		SecBufferDesc newSecBufferDesc = {0};
		ULONG fContextAttr = ISC_RET_CALL_LEVEL | ISC_RET_INTERMEDIATE_RETURN | ISC_RET_USED_DCE_STYLE | ISC_RET_USED_SUPPLIED_CREDS;
		sStatus = InitializeSecurityContext(
			&credHandle, 
			NULL, 
			szTargetName, 
			ISC_REQ_DELEGATE | ISC_REQ_ALLOCATE_MEMORY, 
			0, 
			SECURITY_NATIVE_DREP, 
			NULL, 
			0, 
			&newCtxtHandle, 
			&newSecBufferDesc, 
			&fContextAttr, 
			&timeStamp);
		if (sStatus == SEC_I_CONTINUE_NEEDED)
		{
			bool bContinue = true;
		}
		if (newSecBufferDesc.pBuffers)
			FreeContextBuffer(newSecBufferDesc.pBuffers);

	}
	return true;
}

bool findCredentials(const char * proxyIp, QString &user, QString &password)
{
	USES_CONVERSION;

	CREDENTIAL_TARGET_INFORMATION targetInfo = {0};
	targetInfo.TargetName = A2W(proxyIp);
	targetInfo.DnsDomainName = A2W(proxyIp);
	DWORD dwCredType = CRED_TYPE_DOMAIN_PASSWORD;
	targetInfo.CredTypes = &dwCredType;
	targetInfo.CredTypeCount = 1;
	DWORD dwCount = 0;
	PCREDENTIAL* pCredential = NULL;
	bool bFind = CredReadDomainCredentials(&targetInfo, CRED_CACHE_TARGET_INFORMATION, &dwCount, &pCredential);
	if (pCredential)
		CredFree(pCredential);
	return true;
}

void getCredentials(const char * proxyIp, int proxyPort, char * proxType, QString &user, QString &password)
{
	//Log.info("Credentials", L"About to read credentials for [%hs] [%d] [%hs]",proxyIp,proxyPort,proxType);
	HRESULT hr = S_OK;
	DWORD   dwResult;
	PVOID   pvInAuthBlob = NULL;
	ULONG   cbInAuthBlob = 0;
	PVOID   pvAuthBlob = NULL;
	ULONG   cbAuthBlob = 0;
	CREDUI_INFOW ui;
	ULONG   ulAuthPackage = 0;
	BOOL    fSave = FALSE;
	TCHAR pszName[CREDUI_MAX_USERNAME_LENGTH+1];
	TCHAR pszPwd[CREDUI_MAX_PASSWORD_LENGTH+1];
	TCHAR domain[CREDUI_MAX_DOMAIN_TARGET_LENGTH+1];
	DWORD maxLenName =  CREDUI_MAX_USERNAME_LENGTH+1;
	DWORD maxLenPassword =  CREDUI_MAX_PASSWORD_LENGTH+1;
	DWORD maxLenDomain = CREDUI_MAX_DOMAIN_TARGET_LENGTH+1;
	TCHAR pszCaption[CREDUI_MAX_CAPTION_LENGTH] = {0};

	// Display a dialog box to request credentials.
	ui.cbSize = sizeof(ui);
	ui.hwndParent = GetConsoleWindow();
	ui.pszMessageText = L"输入您的凭据";
	USES_CONVERSION;
	swprintf_s(pszCaption, CREDUI_MAX_CAPTION_LENGTH, L"连接到 %s", A2W(proxyIp));
	ui.pszCaptionText = pszCaption;
	ui.hbmBanner = NULL;

	dwResult = CredUIPromptForWindowsCredentialsW(
		&ui,             // Customizing information
		0,               // Error code to display
		&ulAuthPackage,  // Authorization package
		pvInAuthBlob,    // Credential byte array
		cbInAuthBlob,    // Size of credential input buffer
		&pvAuthBlob,     // Output credential byte array
		&cbAuthBlob,     // Size of credential byte array
		&fSave,          // Select the save check box.
		CREDUIWIN_CHECKBOX | CREDUIWIN_ENUMERATE_CURRENT_USER
		);
	if (dwResult == NO_ERROR)
	{
		//Log.info("Credentials", L"cred read success");
		CredUnPackAuthenticationBufferW(
			CRED_PACK_PROTECTED_CREDENTIALS,
			pvAuthBlob,
			cbAuthBlob,
			pszName,
			&maxLenName,
			domain,
			&maxLenDomain,
			pszPwd,
			&maxLenPassword);

		if (fSave)
		{
			CREDENTIAL saveCredential;
			saveCredential.Flags = 0;
			saveCredential.Type = CRED_TYPE_GENERIC;
			saveCredential.TargetName = A2W(proxyIp);
			saveCredential.Comment = NULL;
			saveCredential.CredentialBlob = (BYTE*)pvAuthBlob;
			saveCredential.CredentialBlobSize = cbAuthBlob;
			saveCredential.Persist = CRED_PERSIST_LOCAL_MACHINE;
			saveCredential.AttributeCount = 0;
			saveCredential.Attributes = NULL;
			saveCredential.TargetAlias = NULL;
			saveCredential.UserName = pszName;
			CredWrite(&saveCredential, 0);
		}

		SecureZeroMemory(pvAuthBlob, cbAuthBlob);
		CoTaskMemFree(pvAuthBlob);
		pvAuthBlob = NULL;
		user = QString::fromUtf16((const ushort*)pszName);
		password = QString::fromUtf16((const ushort*)pszPwd);
		SecureZeroMemory(pszName, sizeof(pszName));
		SecureZeroMemory(pszPwd, sizeof(pszPwd));
	}else
	{
		//Log.info("Credentials", L"cred read fail");

		hr = HRESULT_FROM_WIN32(dwResult);
		if (pvInAuthBlob)
		{
			SecureZeroMemory(pvInAuthBlob, cbInAuthBlob);
			CoTaskMemFree(pvInAuthBlob);
			pvInAuthBlob = NULL;
		}
	}

}