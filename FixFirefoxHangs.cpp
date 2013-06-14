// FixFirefoxHangs.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "FixFirefoxHangs.h"

bool IsUserAdmin();

// Returns false if we don't have administrator rights to fix the registry.
// Returns true if the registry is fixed or there exits no error with the registry.
bool FixRegisrty(bool bIsUserAdmin);

bool FixOverlayHandler(LPCTSTR szName, bool bIsUserAdmin);

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	bool isUserAdmin = IsUserAdmin();
	if (!FixRegisrty(isUserAdmin) && !isUserAdmin)
	{
		// We need administrator rights to write the registry.
		TCHAR szFileName[MAX_PATH];
		if (::GetModuleFileName(NULL, szFileName, MAX_PATH))
		{
			::ShellExecute(NULL, _T("runas"), szFileName, NULL, NULL, SW_HIDE);
		}
	}

	return 0;
}

/*++ 
http://msdn.microsoft.com/en-us/library/aa376389%28v=VS.85%29.aspx
Routine Description: This routine returns TRUE if the caller's
process is a member of the Administrators local group. Caller is NOT
expected to be impersonating anyone and is expected to be able to
open its own process and process token. 
Arguments: None. 
Return Value: 
TRUE - Caller has Administrators local group. 
FALSE - Caller does not have Administrators local group. --
*/ 
bool IsUserAdmin()
{
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup; 
	b = AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup); 
	if(b) 
	{
		if (!CheckTokenMembership( NULL, AdministratorsGroup, &b)) 
		{
			b = FALSE;
		} 
		FreeSid(AdministratorsGroup); 
	}

	return b != 0;
}

static LPCTSTR ROOT_KEY = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\");

void TRACE_ERROR(LPCTSTR lpTag, DWORD dwErrorCode)
{
#ifdef _DEBUG
	static const int BUFFER_LENGTH = 1024;
	CString strMsg; 
	TCHAR msgBuf[BUFFER_LENGTH];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msgBuf, BUFFER_LENGTH, NULL);
	CString strOutput;
	strOutput.Format(_T("[%s] %s\n"), lpTag, msgBuf);
	OutputDebugString(strOutput);
#endif
}

// Returns false if we don't have administrator rights to fix the registry.
// Returns true if the registry is fixed or there exits no error with the registry.
bool FixRegisrty(bool bIsUserAdmin)
{
	static const int MAX_KEY_LENGTH = 255;

	// Enumerates subkeys under HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers
	HKEY hKey;
	if (ERROR_SUCCESS != ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, ROOT_KEY, 0, bIsUserAdmin ? KEY_ALL_ACCESS : KEY_READ, &hKey))
	{
		TRACE_ERROR(_T("FixRegisrty"), ::GetLastError());
		return false;
	}

	bool success = true;

	DWORD i = 0; // subkey index
	TCHAR szSubKey[MAX_KEY_LENGTH]; // buffer for subkey name
	DWORD cbName = MAX_KEY_LENGTH; // size of name string 
	while (::RegEnumKeyEx(hKey, i, szSubKey, &cbName, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
	{
		if (!FixOverlayHandler(szSubKey, bIsUserAdmin))
		{
			success = false;
			break;
		}
		cbName = MAX_KEY_LENGTH;
		++i;
	}

	::RegCloseKey(hKey);
	return success;
}

CString GetRegistryKeyDefaultValue(HKEY hKey, LPCTSTR lpSubKey)
{
	CString result;

	static const int MAX_VALUE_LENGTH = 1024;
	HKEY hSubKey;
	if (ERROR_SUCCESS != ::RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ, &hSubKey))
	{
		TRACE_ERROR(_T("GetRegistryKeyDefaultValue"), ::GetLastError());
		return result;
	}

	TCHAR szBuffer[MAX_VALUE_LENGTH] = _T("");
	DWORD cbBuffer = sizeof(szBuffer);
	if (ERROR_SUCCESS == ::RegQueryValueEx(hSubKey, NULL, NULL, NULL, reinterpret_cast<LPBYTE>(szBuffer), &cbBuffer))
	{
		szBuffer[cbBuffer / 2] = _T('\0');
		result = szBuffer;
	}
	::RegCloseKey(hKey);

	return result;
}

bool FixOverlayHandler(LPCTSTR szName, bool bIsUserAdmin)
{
	// Get the overlay handler CLSID
	// http://msdn.microsoft.com/en-us/library/windows/desktop/hh127455%28v=vs.85%29.aspx
	CString keyName;
	keyName.Format(_T("%s%s\\"), ROOT_KEY, szName);
	CString strCLSID = GetRegistryKeyDefaultValue(HKEY_LOCAL_MACHINE, keyName);

	// Get the COM file path of the overlay handler
	keyName.Format(_T("CLSID\\%s\\InprocServer32\\"), strCLSID);
	CString strValue = GetRegistryKeyDefaultValue(HKEY_CLASSES_ROOT, keyName);
	if (strValue.IsEmpty())
	{
		keyName.Format(_T("CLSID\\%s\\LocalServer32\\"), strCLSID);
		strValue = GetRegistryKeyDefaultValue(HKEY_CLASSES_ROOT, keyName);
	}

	// Check if the COM file exists 
	if (!strValue.IsEmpty())
	{
		CString strPath;
		::ExpandEnvironmentStrings(static_cast<LPCTSTR>(strValue), strPath.GetBuffer(MAX_PATH), MAX_PATH);
		strPath.ReleaseBuffer();

		if (!::PathFileExists(strPath))
		{
			if (!bIsUserAdmin)
			{
				return false;
			}
			keyName.Format(_T("%s%s"), ROOT_KEY, szName);
			if (ERROR_SUCCESS != ::RegDeleteKey(HKEY_LOCAL_MACHINE, static_cast<LPCTSTR>(keyName)))
			{
				TRACE_ERROR(_T("GetRegistryKeyDefaultValue"), ::GetLastError());
				return false;
			}
		}
	}
	return true;
}