//////////////////////////////////////////////////////////////////////
//
// File           : HiddenNtRegistry.cpp
// Function       : Source file of the NT Native Registry API classes and the implementation of the hidden registry
// Author         : 3gstudent
// Notes          : Refer to Daniel Madden Sr's NtRegistry.
//					Link:
//					https://www.codeproject.com/Articles/14508/Registry-Manipulation-Using-NT-Native-APIs
//					Rewrite the CNtRegistry class.
//					Add the following functions:
//					- Create hidden key value
//					- Read hidden key value
//					- Delete hidden key value
//					Principle:
//						“In the Win32 API strings are interpreted as NULL-terminated ANSI (8-bit) or wide character 
//						(16-bit) strings. In the Native API names are counted Unicode (16-bit) strings. While this 
//						distinction is usually not important, it leaves open an interesting situation: there is a 
//						class of names that can be referenced using the Native API, but that cannot be described 
//						using the Win32 API. […] When a key (or any other object with a name such as a named Event, 
//						Semaphore or Mutex) is created with such a name any applications using the Win32 API will be 
//						unable to open the name, even though they might seem to see it.”
//					More explanation:
//					https://www.symantec.com/connect/blogs/kovter-malware-learns-poweliks-persistent-fileless-registry-update

#define WIN32_LEAN_AND_MEAN
#include "HiddenNtRegistry.h"

/****************************************************************************
**
**	Function:	MyOpenKey
**
**  Purpose:	OpenKey returns True if the key is successfully opened or created 
**
**  Arguments:	(IN)  char *	- Name of the value to open.
**
**	NOTE:  
**				HKEY_LOCAL_MACHINE:	is converted to =>  \Registry\Machine.
**				HKEY_CLASSES_ROOT:	is converted to =>  \Registry\Machine\SOFTWARE\Classes.
**				HKEY_USERS:			is converted to =>  \Registry\User.
**				HKEY_CURRENT_USER:	is converted to =>  \Registry\User\User_SID
**
**  Returns:	HANDLE - Handle of the NtOpenKey.
**				
****************************************************************************/

HANDLE MyOpenKey(char * csFullKey)
{
	UNICODE_STRING usKeyName;	
	HANDLE hKey = NULL;
	HANDLE hMachineReg = 0x00000000;
	ANSI_STRING asKey;
	RtlZeroMemory(&asKey,sizeof(asKey));
	RtlInitAnsiString(&asKey,csFullKey);
	RtlZeroMemory(&usKeyName,sizeof(usKeyName));
	RtlAnsiStringToUnicodeString(&usKeyName,&asKey,TRUE);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,&usKeyName,OBJ_CASE_INSENSITIVE,hMachineReg,NULL);

	NtStatus = NtOpenKey(&hKey, KEY_ALL_ACCESS, &ObjectAttributes);
	if(!NT_SUCCESS(NtStatus)) {
		printf("[!]NtOpenKey Error:%ul\n",NtStatus);
		exit(0);
	}
	printf("[+]NtOpenKey...\n");
	printf("   Path:	%s\n",csFullKey);
	printf("[*]Done.\n\n");
	return hKey;
}

/****************************************************************************
**
**	Function:	MyCreateKey
**
**  Purpose:	Use CreateKey to add a new key to the registry. 
**				
**  Arguments:	(IN)  char *	- Full name of the key to create.             
**
**  Returns:	BOOL - Success/Failure.
**				
****************************************************************************/
BOOL MyCreateKey(char * csName)
{
	HANDLE hKey = NULL;
	DWORD dwDisposition = 0;
	HANDLE hMachineReg = 0x00000000;
	ANSI_STRING asKey;
	RtlZeroMemory(&asKey,sizeof(asKey));
	RtlInitAnsiString(&asKey,csName);
	UNICODE_STRING usKeyName;
	RtlZeroMemory(&usKeyName,sizeof(usKeyName));
	RtlAnsiStringToUnicodeString(&usKeyName,&asKey,TRUE);
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,&usKeyName,OBJ_CASE_INSENSITIVE,hMachineReg,NULL);
	NtStatus = NtCreateKey(&hKey, 
							KEY_ALL_ACCESS, 
							&ObjectAttributes,
							0, 
							NULL, 
							REG_OPTION_NON_VOLATILE, 
							&dwDisposition);		
	if(!NT_SUCCESS(NtStatus)) {
		printf("[!]NtCreateKey Error:%ul\n",NtStatus);
		return FALSE;
	}
	printf("[+]NtCreateKey...\n");
	printf("   Value:	%s\n",csName);
	printf("[*]Done.\n\n");
	return TRUE;
}

/****************************************************************************
**
**	Function:	MySetValueKey
**
**  Purpose:	Use SetValueKey to write entries in the registry. 
**
**  Arguments:	(IN)  HANDLE	- Handle of the NtOpenKey.
**				(IN) - Name of the value.
**						Use "" to name the Default.
**				(IN) - Data of the value.
**				(IN) - Registry Type of the value.
**					Include:
**						REG_BINARY
**						REG_DWORD
**						REG_SZ
**						REG_DWORD_BIG_ENDIAN
**						REG_EXPAND_SZ
**						REG_LINK
**						REG_RESOURCE_LIST
**						REG_MULTI_SZ
**
**  Returns:	BOOL - Success/Failure.
**				
****************************************************************************/
BOOL MySetValueKey(HANDLE hKey,char *csName,char *csData,DWORD dwRegType)
{	
	ANSI_STRING asName;
	RtlZeroMemory(&asName,sizeof(asName));
	RtlInitAnsiString(&asName,csName);
	UNICODE_STRING ValueName;
	RtlZeroMemory(&ValueName,sizeof(ValueName));
	RtlAnsiStringToUnicodeString(&ValueName,&asName,TRUE);
	WCHAR wszValue[1024];
	unsigned int n ;
	for (n=0; n<strlen(csData); n++) {
		wszValue[n] = (WCHAR)csData[n];
	}
	wszValue[n++] = L'\0';
	NtStatus = NtSetValueKey( hKey, 
								&ValueName, 
								0, 
								dwRegType,
								wszValue, 
								(ULONG)strlen(csData) * sizeof(WCHAR));
	if(!NT_SUCCESS(NtStatus)) {
		printf("[!]NtSetValueKey Error:%ul\n",NtStatus);
		return FALSE;
	}
	printf("[+]NtSetValueKey...\n");
	printf("   Value:	%s\n",csName);
	printf("   Type:	%u\n",dwRegType);
	printf("   Data:	%s\n",csData);
	printf("[*]Done.\n\n");
	return TRUE;
}

/****************************************************************************
**
**	Function:	MyQueryValueKeyString
**
**  Purpose:	Use NtQueryValueKey to read string entries in the registry. 
**
**  Arguments:	(IN)  HANDLE	- Handle of the NtOpenKey.
**				(IN) - Name of the value to be read.
**
**  Returns:	BOOL - Success/Failure.
**				
****************************************************************************/

BOOL MyQueryValueKeyString(HANDLE hKey,char *csName)
{
	DWORD dwDataSize = 1024;
	BYTE *Buffer = NULL;
	ANSI_STRING asName;
	RtlZeroMemory(&asName,sizeof(asName));
	RtlInitAnsiString(&asName,csName);
	UNICODE_STRING ValueName;
	RtlZeroMemory(&ValueName,sizeof(ValueName));
	RtlAnsiStringToUnicodeString(&ValueName,&asName,TRUE);
	KEY_VALUE_PARTIAL_INFORMATION *info;
	NtStatus = STATUS_SUCCESS;
		if (NtQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, 
						NULL, 0, &dwDataSize) == STATUS_BUFFER_OVERFLOW)
	{
		do {
			Buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwDataSize + 1024 + sizeof(WCHAR));
			if (!Buffer) {
				printf("[!]HeapAlloc Error!\n");
				return FALSE;
			}
			NtStatus = NtQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, 
										 Buffer, dwDataSize, &dwDataSize);
		} while(NtStatus == STATUS_BUFFER_OVERFLOW);
	}
	else
	{
		Buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwDataSize + 1024);
		if (!Buffer) {
			printf("[!]HeapAlloc Error!\n");
			return FALSE;
		}
		NtStatus = NtQueryValueKey(hKey, 
									&ValueName, 
									KeyValuePartialInformation, 
									Buffer, 
									dwDataSize, 
									&dwDataSize );
	}
	info = (KEY_VALUE_PARTIAL_INFORMATION *)Buffer;
	char output[1024];
	for(unsigned int i=0;i<info->DataLength;i++)
	{
		output[i] = info->Data[i*2];
	}
	output[info->DataLength/2] = '\0';
	printf("[+]NtQueryValueKey...\n");
	printf("   Value:	%s\n",csName);
	printf("   Type:	REG_SZ\n");
	printf("   Length:	%d\n",info->DataLength/2);
	printf("   Data:	%s\n",output);
	printf("[*]Done.\n\n");
	return TRUE;
}

/****************************************************************************
**
**	Function:	MyDeleteKey
**
**  Purpose:	Call DeleteKey to remove a specified key and its associated data, 
**				if any. !!!Returns FALSE if there are subkeys.  Subkeys must be 
**				explicitly deleted by separate calls to DeleteKey.
**
**  Arguments:	(IN)  HANDLE	- Handle of the NtOpenKey.
**
**  Returns:	BOOL - Success/Failure.
**				
****************************************************************************/

BOOL MyDeleteKey(HANDLE hKey)
{
	NtStatus = NtDeleteKey(hKey);
	if(!NT_SUCCESS( NtStatus)) {
		printf("[!]NtDeleteKey Error:%ul\n",NtStatus);
		return FALSE;
	}
	printf("[+]NtDeleteKey...\n");
	printf("[*]Done.\n\n");
	return TRUE;
}

/****************************************************************************
**
**	Function:	MyDeleteValueKey
**
**  Purpose:	Call DeleteValue to remove a specific data value 
**				associated with the current key. Name is string 
**				containing the name of the value to delete. Keys can contain 
**				multiple data values, and every value associated with a key 
**				has a unique name. 
**
**  Arguments:	(IN)  HANDLE	- Handle of the NtOpenKey.
**              (IN)  char *	- Name of the value to delete.
**
**  Returns:	BOOL - Success/Failure.
**				
****************************************************************************/

BOOL MyDeleteValueKey(HANDLE hKey,char * csName)
{
	ANSI_STRING asName;
	RtlZeroMemory(&asName,sizeof(asName));
	RtlInitAnsiString(&asName,csName);
	UNICODE_STRING ValueName;
	RtlZeroMemory(&ValueName,sizeof(ValueName));
	RtlAnsiStringToUnicodeString(&ValueName,&asName,TRUE);
	NtStatus = NtDeleteValueKey(hKey, &ValueName);
	if(!NT_SUCCESS( NtStatus)) {
		printf("[!]NtDeleteValueKey Error:%ul\n",NtStatus);
		return FALSE;
	}
	printf("[+]NtDeleteValueKey...\n");
	printf("   Value:	%s\n",csName);
	printf("[*]Done.\n\n");
	return TRUE;
}

/****************************************************************************
**
**	Function:	MyCreateHiddenKey
**
**  Purpose:	Use CreateKey to add a hidden key to the registry. 
**				Win32 API cann't open it.
**
**  Arguments:	(IN)  char *	- Full name of the hidden key to create.             
**
**  Returns:	BOOL - Success/Failure.
**				
****************************************************************************/
BOOL MyCreateHiddenKey(char * csName)
{
	HANDLE hKey = NULL;
	DWORD dwDisposition = 0;
	HANDLE hMachineReg = 0x00000000;
	ANSI_STRING asKey;
	RtlZeroMemory(&asKey,sizeof(asKey));
	RtlInitAnsiString(&asKey,csName);
	UNICODE_STRING usKeyName;
	RtlZeroMemory(&usKeyName,sizeof(usKeyName));
	RtlAnsiStringToUnicodeString(&usKeyName,&asKey,TRUE);
	usKeyName.MaximumLength = usKeyName.Length += 2;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,&usKeyName,OBJ_CASE_INSENSITIVE,hMachineReg,NULL);
	NtStatus = NtCreateKey(&hKey, 
							 KEY_ALL_ACCESS, 
							 &ObjectAttributes,
							 0, 
							 NULL, 
							 REG_OPTION_NON_VOLATILE, 
							 &dwDisposition);
	if(!NT_SUCCESS(NtStatus)) {
		printf("[!]NtCreateKey Error:%ul\n",NtStatus);
		return FALSE;
	}
	printf("[+]NtCreateHiddenKey...\n");
	printf("   Value:	%s\n",csName);
	printf("[*]Done.\n\n");
	return TRUE;
}

/****************************************************************************
**
**	Function:	MyOpenHiddenKey
**
**  Purpose:	OpenKey returns True if the key is successfully opened or created 
**
**  Arguments:	(IN)  char *	- Name of the value to open.
**
**	NOTE:  
**				HKEY_LOCAL_MACHINE:	is converted to =>  \Registry\Machine.
**				HKEY_CLASSES_ROOT:	is converted to =>  \Registry\Machine\SOFTWARE\Classes.
**				HKEY_USERS:			is converted to =>  \Registry\User.
**				HKEY_CURRENT_USER:	is converted to =>  \Registry\User\User_SID
**
**  Returns:	HANDLE - Handle of the NtOpenKey.
**				
****************************************************************************/

HANDLE MyOpenHiddenKey(char * csHiddenKey)
{
	printf("****[Hidden Key Mode]****\n");
	UNICODE_STRING usKeyName;	
	HANDLE hKey = NULL;
	HANDLE hMachineReg = 0x00000000;
	ANSI_STRING asKey;
	RtlZeroMemory(&asKey,sizeof(asKey));
	RtlInitAnsiString(&asKey,csHiddenKey);
	RtlZeroMemory(&usKeyName,sizeof(usKeyName));
	RtlAnsiStringToUnicodeString(&usKeyName,&asKey,TRUE);
	usKeyName.MaximumLength = usKeyName.Length += 2;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,&usKeyName,OBJ_CASE_INSENSITIVE,hMachineReg,NULL);
	NtStatus = NtOpenKey(&hKey, KEY_ALL_ACCESS, &ObjectAttributes);
	if(!NT_SUCCESS(NtStatus)) {
		printf("[!]NtOpenKey Error:%ul\n",NtStatus);
		exit(0);
	}
	printf("[+]NtOpenHiddenKey...\n");
	printf("   Path:	%s\n",csHiddenKey);
	printf("[*]Done.\n\n");
	return hKey;
}

/****************************************************************************
**
**	Function:	MySetHiddenValueKey
**
**  Purpose:	Use SetValueKey to write entries in the registry. 
**
**  Arguments:	(IN) HANDLE	- Handle of the NtOpenKey.
**				(IN) - Name of the hidden value.
**						Use "" to name the Default.
**						Start with "\0"
**				(IN) - Data of the value.
**				(IN) - Registry Type of the value.
**					Include:
**						REG_BINARY
**						REG_DWORD
**						REG_SZ
**						REG_DWORD_BIG_ENDIAN
**						REG_EXPAND_SZ
**						REG_LINK
**						REG_RESOURCE_LIST
**						REG_MULTI_SZ
**
**  Returns:	BOOL - Success/Failure.
**				
****************************************************************************/

BOOL MySetHiddenValueKey(HANDLE hKey,char *csName,char *csData,DWORD dwRegType)
{	
	printf("****[Hidden Key Mode]****\n");	
	ANSI_STRING asName;
	RtlZeroMemory(&asName,sizeof(asName));
	RtlInitAnsiString(&asName,csName);
	asName.Length = strlen(csName+1)+1;
	asName.MaximumLength = strlen(csName+1)+1;
	UNICODE_STRING ValueName;
	RtlZeroMemory(&ValueName,sizeof(ValueName));
//	RtlAnsiStringToUnicodeString(&ValueName,&asName,TRUE);
	ValueName.Length = asName.Length*2;
	ValueName.MaximumLength = asName.MaximumLength*2;
	char *TempBuff;
	TempBuff = (char*)malloc(ValueName.Length);
	for(int i=0;i<asName.Length;i++)
	{
		TempBuff[i*2] = asName.Buffer[i];
		TempBuff[i*2+1] = 0x00;
	}
	ValueName.Buffer = (WCHAR *)TempBuff;
	WCHAR wszValue[1024];
	unsigned int n ;
	for (n=0; n<strlen(csData); n++) {
		wszValue[n] = (WCHAR)csData[n];
	}
	wszValue[n++] = L'\0';
	NtStatus = NtSetValueKey( hKey, 
								&ValueName, 
								0, 
								dwRegType,
								wszValue, 
								(ULONG)strlen(csData) * sizeof(WCHAR));
	if(!NT_SUCCESS(NtStatus)) {
		printf("[!]NtSetValueKey Error:%ul\n",NtStatus);
		return FALSE;
	}
	printf("[+]NtSetHiddenValueKey...\n");
	printf("   Value:	\\0%s\n",csName+1);
	printf("   Type:	%u\n",dwRegType);
	printf("   Data:	%s\n",csData);
	printf("[*]Done.\n\n");
	return TRUE;
}

/****************************************************************************
**
**	Function:	MyQueryHiddenValueKeyString
**
**  Purpose:	Use NtQueryValueKey to read string entries in the Hidden key. 
**
**  Arguments:	(IN) HANDLE	- Handle of the NtOpenKey.
**				(IN) - Name of the hidden value to be read.
**					    Start with "\0"
**
**  Returns:	BOOL - Success/Failure.
**				
****************************************************************************/

BOOL MyQueryHiddenValueKeyString(HANDLE hKey,char *csName)
{
	printf("****[Hidden Key Mode]****\n");		
	DWORD dwDataSize = 1024;
	BYTE *Buffer = NULL;
	ANSI_STRING asName;
	RtlZeroMemory(&asName,sizeof(asName));
	RtlInitAnsiString(&asName,csName);
	asName.Length = strlen(csName+1)+1;
	asName.MaximumLength = strlen(csName+1)+1;
	UNICODE_STRING ValueName;
	RtlZeroMemory(&ValueName,sizeof(ValueName));
//	RtlAnsiStringToUnicodeString(&ValueName+2,&asName,TRUE);
	ValueName.Length = asName.Length*2;
	ValueName.MaximumLength = asName.MaximumLength*2;
	char *TempBuff;
	TempBuff = (char*)malloc(ValueName.Length);
	for(int i=0;i<asName.Length;i++)
	{
		TempBuff[i*2] = asName.Buffer[i];
		TempBuff[i*2+1] = 0x00;
	}
	ValueName.Buffer = (WCHAR *)TempBuff;
	KEY_VALUE_PARTIAL_INFORMATION *info;
	NtStatus = STATUS_SUCCESS;
	if (NtQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, NULL, 0, &dwDataSize) == STATUS_BUFFER_OVERFLOW)
	{
		do {
			Buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwDataSize + 1024 + sizeof(WCHAR));
			if (!Buffer) {
				printf("[!]HeapAlloc Error!\n");
				return FALSE;
			}
			NtStatus = NtQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, Buffer, dwDataSize, &dwDataSize);
		} while(NtStatus == STATUS_BUFFER_OVERFLOW);
	}
	else
	{
		Buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwDataSize + 1024);
		if (!Buffer) {
			printf("[!]HeapAlloc Error!\n");
			return FALSE;
		}
		NtStatus = NtQueryValueKey(hKey, 
									&ValueName, 
									KeyValuePartialInformation, 
									Buffer, 
									dwDataSize, 
									&dwDataSize );
	}
	info = (KEY_VALUE_PARTIAL_INFORMATION *)Buffer;
	char output[1024];
	for(unsigned int i=0;i<info->DataLength;i++)
	{
		output[i] = info->Data[i*2];
	}
	output[info->DataLength/2] = '\0';
	printf("[+]NtQueryHiddenValueKey...\n");
	printf("   Value:	\\0%s\n",csName+1);
	printf("   Type:	REG_SZ\n");
	printf("   Length:	%d\n",info->DataLength/2);
	printf("   Data:	%s\n",output);
	printf("[*]Done.\n\n");
	return TRUE;
}

/****************************************************************************
**
**	Function:	MyDeleteHiddenValueKey
**
**  Purpose:	Call DeleteValue to remove a specific data value 
**				associated with the current key. Name is string 
**				containing the name of the value to delete. Keys can contain 
**				multiple data values, and every value associated with a key 
**				has a unique name. 
**
**  Arguments:	(IN)  HANDLE	- Handle of the NtOpenKey.
**              (IN)  char *	- Name of the hidden value to delete.
**					               Start with "\0"
**
**  Returns:	BOOL - Success/Failure.
**				
****************************************************************************/

BOOL MyDeleteHiddenValueKey(HANDLE hKey,char * csName)
{
	printf("****[Hidden Key Mode]****\n");		
	ANSI_STRING asName;
	RtlZeroMemory(&asName,sizeof(asName));
	RtlInitAnsiString(&asName,csName);
	asName.Length = strlen(csName+1)+1;
	asName.MaximumLength = strlen(csName+1)+1;	
	UNICODE_STRING ValueName;
	RtlZeroMemory(&ValueName,sizeof(ValueName));
//	RtlAnsiStringToUnicodeString(&ValueName,&asName,TRUE);
	ValueName.Length = asName.Length*2;
	ValueName.MaximumLength = asName.MaximumLength*2;
	char *TempBuff;
	TempBuff = (char*)malloc(ValueName.Length);
	for(int i=0;i<asName.Length;i++)
	{
		TempBuff[i*2] = asName.Buffer[i];
		TempBuff[i*2+1] = 0x00;
	}
	ValueName.Buffer = (WCHAR *)TempBuff;
	NtStatus = NtDeleteValueKey(hKey, &ValueName);
	if(!NT_SUCCESS( NtStatus)) {
		printf("[!]NtDeleteValueKey Error:%ul\n",NtStatus);
		return FALSE;
	}
	printf("[+]NtDeleteHiddenValueKey...\n");
	printf("   Value:	\\0%s\n",csName+1);
	printf("[*]Done.\n\n");
	return TRUE;
}

int _tmain( int argc, _TCHAR* argv[] )
{
	HINSTANCE hinstStub = GetModuleHandle(_T("ntdll.dll"));
	if(hinstStub) 
	{
		NtOpenKey = (LPNTOPENKEY)GetProcAddress(hinstStub, "NtOpenKey");
		if (!NtOpenKey) 
		{
			printf("Could not find NtOpenKey entry point in NTDLL.DLL");
			return FALSE;
		}
		NtCreateKey = (LPNTCREATEKEY)GetProcAddress(hinstStub, "NtCreateKey");
		if (!NtCreateKey) 
		{
			printf("Could not find NtCreateKey entry point in NTDLL.DLL");
			return FALSE;
		}
		NtSetValueKey = (LPNTSETVALUEKEY)GetProcAddress(hinstStub, "NtSetValueKey");
		if (!NtSetValueKey)
		{
			printf("Could not find NTSetValueKey entry point in NTDLL.DLL");
			return FALSE;
		}
		NtQueryValueKey = (LPNTQUERYVALUEKEY)GetProcAddress(hinstStub, "NtQueryValueKey");
		if (!NtQueryValueKey)
		{
			printf("Could not find NtQueryValueKey entry point in NTDLL.DLL");
			return FALSE;
		}
		NtDeleteKey = (LPNTDELETEKEY)GetProcAddress(hinstStub, "NtDeleteKey");
		if (!NtDeleteKey) {
			printf("Could not find NtDeleteKey entry point in NTDLL.DLL");
			return FALSE;
		}
		NtDeleteValueKey = (LPNTDELETEVALUEKEY)GetProcAddress(hinstStub, "NtDeleteValueKey");
		if (!NtDeleteValueKey)
		{
			printf("Could not find NtDeleteValueKey entry point in NTDLL.DLL");
			return FALSE;
		}
		NtClose = (LPNTCLOSE)GetProcAddress(hinstStub, "NtClose");
		if (!NtClose) {
			printf("Could not find NtClose entry point in NTDLL.DLL");
			return FALSE;
		}
	}
	else
	{
		printf("Could not GetModuleHandle of NTDLL.DLL");
		return FALSE;
	}
	RtlInitAnsiString = (LPRTLINITANSISTRING)GetProcAddress(hinstStub, "RtlInitAnsiString");
	RtlAnsiStringToUnicodeString = (LPRTLANSISTRINGTOUNICODESTRING)GetProcAddress(hinstStub, "RtlAnsiStringToUnicodeString");

	HANDLE hKey;
	printf("=================Test 0=================\n");
	printf("=================Normal Mode============\n");
	printf("1.CreateKey:\n");
	MyCreateKey("\\Registry\\Machine\\Software\\test");
	printf("2.OpenKey:\n");
	hKey = MyOpenKey("\\Registry\\Machine\\Software\\test");
	printf("3.SetValueKey:\n");
	MySetValueKey(hKey,"test0","0123456789abcdef",REG_SZ);
	printf("4.QueryValueKey:\n");
	MyQueryValueKeyString(hKey,"test0");
	printf("5.DeleteValueKey:\n");
	MyDeleteValueKey(hKey,"test0");
	printf("6.DeleteKey:\n");
	MyDeleteKey(hKey);
	NtClose(hKey);

	printf("=================Test 1=================\n");
	printf("=================Hidden Key Mode========\n");
	printf("Normal User can't visit the hidden key.\n");
	printf("1.CreateHiddenKey:\n");
	MyCreateHiddenKey("\\Registry\\Machine\\Software\\testhidden");
	printf("2.OpenHiddenKey:\n");
	hKey = MyOpenHiddenKey("\\Registry\\Machine\\Software\\testhidden");
	printf("3.SetValueKey:\n");
	MySetValueKey(hKey,"test1","0123456789abcdef",REG_SZ);
	printf("4.QueryValueKey:\n");
	MyQueryValueKeyString(hKey,"test1");
	printf("5.DeleteValueKey:\n");
	MyDeleteValueKey(hKey,"test1");
	printf("6.DeleteKey:\n");
	MyDeleteKey(hKey);
	NtClose(hKey);

	printf("=================Test 2=================\n");
	printf("=================Hidden KeyValue Mode===\n");
	printf("Normal User can visit the key,but can't visit the key value\n");
	printf("1.CreateKey:\n");
	MyCreateKey("\\Registry\\Machine\\Software\\test2");
	printf("2.OpenKey:\n");
	hKey = MyOpenKey("\\Registry\\Machine\\Software\\test2");
	printf("3.SetHiddenValueKey:\n");
	MySetHiddenValueKey(hKey,"\0test2","0123456789abcdef",REG_SZ);
	printf("4.QueryHiddenValueKey:\n");
	MyQueryHiddenValueKeyString(hKey,"\0test2");
	printf("5.DeleteHiddenValueKey:\n");
	MyDeleteHiddenValueKey(hKey,"\0test2");
	printf("6.DeleteKey:\n");
	MyDeleteKey(hKey);
	NtClose(hKey);

}
