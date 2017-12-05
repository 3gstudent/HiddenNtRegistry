#include <windows.h>
#include <stdlib.h>

#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))
#define STATUS_SUCCESS				((NTSTATUS)0x00000000L) // ntsubauth
#define STATUS_BUFFER_OVERFLOW		((NTSTATUS)0x80000005L)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)
#define OBJ_CASE_INSENSITIVE	0x00000040L
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
    }
typedef ULONG NTSTATUS, *PNTSTATUS;
typedef struct _UNICODE_STRING 
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef struct _STRING 
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;
typedef STRING OEM_STRING;
typedef STRING *POEM_STRING;
typedef STRING ANSI_STRING;
typedef STRING *PANSI_STRING;

typedef enum _KEY_INFORMATION_CLASS 
{
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation
} KEY_INFORMATION_CLASS;

typedef NTSTATUS (STDAPICALLTYPE RTLINITANSISTRING)
(
	IN OUT PANSI_STRING DestinationString,
	IN LPCSTR SourceString
);
typedef RTLINITANSISTRING FAR * LPRTLINITANSISTRING;

typedef NTSTATUS (STDAPICALLTYPE RTLANSISTRINGTOUNICODESTRING)
(
	IN OUT PUNICODE_STRING	DestinationString,
	IN PANSI_STRING			SourceString,
	IN BOOLEAN				AllocateDestinationString
);
typedef RTLANSISTRINGTOUNICODESTRING FAR * LPRTLANSISTRINGTOUNICODESTRING;

typedef struct _KEY_BASIC_INFORMATION 
{
	LARGE_INTEGER LastWriteTime;// The last time the key or any of its values changed.
	ULONG TitleIndex;			// Device and intermediate drivers should ignore this member.
	ULONG NameLength;			// The size in bytes of the following name, including the zero-terminating character.
	WCHAR Name[1];				// A zero-terminated Unicode string naming the key.
} KEY_BASIC_INFORMATION;
typedef KEY_BASIC_INFORMATION *PKEY_BASIC_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION 
{
	ULONG TitleIndex;	// Device and intermediate drivers should ignore this member.
	ULONG Type;			// The system-defined type for the registry value in the 
						// Data member (see the values above).
	ULONG DataLength;	// The size in bytes of the Data member.
	UCHAR Data[1];		// A value entry of the key.
} KEY_VALUE_PARTIAL_INFORMATION;
typedef KEY_VALUE_PARTIAL_INFORMATION *PKEY_VALUE_PARTIAL_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS 
{
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
} KEY_VALUE_INFORMATION_CLASS;

typedef NTSTATUS (STDAPICALLTYPE NTOPENKEY)
(
	IN HANDLE				KeyHandle,
	IN ULONG				DesiredAccess,
	IN POBJECT_ATTRIBUTES	ObjectAttributes
);
typedef NTOPENKEY FAR * LPNTOPENKEY;

typedef NTSTATUS (STDAPICALLTYPE NTCREATEKEY)
(
	IN HANDLE				KeyHandle, 
	IN ULONG				DesiredAccess, 
	IN POBJECT_ATTRIBUTES	ObjectAttributes,
	IN ULONG				TitleIndex, 
	IN PUNICODE_STRING		Class,			/* optional*/
	IN ULONG				CreateOptions, 
	OUT PULONG				Disposition		/* optional*/
);
typedef NTCREATEKEY FAR * LPNTCREATEKEY;

typedef NTSTATUS (STDAPICALLTYPE NTDELETEKEY)
(
	IN HANDLE KeyHandle
);
typedef NTDELETEKEY FAR * LPNTDELETEKEY;

typedef NTSTATUS (STDAPICALLTYPE NTSETVALUEKEY)
(
	IN HANDLE			KeyHandle,
	IN PUNICODE_STRING	ValueName,
	IN ULONG			TitleIndex,			/* optional */
	IN ULONG			Type,
	IN PVOID			Data,
	IN ULONG			DataSize
);
typedef NTSETVALUEKEY FAR * LPNTSETVALUEKEY;

typedef NTSTATUS (STDAPICALLTYPE NTQUERYVALUEKEY)
(
	IN HANDLE			KeyHandle,		 
	IN PUNICODE_STRING	ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID			KeyValueInformation,
	IN ULONG			Length,
	OUT PULONG			ResultLength
);
typedef NTQUERYVALUEKEY FAR * LPNTQUERYVALUEKEY;

typedef NTSTATUS (STDAPICALLTYPE NTDELETEVALUEKEY)
(
    IN HANDLE			KeyHandle,
    IN PUNICODE_STRING	ValueName
);
typedef NTDELETEVALUEKEY FAR * LPNTDELETEVALUEKEY;

typedef NTSTATUS (STDAPICALLTYPE NTCLOSE)
(
	IN HANDLE KeyHandle
);
typedef NTCLOSE FAR * LPNTCLOSE;

LPRTLINITANSISTRING				RtlInitAnsiString;
LPRTLANSISTRINGTOUNICODESTRING	RtlAnsiStringToUnicodeString;
LPNTOPENKEY					NtOpenKey;
LPNTCREATEKEY	            NtCreateKey;
LPNTSETVALUEKEY				NtSetValueKey;
LPNTQUERYVALUEKEY			NtQueryValueKey;
LPNTDELETEKEY				NtDeleteKey;
LPNTDELETEVALUEKEY			NtDeleteValueKey;
LPNTCLOSE					NtClose;

NTSTATUS NtStatus = STATUS_SUCCESS;
