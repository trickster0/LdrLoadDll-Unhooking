#include <Windows.h>
#include <stdio.h>

#define OBJ_CASE_INSENSITIVE 0x00000040L


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

using pNewLdrLoadDll = NTSTATUS(NTAPI*)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);


PVOID CCopyMemory(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

SIZE_T StringLengthW(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = StringLengthW(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

int main()
{
	pNewLdrLoadDll LdrLoadrDll;
	UNICODE_STRING ldrldll;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	wchar_t ldrstring[] = L"Wininet.dll";
	
	//Obtaining LdrLoadDll Address from loaded NTDLL
	RtlInitUnicodeString(&ldrldll, ldrstring);
	InitializeObjectAttributes(&objectAttributes, &ldrldll, OBJ_CASE_INSENSITIVE, NULL, NULL);
	LPVOID origLdrLoadDll = GetProcAddress(GetModuleHandleA("ntdll.dll"),"LdrLoadDll");
	
	//Setting up the structure of the trampoline for the instructions
	unsigned char jumpPrelude[] = { 0x49, 0xBB };
	unsigned char jumpAddress[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
	unsigned char jumpEpilogue[] = { 0x41, 0xFF, 0xE3, 0xC3 };
	LPVOID jmpAddr = (void*)((char*)origLdrLoadDll + 0x5);
	*(void**)(jumpAddress) = jmpAddr;
	
	//Allocating the memory for the strcture and its instructions
	LPVOID trampoline = VirtualAlloc(NULL,19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	printf("Address of trampoline at 0x%p\n", trampoline);
	printf("Original LdrLoadDll at 0x%p\n",origLdrLoadDll);
	printf("Original jmp Address at 0x%p\n", jmpAddr);
	
	//Copying the original instruction mov qword ptr [rsp+10h],rbx in the trampoline and jumping back to the rest of the execution for LdrLoadDll
	CCopyMemory(trampoline,(PVOID)"\x48\x89\x5c\x24\x10", 5);
	//Setting up the JMP address in the original LdrLoadDll
	CCopyMemory((PBYTE)trampoline+5, jumpPrelude, 2);
	CCopyMemory((PBYTE)trampoline + 5 + 2, jumpAddress, sizeof(jumpAddress));
	CCopyMemory((PBYTE)trampoline + 5 + 2 + 8, jumpEpilogue, 4);
	
	//Making the Allocated memory executable RX
	DWORD oldProtect = 0;
	VirtualProtect(trampoline,30,PAGE_EXECUTE_READ,&oldProtect);
	LdrLoadrDll = (pNewLdrLoadDll)trampoline;
	
	//Loading Wininet.dll
	HANDLE wininetmodule = NULL;
	LdrLoadrDll(NULL, 0 , &ldrldll, &wininetmodule);
}
