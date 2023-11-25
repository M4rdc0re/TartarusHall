#pragma once
#include <Windows.h>
#include "Structs.h"
#include "typedefs.h"

#define DEREF( name )		*(	UINT_PTR	*)	(name)
#define DEREF_64( name )	*(	DWORD64		*)	(name)
#define DEREF_32( name )	*(	DWORD		*)	(name)
#define DEREF_16( name )	*(	WORD		*)	(name)
#define DEREF_8( name )		*(	BYTE		*)	(name)

#define SEED        0xEDB88320
#define RANGE       255
#define UP			32
#define DOWN		-32

#define NtAllocateVirtualMemory_CRC32	0xE0762FEB
#define NtProtectVirtualMemory_CRC32	0x5C2D1A97
#define NtCreateThreadEx_CRC32			0x2073465A
#define NtWaitForSingleObject_CRC32		0xDD554681

#define KERNEL32DLL_CRC32        0x998B531E
#define CreateToolhelp32Snapshot_CRC32   0xC1F3B876
#define Thread32First_CRC32      0x238B3114
#define Thread32Next_CRC32       0xF5197707
#define CloseHandle_CRC32        0xB09315F4
#define NtOpenSection_CRC32      0x709DE3CC
#define NtCreateSection_CRC32    0x9EEE4B80
#define NtMapViewOfSection_CRC32         0xA4163EBC
#define NtUnmapViewOfSection_CRC32       0x90483FF6
#define NtOpenThread_CRC32       0xB7A26D79
#define NtSuspendThread_CRC32    0xB19AB602
#define NtResumeThread_CRC32     0x6273B572
#define NtClose_CRC32    0x0D09C750

#define win32udll_CRC32          0x1C630B12
#define WIN32UDLL_CRC32          0x270D2BDA

unsigned int crc32h(char* message);
VOID	 _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);
PVOID	 _memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length);
wchar_t* _strcpy(wchar_t* dest, const wchar_t* src);
wchar_t* _strcat(wchar_t* dest, const wchar_t* src);

#define HASH(API) crc32h((char*)API)
#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))

PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);

HMODULE GetModuleHandleH(DWORD dwModuleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiHash);

BOOL IniUnhookDirectCalls();
BOOL IniUnhookIndirectSyscalls();
BOOL RefreshAllDlls();