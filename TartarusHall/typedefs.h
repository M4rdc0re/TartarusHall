#pragma once
#include <tlhelp32.h>

typedef struct _NT_SYSCALL
{
	DWORD dwSSn;                    // syscall number
	DWORD dwSyscallHash;            // syscall hash value
	PVOID pSyscallAddress;          // syscall address
	PVOID pSyscallInstAddress;      // address of a random 'syscall' instruction in ntdll

}NT_SYSCALL, * PNT_SYSCALL;

typedef struct _NTDLL_CONFIG
{
	PDWORD      pdwArrayOfAddresses; // The VA of the array of addresses of ntdll's exported functions
	PDWORD      pdwArrayOfNames;     // The VA of the array of names of ntdll's exported functions
	PWORD       pwArrayOfOrdinals;   // The VA of the array of ordinals of ntdll's exported functions
	DWORD       dwNumberOfNames;     // The number of exported functions from ntdll.dll
	ULONG_PTR   uModule;             // The base address of ntdll - requred to calculated future RVAs

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

typedef HANDLE(WINAPI* fnCreateToolhelp32Snapshot)(
	IN DWORD				dwFlags,
	IN DWORD				th32ProcessID
);

typedef BOOL(WINAPI* fnThread32First)(
	IN		HANDLE          hSnapshot,
	IN OUT	LPTHREADENTRY32 lpte
);

typedef BOOL(WINAPI* fnThread32Next)(
	IN  HANDLE				hSnapshot,
	OUT LPTHREADENTRY32		lpte
);

typedef BOOL(WINAPI* fnCloseHandle)(
	IN HANDLE				hObject
);

typedef struct _DIRECT_CALLS {

	fnCreateToolhelp32Snapshot	pCreateToolhelp32Snapshot;
	fnThread32First				pThread32First;
	fnThread32Next				pThread32Next;
	fnCloseHandle				pCloseHandle;

}WINAPI_FUNC, * PWINAPI_FUNC;

typedef enum THREADS {
	SUSPEND_THREADS,
	RESUME_THREADS
};
